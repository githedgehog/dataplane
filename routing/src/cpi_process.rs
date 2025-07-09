// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Main processing functions of the CPI

use crate::rib::Vrf;
use crate::rib::VrfTable;
use crate::routingdb::RoutingDb;
use crate::rpc_adapt::is_evpn_route;
use crate::{evpn::RmacEntry, fib::fibobjects::FibGroup};
use crate::{evpn::RmacStore, prefix::Prefix};

use bytes::Bytes;
use dplane_rpc::msg::*;
use dplane_rpc::socks::RpcCachedSock;
use dplane_rpc::wire::*;
use std::os::unix::net::SocketAddr;

use std::path::Path;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

/* convenience trait */
trait RpcOperation {
    type ObjectStore;
    fn connect(&self) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::InvalidRequest
    }
    fn add(&self, _db: &mut Self::ObjectStore) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::InvalidRequest
    }
    fn del(&self, _db: &mut Self::ObjectStore) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::InvalidRequest
    }
}

impl RpcOperation for ConnectInfo {
    type ObjectStore = ();
    fn connect(&self) -> RpcResultCode {
        if self.verinfo == VerInfo::default() {
            RpcResultCode::Ok
        } else {
            error!("Got connection request with mismatch RPC version!!");
            error!("Supported version is v{VER_DP_MAJOR}{VER_DP_MINOR}{VER_DP_PATCH}");
            RpcResultCode::Failure
        }
    }
}

fn nonlocal_nhop(iproute: &IpRoute) -> bool {
    let vrfid = iproute.vrfid;
    for nhop in &iproute.nhops {
        // NB: for simplicity we assume all nhops for a route belong to same vrf
        if nhop.vrfid != vrfid {
            return true;
        }
    }
    false
}

// Fixme(fredi): remove this
fn update_vrf(vrf: &mut Vrf, rmac_store: &RmacStore) {
    let updates = vrf.refresh_fib_updates(rmac_store, vrf);
    if let Some(fibw) = &mut vrf.fibw {
        updates.into_iter().for_each(|(prefix, fibgroup)| {
            fibw.add_fibgroup(prefix, fibgroup, false);
        });
        fibw.publish();
    }
}

// Fixme(fredi): remove this
fn update_vrfs(vrftable: &mut VrfTable, rmac_store: &RmacStore) {
    let vrf0 = vrftable.get_default_vrf_mut();
    update_vrf(vrf0, rmac_store);
    let vrf0 = vrftable.get_default_vrf();

    let updates: Vec<(u32, Vec<(Prefix, FibGroup)>)> = vrftable
        .values()
        .filter(|vrf| vrf.vrfid != 0)
        .map(|vrf| (vrf.vrfid, vrf.refresh_fib_updates(rmac_store, vrf0)))
        .collect();

    for (vrfid, updates) in &updates {
        if let Ok(vrf) = vrftable.get_vrf_mut(*vrfid) {
            if let Some(fibw) = &mut vrf.fibw {
                updates.into_iter().for_each(|(prefix, fibgroup)| {
                    fibw.add_fibgroup(*prefix, fibgroup.clone(), false); // avoid this clone
                });
                fibw.publish();
            }
        }
    }
}

impl RpcOperation for IpRoute {
    type ObjectStore = RoutingDb;
    #[allow(unused_mut)]
    fn add(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let rmac_store = &db.rmac_store;
        let vrftable = &mut db.vrftable;
        let iftabler = &db.iftw.as_iftable_reader();

        if self.vrfid != 0 && (is_evpn_route(self) || nonlocal_nhop(self)) {
            let Ok((vrf, vrf0)) = vrftable.get_with_default_mut(self.vrfid) else {
                error!("Unable to get vrf with id {}", self.vrfid);
                return RpcResultCode::Failure;
            };
            vrf.add_route_rpc(self, Some(vrf0), rmac_store, iftabler);
        } else {
            let Ok(vrf0) = vrftable.get_vrf_mut(self.vrfid) else {
                error!("Unable to find VRF with id {}", self.vrfid);
                return RpcResultCode::Failure;
            };
            vrf0.add_route_rpc(self, None, rmac_store, iftabler);
        }
        RpcResultCode::Ok
    }
    fn del(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let vrftable = &mut db.vrftable;
        if let Ok(vrf) = vrftable.get_vrf_mut(self.vrfid) {
            vrf.del_route_rpc(self);
            if vrf.can_be_deleted() {
                if let Err(e) = vrftable.remove_vrf(self.vrfid, &mut db.iftw) {
                    warn!("Failed to delete vrf {}: {e}", self.vrfid);
                }
            }
            RpcResultCode::Ok
        } else {
            error!("Unable to find VRF with id {}", self.vrfid);
            // if we did not find vrf, we don't have the route
            // tell frr all is good
            if !db.have_config() {
                RpcResultCode::Ok
            } else {
                RpcResultCode::Failure
            }
        }
    }
}
impl RpcOperation for Rmac {
    type ObjectStore = RoutingDb;
    fn add(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let rmac_store = &mut db.rmac_store;
        let Ok(rmac) = RmacEntry::try_from(self) else {
            error!("Failed to store rmac entry {self}");
            return RpcResultCode::Failure;
        };
        rmac_store.add_rmac_entry(rmac);
        RpcResultCode::Ok
    }
    fn del(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let rmac_store = &mut db.rmac_store;
        let Ok(rmac) = RmacEntry::try_from(self) else {
            return RpcResultCode::Failure;
        };
        rmac_store.del_rmac_entry(&rmac);
        RpcResultCode::Ok
    }
}

impl RpcOperation for IfAddress {
    type ObjectStore = RoutingDb;
    fn add(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        db.iftw
            .add_ip_address(self.ifindex, (self.address, self.mask_len));
        RpcResultCode::Ok
    }
    fn del(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        db.iftw
            .del_ip_address(self.ifindex, (self.address, self.mask_len));
        RpcResultCode::Ok
    }
}

/* message builders */
fn build_response_msg(
    req: &RpcRequest,
    rescode: RpcResultCode,
    _objects: Option<Vec<&RpcObject>>,
) -> RpcMsg {
    let op = req.get_op();
    let seqn = req.get_seqn();
    let response = RpcResponse {
        op,
        seqn,
        rescode,
        objs: vec![],
    };
    response.wrap_in_msg()
}
fn build_notification_msg() -> RpcMsg {
    let notif = RpcNotification {};
    notif.wrap_in_msg()
}

/* message handlers */
fn handle_request(
    csock: &mut RpcCachedSock,
    peer: &SocketAddr,
    req: &RpcRequest,
    db: &mut RoutingDb,
) {
    let op = req.get_op();
    let object = req.get_object();
    debug!("Handling {}", req);

    // ignore additions if have no config. Connects are allowed, so are deletions to wipe out old state
    if !db.have_config() && op == RpcOp::Add {
        debug!("Ignoring message: no config is available");
        let resp_msg = build_response_msg(req, RpcResultCode::Ok, None);
        csock.send_msg(resp_msg, peer);
        return;
    }

    let res_code = match object {
        None => {
            error!("Received {:?} request without object!", op);
            RpcResultCode::InvalidRequest
        }
        Some(RpcObject::IfAddress(ifaddr)) => match op {
            RpcOp::Add => ifaddr.add(db),
            RpcOp::Del => ifaddr.del(db),
            _ => RpcResultCode::InvalidRequest,
        },
        Some(RpcObject::Rmac(rmac)) => match op {
            RpcOp::Add => rmac.add(db),
            RpcOp::Del => rmac.del(db),
            _ => RpcResultCode::InvalidRequest,
        },
        Some(RpcObject::IpRoute(route)) => {
            let res = match op {
                RpcOp::Add | RpcOp::Update => route.add(db),
                RpcOp::Del => route.del(db),
                _ => RpcResultCode::InvalidRequest,
            };
            if route.vrfid == 0 {
                update_vrfs(&mut db.vrftable, &db.rmac_store);
            }
            res
        }
        Some(RpcObject::ConnectInfo(conninfo)) => match op {
            RpcOp::Connect => conninfo.connect(),
            _ => RpcResultCode::InvalidRequest,
        },
    };
    let resp_msg = build_response_msg(req, res_code, None);
    csock.send_msg(resp_msg, peer);
}
fn handle_response(_csock: &RpcCachedSock, _peer: &SocketAddr, _res: &RpcResponse) {}
fn handle_notification(_csock: &RpcCachedSock, peer: &SocketAddr, _notif: &RpcNotification) {
    warn!("Received a notification message from {:?}", peer);
}
fn handle_control(_csock: &RpcCachedSock, _peer: &SocketAddr, _ctl: &RpcControl) {}
fn handle_rpc_msg(csock: &mut RpcCachedSock, peer: &SocketAddr, msg: &RpcMsg, db: &mut RoutingDb) {
    match msg {
        RpcMsg::Control(ctl) => handle_control(csock, peer, ctl),
        RpcMsg::Request(req) => handle_request(csock, peer, req, db),
        RpcMsg::Response(resp) => handle_response(csock, peer, resp),
        RpcMsg::Notification(notif) => handle_notification(csock, peer, notif),
    }
}

/* process rx data from UX sock */
pub fn process_rx_data(
    csock: &mut RpcCachedSock,
    peer: &SocketAddr,
    data: &[u8],
    db: &mut RoutingDb,
) {
    let peer_addr = peer.as_pathname().unwrap_or_else(|| Path::new("unnamed"));
    trace!("CPI: recvd {} bytes from {:?}...", data.len(), peer_addr);
    let mut buf_rx = Bytes::copy_from_slice(data); // TODO: avoid this copy
    match RpcMsg::decode(&mut buf_rx) {
        Ok(msg) => handle_rpc_msg(csock, peer, &msg, db),
        Err(e) => {
            error!("Failure decoding msg rx from {:?}: {:?}", peer, e);
            let notif = build_notification_msg();
            csock.send_msg(notif, peer);
        }
    }
}
