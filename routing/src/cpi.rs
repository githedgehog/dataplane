// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Main processing functions of the Control-plane interface (CPI)

use crate::evpn::{RmacEntry, RmacStore};
use crate::fib::fibobjects::FibGroup;
use crate::rib::{Vrf, VrfTable};
use crate::rio::CpiStats;
use crate::routingdb::RoutingDb;
use crate::rpc_adapt::is_evpn_route;

use bytes::Bytes;
use chrono::Local;
use dplane_rpc::socks::RpcCachedSock;
use dplane_rpc::wire::*;
use dplane_rpc::{msg::*, socks::Pretty};
use lpm::prefix::Prefix;
use std::os::unix::net::SocketAddr;

use std::path::Path;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

/* convenience trait */
trait RpcOperation {
    type ObjectStore;
    fn connect(&self, _stats: &mut Self::ObjectStore) -> RpcResultCode
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
    type ObjectStore = CpiStats;
    fn connect(&self, stats: &mut Self::ObjectStore) -> RpcResultCode {
        info!("Got connect request from {}, pid {}", self.name, self.pid);
        if let Some(pid) = stats.last_pid {
            warn!("CP had already been connected with pid {}..", pid);
            if pid != self.pid {
                warn!("Frr reports a new pid of {}", self.pid);
            }
        }
        if self.verinfo == VerInfo::default() {
            stats.last_pid = Some(self.pid);
            stats.connect_time = Some(Local::now());
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
fn build_control_msg() -> RpcMsg {
    let control = RpcControl {};
    control.wrap_in_msg()
}

/* message handlers */
fn update_stats(
    stats: &mut CpiStats,
    op: RpcOp,
    object: Option<&RpcObject>,
    res_code: RpcResultCode,
) {
    let index = res_code.as_usize();
    match object {
        None => {}
        Some(RpcObject::IfAddress(_)) => match op {
            RpcOp::Add => stats.add_ifaddr.incr_by(index, 1),
            RpcOp::Del => stats.del_ifaddr.incr_by(index, 1),
            _ => unreachable!(),
        },
        Some(RpcObject::Rmac(_)) => match op {
            RpcOp::Add => stats.add_rmac.incr_by(index, 1),
            RpcOp::Del => stats.del_rmac.incr_by(index, 1),
            _ => unreachable!(),
        },
        Some(RpcObject::IpRoute(_)) => match op {
            RpcOp::Add => stats.add_route.incr_by(index, 1),
            RpcOp::Update => stats.update_route.incr_by(index, 1),
            RpcOp::Del => stats.del_route.incr_by(index, 1),
            _ => unreachable!(),
        },
        Some(RpcObject::ConnectInfo(_)) => stats.connect.incr_by(index, 1),
    }
}
fn rpc_reply(
    csock: &mut RpcCachedSock,
    peer: &SocketAddr,
    req: &RpcRequest,
    rescode: RpcResultCode,
    stats: &mut CpiStats,
) {
    let op = req.get_op();
    let object = req.get_object();
    let resp_msg = build_response_msg(req, rescode, None);
    csock.send_msg(resp_msg, peer);
    update_stats(stats, op, object, rescode);
}

fn handle_request(
    csock: &mut RpcCachedSock,
    peer: &SocketAddr,
    req: &RpcRequest,
    db: &mut RoutingDb,
    stats: &mut CpiStats,
) {
    let op = req.get_op();
    let object = req.get_object();
    debug!("Handling {}", req);

    // We should not see requests before a connect, because the plugin always sends a connect as the very
    // first message when it first connects. If dataplane restarts, plugin will get xmit failures, cache
    // messages and attempt to reconnect. On success, it will send cached messages again. So, if we get
    // messages without having seen a connect, that means we restarted. We will ignore those messages
    // since we need the plugin to push the whole state again anyway and, to be able to process it,
    // we need to have a configuration.
    if op != RpcOp::Connect && stats.last_pid.is_none() {
        warn!("Ignoring request: no prior connect received. Did we restart?");
        rpc_reply(csock, peer, req, RpcResultCode::Ignored, stats);
        return;
    }

    // ignore additions if have no config. Connects are allowed, so are deletions to wipe out old state
    if !db.have_config() && op == RpcOp::Add {
        debug!("Ignoring request: no config is available");
        rpc_reply(csock, peer, req, RpcResultCode::Ignored, stats);
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
            RpcOp::Connect => conninfo.connect(stats),
            _ => RpcResultCode::InvalidRequest,
        },
    };
    rpc_reply(csock, peer, req, res_code, stats);
}
fn handle_response(_csock: &RpcCachedSock, _peer: &SocketAddr, _res: &RpcResponse) {}
fn handle_notification(_csock: &RpcCachedSock, peer: &SocketAddr, _notif: &RpcNotification) {
    warn!("Received a notification message from {:?}", peer);
}
fn handle_control(
    csock: &mut RpcCachedSock,
    peer: &SocketAddr,
    _ctl: &RpcControl,
    stats: &mut CpiStats,
) {
    let control = build_control_msg();
    stats.control_rx += 1;
    csock.send_msg(control, peer);
}
fn handle_rpc_msg(
    csock: &mut RpcCachedSock,
    peer: &SocketAddr,
    msg: &RpcMsg,
    db: &mut RoutingDb,
    stats: &mut CpiStats,
) {
    match msg {
        RpcMsg::Control(ctl) => handle_control(csock, peer, ctl, stats),
        RpcMsg::Request(req) => handle_request(csock, peer, req, db, stats),
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
    stats: &mut CpiStats,
) {
    let peer_addr = peer.as_pathname().unwrap_or_else(|| Path::new("unnamed"));
    trace!("CPI: recvd {} bytes from {:?}...", data.len(), peer_addr);
    let mut buf_rx = Bytes::copy_from_slice(data); // TODO: avoid this copy
    stats.last_msg_rx = Some(Local::now());
    match RpcMsg::decode(&mut buf_rx) {
        Ok(msg) => handle_rpc_msg(csock, peer, &msg, db, stats),
        Err(e) => {
            stats.decode_failures += 1;
            error!("Failure decoding msg rx from {}: {:?}", peer.pretty(), e);
            let notif = build_notification_msg();
            csock.send_msg(notif, peer);
        }
    }
}
