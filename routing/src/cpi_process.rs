// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Main processing functions of the CPI

//use crate::interface::IfTable;
#[cfg(feature = "auto-learn")]
use crate::interface::Interface;

#[cfg(feature = "auto-learn")]
use net::vxlan::Vni;

use crate::rmac::RmacEntry;
use crate::routingdb::{RoutingDb, VrfTable};
use crate::rpc_adapt::is_evpn_route;
use crate::vrf::Vrf;
use bytes::Bytes;
use dplane_rpc::msg::*;
use dplane_rpc::socks::RpcCachedSock;
use dplane_rpc::wire::*;
use std::any::Any;
use std::os::unix::net::SocketAddr;

use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, trace, warn};

/* convenience trait */
#[allow(unused)]
trait RpcOperation {
    type ObjectStore;
    fn connect(&self) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::InvalidRequest
    }
    fn add(&self, db: &Self::ObjectStore) -> RpcResultCode
    where
        Self: Sized,
    {
        RpcResultCode::InvalidRequest
    }
    fn del(&self, db: &Self::ObjectStore) -> RpcResultCode
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

trait TypeName: Any {
    fn type_name(&self) -> &'static str;
}
impl<T: Any> TypeName for T {
    fn type_name(&self) -> &'static str {
        std::any::type_name::<T>()
    }
}

fn poison_warn<T: 'static>(object: &RwLock<T>) -> RpcResultCode {
    error!("Poisoned lock on {} !!", object.type_name());
    object.clear_poison();
    RpcResultCode::Failure
}

#[cfg(feature = "auto-learn")]
fn auto_learn_vrf(route: &IpRoute, db: &mut VrfTable) {
    if let Ok(vrf) = db.get_vrf(route.vrfid) {
        let mut vni = None;
        if let Ok(vrf) = vrf.read() {
            if vrf.vni.is_none() {
                for nh in route.nhops.iter() {
                    if let Some(NextHopEncap::VXLAN(vxlan)) = &nh.encap {
                        if nh.vrfid == route.vrfid {
                            vni = Some(vxlan.vni);
                            break;
                        }
                    }
                }
            }
        }
        if let Some(vni) = vni {
            let _ = db.set_vni(route.vrfid, Vni::new_checked(vni).unwrap());
        }
    } else {
        let mut vni = None;
        for nh in route.nhops.iter() {
            if let Some(NextHopEncap::VXLAN(vxlan)) = &nh.encap {
                if nh.vrfid == route.vrfid {
                    vni = Some(vxlan.vni);
                    break;
                }
            }
        }
        let name = if route.vrfid == 0 {
            "default"
        } else {
            "unknown"
        };
        let _ = db.add_vrf(name, route.vrfid, vni);
    }
}

fn get_vrf0<'a>(iproute: &IpRoute, vrftable: &'a VrfTable) -> Option<&'a Arc<RwLock<Vrf>>> {
    if is_evpn_route(iproute) && iproute.vrfid != 0 {
        match vrftable.get_vrf(0) {
            Ok(vrfg) => Some(vrfg),
            Err(e) => {
                error!("Unable to access default vrf!: {e}");
                None
            }
        }
    } else {
        None
    }
}

impl RpcOperation for IpRoute {
    type ObjectStore = RoutingDb;
    #[allow(unused_mut)]
    fn add(&self, db: &Self::ObjectStore) -> RpcResultCode {
        let _iftable_g = db.iftable.read().unwrap();
        let rmac_store_g = db.rmac_store.read().unwrap();
        let vtep_g = db.vtep.read().unwrap();

        /*
                let process_route = |vrftable: &mut VrfTable| -> RpcResultCode {
                    #[cfg(feature = "auto-learn")]
                    auto_learn_vrf(&self, vrftable);

                    let vrfg = get_vrf0(self, vrftable);

                    if let Ok(vrf) = vrftable.get_vrf(self.vrfid) {
                        if let Ok(mut vrf) = vrf.write() {
                            if let Some(vrf0) = vrfg {
                                vrf.add_route_rpc(self, vrf0.read().ok().as_deref());
                            } else {
                                vrf.add_route_rpc(self, None);
                            }
                            RpcResultCode::Ok
                        } else {
                            vrf.clear_poison();
                            RpcResultCode::Failure
                        }
                    } else {
                        RpcResultCode::Failure
                    }
                };

                if let Ok(mut vrftable) = db.vrftable.write() {
                    process_route(&mut vrftable)
                } else {
                    db.vrftable.clear_poison();
                    RpcResultCode::Failure
                }
        */

        if let Ok(mut vrftable) = db.vrftable.write() {
            #[cfg(feature = "auto-learn")]
            auto_learn_vrf(self, &mut vrftable);

            let vrfg = get_vrf0(self, &vrftable);

            if let Ok(vrf) = vrftable.get_vrf(self.vrfid) {
                if let Ok(mut vrf) = vrf.write() {
                    if let Some(vrf0) = vrfg {
                        vrf.add_route_rpc(
                            self,
                            vrf0.read().ok().as_deref(),
                            &rmac_store_g,
                            &vtep_g,
                        );
                    } else {
                        vrf.add_route_rpc(self, None, &rmac_store_g, &vtep_g);
                    }
                    RpcResultCode::Ok
                } else {
                    poison_warn(vrf)
                }
            } else {
                error!("Unable to find VRF with id {}", self.vrfid);
                RpcResultCode::Failure
            }
        } else {
            poison_warn(&db.vrftable)
        }
    }
    fn del(&self, db: &Self::ObjectStore) -> RpcResultCode {
        if let Ok(vrftable) = db.vrftable.write() {
            if let Ok(vrf) = vrftable.get_vrf(self.vrfid) {
                if let Ok(mut vrf) = vrf.write() {
                    vrf.del_route_rpc(self);
                    RpcResultCode::Ok
                } else {
                    poison_warn(vrf)
                }
            } else {
                error!("Unable to find VRF with id {}", self.vrfid);
                RpcResultCode::Failure
            }
        } else {
            poison_warn(&db.vrftable)
        }
    }
}
impl RpcOperation for Rmac {
    type ObjectStore = RoutingDb;
    fn add(&self, db: &Self::ObjectStore) -> RpcResultCode {
        if let Ok(mut rmac_store) = db.rmac_store.write() {
            let rmac = RmacEntry::from(self);
            rmac_store.add_rmac_entry(rmac);
            RpcResultCode::Ok
        } else {
            RpcResultCode::Failure
        }
    }
    fn del(&self, db: &Self::ObjectStore) -> RpcResultCode {
        if let Ok(mut rmac_store) = db.rmac_store.write() {
            let rmac = RmacEntry::from(self);
            rmac_store.del_rmac_entry(rmac);
            RpcResultCode::Ok
        } else {
            poison_warn(&db.rmac_store)
        }
    }
}
impl RpcOperation for IfAddress {
    type ObjectStore = RoutingDb;
    fn add(&self, db: &Self::ObjectStore) -> RpcResultCode {
        if let Ok(mut iftable) = db.iftable.write() {
            #[cfg(feature = "auto-learn")]
            if iftable.get_interface(self.ifindex).is_none() {
                iftable.add_interface(Interface::new(self.ifname.as_str(), self.ifindex));
            }
            if let Err(e) = iftable.add_ifaddr(self.ifindex, &(self.address, self.mask_len)) {
                error!("Failed to add address to interface {}:{e}", self.ifname);
                RpcResultCode::Failure
            } else {
                RpcResultCode::Ok
            }
        } else {
            poison_warn(&db.iftable)
        }
    }
    fn del(&self, db: &Self::ObjectStore) -> RpcResultCode {
        if let Ok(mut iftable) = db.iftable.write() {
            iftable.del_ifaddr(self.ifindex, &(self.address, self.mask_len));
            RpcResultCode::Ok
        } else {
            poison_warn(&db.iftable)
        }
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
fn collect_objects(_ovec: &mut [&RpcObject], filter: Option<&GetFilter>) -> RpcResultCode {
    if let Some(_filter) = filter {
        // get the objects considering the filter and place refs in ovec
    } else {
        // get all objects and place refs in ovec
    }
    RpcResultCode::Ok
}
fn handle_get_request(csock: &mut RpcCachedSock, peer: &SocketAddr, req: &RpcRequest) {
    let mut objects: Vec<&RpcObject> = vec![];
    let x = req.get_object();
    let res_code = match x {
        None => collect_objects(&mut objects, None),
        Some(RpcObject::GetFilter(filter)) => collect_objects(&mut objects, Some(filter)),
        _ => {
            error!("Received Get request with invalid object");
            RpcResultCode::InvalidRequest
        }
    };

    let resp_msg = build_response_msg(req, res_code, Some(objects));
    csock.send_msg(resp_msg, peer);
}
fn handle_request(csock: &mut RpcCachedSock, peer: &SocketAddr, req: &RpcRequest, db: &RoutingDb) {
    let op = req.get_op();
    let object = req.get_object();
    debug!("Handling {}", req);

    if op == RpcOp::Get {
        return handle_get_request(csock, peer, req);
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
        Some(RpcObject::IpRoute(route)) => match op {
            RpcOp::Add | RpcOp::Update => route.add(db),
            RpcOp::Del => route.del(db),
            _ => RpcResultCode::InvalidRequest,
        },
        Some(RpcObject::ConnectInfo(conninfo)) => match op {
            RpcOp::Connect => conninfo.connect(),
            _ => RpcResultCode::InvalidRequest,
        },
        _ => RpcResultCode::InvalidRequest,
    };
    let resp_msg = build_response_msg(req, res_code, None);
    csock.send_msg(resp_msg, peer);
}
fn handle_response(_csock: &RpcCachedSock, _peer: &SocketAddr, _res: &RpcResponse) {}
fn handle_notification(_csock: &RpcCachedSock, peer: &SocketAddr, _notif: &RpcNotification) {
    warn!("Received a notification message from {:?}", peer);
}
fn handle_control(_csock: &RpcCachedSock, _peer: &SocketAddr, _ctl: &RpcControl) {}
fn handle_rpc_msg(csock: &mut RpcCachedSock, peer: &SocketAddr, msg: &RpcMsg, db: &RoutingDb) {
    match msg {
        RpcMsg::Control(ctl) => handle_control(csock, peer, ctl),
        RpcMsg::Request(req) => handle_request(csock, peer, req, db),
        RpcMsg::Response(resp) => handle_response(csock, peer, resp),
        RpcMsg::Notification(notif) => handle_notification(csock, peer, notif),
    }
}

/* process rx data from UX sock */
#[allow(unused)]
pub fn process_rx_data(csock: &mut RpcCachedSock, peer: &SocketAddr, data: &[u8], db: &RoutingDb) {
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
