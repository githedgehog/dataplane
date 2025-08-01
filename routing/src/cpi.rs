// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Main processing functions of the Control-plane interface (CPI)

use crate::evpn::{RmacEntry, RmacStore};
use crate::fib::fibobjects::FibGroup;
use crate::revent::{ROUTER_EVENTS, RouterEvent, revent};
use crate::rib::{Vrf, VrfTable};
use crate::rio::Rio;
use crate::routingdb::RoutingDb;
use crate::rpc_adapt::is_evpn_route;

use bytes::Bytes;
use chrono::{DateTime, Local};
use dplane_rpc::socks::RpcCachedSock;
use dplane_rpc::wire::*;
use dplane_rpc::{msg::*, socks::Pretty};
use lpm::prefix::Prefix;
use std::os::unix::net::SocketAddr;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

pub(crate) const CPI_STATS_SIZE: usize = RpcResultCode::RpcResultCodeMax as usize;
#[derive(Default)]
pub(crate) struct StatsRow(pub(crate) [u64; CPI_STATS_SIZE]);
impl StatsRow {
    pub(crate) fn incr(&mut self, res_code: RpcResultCode) {
        let index = res_code.as_usize();
        self.0[index] += 1;
    }
    pub(crate) fn get(&self, res_code: RpcResultCode) -> u64 {
        let index = res_code.as_usize();
        self.0[index]
    }
}

#[derive(Default, Copy, Clone, PartialEq)]
pub(crate) enum CpiStatus {
    #[default]
    NotConnected, /* FRR has not connected -- or we're not attending it */
    Incompatible, /* FRR has attempted to connect but we use incompatible RPC versions */
    Connected,    /* FRR has connected normally */
    FrrRestarted, /* FRR has reconnected: it has restarted */
    NeedRefresh,  /* FRR has reconnected: we have restarted */
}
impl CpiStatus {
    pub(crate) fn change(&mut self, new: CpiStatus) {
        if *self != new {
            debug!("Transitioning to status {new}");
            *self = new;
            revent!(RouterEvent::CpiStatusChange(new));
        }
    }
}

#[derive(Default)]
pub(crate) struct CpiStats {
    pub(crate) status: CpiStatus,

    // sync token
    pub(crate) synt: u64,

    // last reported pid (or some id u32)
    pub(crate) last_pid: Option<u32>,

    // last connect time
    pub(crate) connect_time: Option<DateTime<Local>>,

    // last address
    pub(crate) peer: Option<SocketAddr>,

    // last time a message was received
    pub(crate) last_msg_rx: Option<DateTime<Local>>,

    // decoding failures
    pub(crate) decode_failures: u64,

    // stats per request / object
    pub(crate) connect: StatsRow,
    pub(crate) add_route: StatsRow,
    pub(crate) update_route: StatsRow,
    pub(crate) del_route: StatsRow,
    pub(crate) add_ifaddr: StatsRow,
    pub(crate) del_ifaddr: StatsRow,
    pub(crate) add_rmac: StatsRow,
    pub(crate) del_rmac: StatsRow,

    // control - keepalives
    pub(crate) control_rx: u64,
}
impl CpiStats {
    pub(crate) fn new() -> CpiStats {
        Self {
            synt: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time is wrong!")
                .as_secs(),
            ..Default::default()
        }
    }
}
fn build_connect_info(synt: u64) -> ConnectInfo {
    ConnectInfo {
        pid: process::id(),
        name: "GW-dataplane".to_string(),
        verinfo: VerInfo::default(),
        synt,
    }
}

/* convenience trait */
trait RpcOperation {
    type ObjectStore;
    fn connect(&self, _stats: &mut Self::ObjectStore, _: &SocketAddr) -> RpcResultCode
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
    fn connect(&self, stats: &mut Self::ObjectStore, peer: &SocketAddr) -> RpcResultCode {
        info!(
            "Got connect from {}; ver:{} pid:{} synt:{}",
            self.name, self.verinfo, self.pid, self.synt
        );
        if let Some(pid) = stats.last_pid {
            warn!("FRR had already been connected with pid: {}..", pid);
            if pid != self.pid {
                warn!("Frr reports a new pid of {}", self.pid);
            }
        }
        if self.verinfo == VerInfo::default() {
            stats.last_pid = Some(self.pid);
            stats.connect_time = Some(Local::now());
            stats.peer = Some(peer.clone());
            stats.status.change(CpiStatus::Connected);

            if stats.connect.get(RpcResultCode::Ok) > 0 && self.synt == 0 {
                stats.status.change(CpiStatus::FrrRestarted);
            }
            if stats.connect.get(RpcResultCode::Ok) == 0 && self.synt != 0 {
                stats.status.change(CpiStatus::NeedRefresh);
            }
            RpcResultCode::Ok
        } else {
            stats.status.change(CpiStatus::Incompatible);
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
    object: Option<RpcObject>,
) -> RpcMsg {
    let op = req.get_op();
    let seqn = req.get_seqn();
    let mut objs = Vec::new();
    if let Some(object) = object {
        objs.push(object);
    }
    let response = RpcResponse {
        op,
        seqn,
        rescode,
        objs,
    };
    response.wrap_in_msg()
}
fn build_notification_msg() -> RpcMsg {
    let notif = RpcNotification {};
    notif.wrap_in_msg()
}
fn build_control_msg(refresh: u8) -> RpcMsg {
    let control = RpcControl { refresh };
    control.wrap_in_msg()
}
/* message senders */
fn rpc_send_response(
    rio: &mut Rio,
    peer: &SocketAddr,
    req: &RpcRequest,
    rescode: RpcResultCode,
    resp_object: Option<RpcObject>,
) {
    let op = req.get_op();
    let object = req.get_object();
    let resp_msg = build_response_msg(req, rescode, resp_object);
    rio.cpi_sock.send_msg(resp_msg, peer);
    update_stats(&mut rio.cpistats, op, object, rescode);
}
pub(crate) fn rpc_send_control(csock: &mut RpcCachedSock, peer: &SocketAddr, refresh: bool) {
    let refresh: u8 = if refresh { 1 } else { 0 };
    let control = build_control_msg(refresh);
    csock.send_msg(control, peer);
}

/* message handlers */
fn update_stats(
    stats: &mut CpiStats,
    op: RpcOp,
    object: Option<&RpcObject>,
    res_code: RpcResultCode,
) {
    match object {
        None => {}
        Some(RpcObject::IfAddress(_)) => match op {
            RpcOp::Add => stats.add_ifaddr.incr(res_code),
            RpcOp::Del => stats.del_ifaddr.incr(res_code),
            _ => unreachable!(),
        },
        Some(RpcObject::Rmac(_)) => match op {
            RpcOp::Add => stats.add_rmac.incr(res_code),
            RpcOp::Del => stats.del_rmac.incr(res_code),
            _ => unreachable!(),
        },
        Some(RpcObject::IpRoute(_)) => match op {
            RpcOp::Add => stats.add_route.incr(res_code),
            RpcOp::Update => stats.update_route.incr(res_code),
            RpcOp::Del => stats.del_route.incr(res_code),
            _ => unreachable!(),
        },
        Some(RpcObject::ConnectInfo(_)) => stats.connect.incr(res_code),
    }
}

fn handle_request(rio: &mut Rio, peer: &SocketAddr, req: &RpcRequest, db: &mut RoutingDb) {
    let op = req.get_op();
    let object = req.get_object();
    debug!("Handling {}", req);

    // We should not see requests before a connect, because the plugin always sends a connect as the very
    // first message when it first connects. If dataplane restarts, plugin will get xmit failures, cache
    // messages and attempt to reconnect. On success, it will send cached messages again. So, if we get
    // messages without having seen a connect, that means we restarted. We will ignore those messages
    // since we need the plugin to push the whole state again anyway and, to be able to process it,
    // we need to have a configuration.
    if op != RpcOp::Connect && rio.cpistats.last_pid.is_none() {
        warn!("Ignoring request: no prior connect received. Did we restart?");
        rpc_send_response(rio, peer, req, RpcResultCode::Ignored, None);
        return;
    }

    // ignore additions if have no config. Connects are allowed, so are deletions to wipe out old state
    if !db.have_config() && op == RpcOp::Add {
        error!("Ignoring request: there's no config. This should not happen...");
        error!("..but may not cause malfunction.");
        rpc_send_response(rio, peer, req, RpcResultCode::Ignored, None);
        return;
    }

    let mut response_object: Option<RpcObject> = None;
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
            RpcOp::Connect => {
                let res = conninfo.connect(&mut rio.cpistats, peer);
                let synt = if res == RpcResultCode::Ok {
                    rio.cpistats.synt
                } else {
                    0
                };
                response_object = Some(RpcObject::ConnectInfo(build_connect_info(synt)));
                res
            }
            _ => RpcResultCode::InvalidRequest,
        },
    };
    rpc_send_response(rio, peer, req, res_code, response_object);
}
fn handle_response(_csock: &RpcCachedSock, _peer: &SocketAddr, _res: &RpcResponse) {}
fn handle_notification(_csock: &RpcCachedSock, peer: &SocketAddr, _notif: &RpcNotification) {
    warn!("Received a notification message from {:?}", peer);
}
fn handle_control(
    csock: &mut RpcCachedSock,
    peer: &SocketAddr,
    ctl: &RpcControl,
    stats: &mut CpiStats,
) {
    stats.control_rx += 1;
    if ctl.refresh != 0 {
        info!("CP acks reception of refresh request");
    }
    rpc_send_control(csock, peer, false);
}
fn handle_rpc_msg(rio: &mut Rio, peer: &SocketAddr, msg: &RpcMsg, db: &mut RoutingDb) {
    let csock = &mut rio.cpi_sock;
    match msg {
        RpcMsg::Control(ctl) => handle_control(csock, peer, ctl, &mut rio.cpistats),
        RpcMsg::Request(req) => handle_request(rio, peer, req, db),
        RpcMsg::Response(resp) => handle_response(csock, peer, resp),
        RpcMsg::Notification(notif) => handle_notification(csock, peer, notif),
    }
}

/* process rx data from UX sock */
pub fn process_rx_data(rio: &mut Rio, peer: &SocketAddr, data: &[u8], db: &mut RoutingDb) {
    trace!("CPI: recvd {} bytes from {}...", data.len(), peer.pretty());
    let mut buf_rx = Bytes::copy_from_slice(data); // TODO: avoid this copy
    rio.cpistats.last_msg_rx = Some(Local::now());
    match RpcMsg::decode(&mut buf_rx) {
        Ok(msg) => handle_rpc_msg(rio, peer, &msg, db),
        Err(e) => {
            rio.cpistats.decode_failures += 1;
            error!("Failure decoding msg rx from {}: {:?}", peer.pretty(), e);
            let notif = build_notification_msg();
            rio.cpi_sock.send_msg(notif, peer);
        }
    }
}
