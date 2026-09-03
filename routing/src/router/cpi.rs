// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Main processing functions of the Control-plane interface (CPI)

use crate::evpn::RmacEntry;
use crate::rib::Vrf;
use crate::routingdb::RoutingDb;

use crate::router::revent::{ROUTER_EVENTS, RouterEvent, revent};
use crate::router::rio::Rio;

use bytes::Bytes;
use chrono::{DateTime, Local};
use dplane_rpc::msg::{
    ConnectInfo, IfAddress, IpRoute, NextHopEncap, Rmac, RouteType, RpcControl, RpcMsg,
    RpcNotification, RpcObject, RpcOp, RpcRequest, RpcResponse, RpcResultCode, VER_DP_MAJOR,
    VER_DP_MINOR, VER_DP_PATCH, VerInfo, VrfId, WrapMsg,
};
use dplane_rpc::socks::Pretty;
use dplane_rpc::socks::RpcCachedSock;
use dplane_rpc::wire::Wire;

use net::interface::InterfaceIndex;
use net::interface::address::IfAddr;
use std::os::unix::net::SocketAddr;
use std::process;
use std::time::UNIX_EPOCH;

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

use tracectl::trace_target;
trace_target!("cpi", LevelFilter::DEBUG, &["routing-full"]);

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
            synt: clock::system_now()
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
    fn connect(&self, _stats: &mut Self::ObjectStore, _: &SocketAddr) -> RpcResultCode {
        RpcResultCode::InvalidRequest
    }
    fn add(&self, _db: &mut Self::ObjectStore) -> RpcResultCode {
        RpcResultCode::InvalidRequest
    }
    fn del(&self, _db: &mut Self::ObjectStore) -> RpcResultCode {
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

#[must_use]
#[allow(unused)]
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
fn on_vrf_lookup_fail(have_config: bool, vrfid: VrfId) -> RpcResultCode {
    error!("Unable to find VRF with id {vrfid}!!");
    if have_config {
        RpcResultCode::Failure
    } else {
        // On, deletions, if we don't find VRF, that means that we don't have
        // the route. So, treat this as a successful deletion to make frr happy.
        RpcResultCode::Ok
    }
}

/// Util to tell if a route is EVPN - heuristic
#[must_use]
#[allow(unused)]
fn is_evpn_route(iproute: &IpRoute) -> bool {
    if iproute.rtype != RouteType::Bgp || iproute.nhops.is_empty() {
        false
    } else {
        matches!(iproute.nhops[0].encap, Some(NextHopEncap::VXLAN(_)))
    }
}

impl RpcOperation for IpRoute {
    type ObjectStore = RoutingDb;
    fn add(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let rmac_store = &db.rmac_store;
        let vrftable = &mut db.vrftable;

        if self.vrfid == Vrf::DEFAULT_VRFID {
            let Ok(vrf0) = vrftable.get_vrf_mut(self.vrfid) else {
                error!("Unable to find default VRF!");
                return RpcResultCode::Failure;
            };
            vrf0.add_route_rpc(self, None, rmac_store);
            vrftable.refresh_non_default_fibs(rmac_store);
        } else {
            // this assumes that we always resolve non-default vrfs with the default vrf
            // FIXME: generalize this. This is fine atm because non-default vrfs are always
            // evpn-associated VRFs and we don't import routes from vrfs. However, that may
            // no longer be the case in the future. Fixing this in general, requires changing
            // get_with_default_mut() to return two non-default vrfs and the vrfs to use may
            // be determined with something like `nonlocal_nhop`
            let Ok((vrf, vrf0)) = vrftable.get_with_default_mut(self.vrfid) else {
                error!("Unable to get vrf with id {}", self.vrfid);
                return RpcResultCode::Failure;
            };
            vrf.add_route_rpc(self, Some(vrf0), rmac_store);
        }
        RpcResultCode::Ok
    }
    fn del(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let rmac_store = &db.rmac_store;
        let vrftable = &mut db.vrftable;

        if self.vrfid == Vrf::DEFAULT_VRFID {
            let Ok(vrf0) = vrftable.get_vrf_mut(self.vrfid) else {
                return on_vrf_lookup_fail(db.have_config(), self.vrfid);
            };
            vrf0.del_route_rpc(self, None, rmac_store);
            vrftable.refresh_non_default_fibs(rmac_store);
        } else {
            let Ok((vrf, vrf0)) = vrftable.get_with_default_mut(self.vrfid) else {
                return on_vrf_lookup_fail(db.have_config(), self.vrfid);
            };
            vrf.del_route_rpc(self, Some(vrf0), rmac_store);
            if vrf.can_be_deleted() {
                if let Err(e) = vrftable.remove_vrf(self.vrfid, &mut db.iftw) {
                    warn!("Failed to delete vrf {}: {e}", self.vrfid);
                }
            }
        }
        RpcResultCode::Ok
    }
}
impl RpcOperation for Rmac {
    type ObjectStore = RoutingDb;
    fn add(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let rmac_store = &mut db.rmac_store;
        let vrftable = &mut db.vrftable;
        let Ok(rmac) = RmacEntry::try_from(self) else {
            error!("Failed to parse rmac entry {self}");
            return RpcResultCode::Failure;
        };
        let vni = rmac.vni;
        if rmac_store.add_rmac_entry(rmac) {
            // refresh the vrf for that vni
            vrftable.refresh_fibs_by_vni(&[vni], &db.rmac_store);
        }
        RpcResultCode::Ok
    }
    fn del(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let rmac_store = &mut db.rmac_store;
        let Ok(rmac) = RmacEntry::try_from(self) else {
            return RpcResultCode::Failure;
        };
        rmac_store.invalidate_rmac_entry(&rmac);
        RpcResultCode::Ok
    }
}

impl RpcOperation for IfAddress {
    type ObjectStore = RoutingDb;
    fn add(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let Ok(ifaddr) = IfAddr::new(self.address, self.mask_len) else {
            error!("Invalid interface address: {self}");
            return RpcResultCode::InvalidRequest;
        };
        let ifindex = match InterfaceIndex::try_new(self.ifindex) {
            Ok(idx) => idx,
            Err(e) => {
                error!("unable to add interface address: {e}");
                return RpcResultCode::InvalidRequest;
            }
        };
        db.iftw.add_ip_address(ifindex, ifaddr);
        RpcResultCode::Ok
    }
    fn del(&self, db: &mut Self::ObjectStore) -> RpcResultCode {
        let Ok(ifaddr) = IfAddr::new(self.address, self.mask_len) else {
            error!("Invalid interface address: {self}");
            return RpcResultCode::InvalidRequest;
        };
        let ifindex = match InterfaceIndex::try_new(self.ifindex) {
            Ok(idx) => idx,
            Err(e) => {
                error!("unable to remove interface address: {e}");
                return RpcResultCode::InvalidRequest;
            }
        };
        db.iftw.del_ip_address(ifindex, ifaddr);
        RpcResultCode::Ok
    }
}

/* RPC message builders */
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

/* RPC message senders */
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
    let refresh: u8 = u8::from(refresh);
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
        Some(RpcObject::IpRoute(route)) => match op {
            RpcOp::Add | RpcOp::Update => route.add(db),
            RpcOp::Del => route.del(db),
            _ => RpcResultCode::InvalidRequest,
        },
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

/* process data from CPI */
pub fn process_cpi_data(rio: &mut Rio, peer: &SocketAddr, data: &mut Bytes, db: &mut RoutingDb) {
    trace!("CPI: recvd {} bytes from {}...", data.len(), peer.pretty());
    rio.cpistats.last_msg_rx = Some(Local::now());

    match RpcMsg::decode(data) {
        Ok(msg) => handle_rpc_msg(rio, peer, &msg, db),
        Err(e) => {
            rio.cpistats.decode_failures += 1;
            error!("Failure decoding msg rx from {}: {:?}", peer.pretty(), e);
            let notif = build_notification_msg();
            rio.cpi_sock.send_msg(notif, peer);
        }
    }
}

#[cfg(test)]
mod cpi_properties {
    use super::*;
    use crate::atable::atablerw::AtableWriter;
    use crate::config::RouterConfig;
    use crate::evpn::RmacStore;
    use crate::fib::fibobjects::{FibEntry, PktInstruction};
    use crate::fib::fibtable::FibTableWriter;
    use crate::interfaces::iftablerw::IfTableWriter;
    use crate::interfaces::tests::build_test_iftable;
    use crate::rib::encapsulation::Encapsulation;
    use crate::rib::vrf::tests::{build_test_nhop, build_test_route};
    use crate::rib::vrf::{RouteOrigin, RouterVrfConfig, VrfStatus};
    use bolero::{Driver, ValueGenerator};
    use dplane_rpc::msg::{ForwardAction, NextHop, VxlanEncap};
    use dplane_rpc::objects::MacAddress;
    use lpm::prefix::Prefix;
    use net::eth::mac::Mac;
    use net::vxlan::Vni;
    use std::net::IpAddr;
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const OVERLAY_VRF: VrfId = 7;
    const OVERLAY_VNI: u32 = 3000;
    const UNDERLAY_IFINDEX: u32 = 2;

    const NUM_VTEPS: u8 = 2;
    const NUM_MACS: u8 = 2;

    fn addr(a: &str) -> IpAddr {
        IpAddr::from_str(a).unwrap_or_else(|_| unreachable!())
    }

    fn vteps() -> Vec<IpAddr> {
        vec![addr("7.0.0.1"), addr("7.0.0.2")]
    }

    fn macs() -> Vec<[u8; 6]> {
        vec![
            [0x00, 0xaa, 0x00, 0x00, 0x00, 0x01],
            [0x00, 0xbb, 0x00, 0x00, 0x00, 0x02],
        ]
    }

    fn fabric() -> RoutingDb {
        let (fibtw, _fibtr) = FibTableWriter::new();
        let (iftw, _iftr) = IfTableWriter::new_with_data(build_test_iftable());
        let (_atw, atabler) = AtableWriter::new();
        let mut db = RoutingDb::new(fibtw, iftw, atabler);

        let vrf0 = db
            .vrftable
            .get_vrf_mut(Vrf::DEFAULT_VRFID)
            .unwrap_or_else(|e| unreachable!("{e}"));
        vrf0.add_route_complete(
            &Prefix::from_str("7.0.0.0/8").unwrap_or_else(|_| unreachable!()),
            build_test_route(RouteOrigin::Connected, 0, 0),
            &[build_test_nhop(None, Some(UNDERLAY_IFINDEX), 0, None)],
            None,
            &RmacStore::new(),
        );

        let vni = Vni::new_checked(OVERLAY_VNI).unwrap_or_else(|_| unreachable!());
        let config = RouterVrfConfig::new(OVERLAY_VRF, "overlay").set_vni(Some(vni));
        db.vrftable
            .add_vrf(&config)
            .unwrap_or_else(|e| unreachable!("{e}"));
        db
    }

    fn overlay_route(vrfid: VrfId, prefix: &str, vtep: IpAddr) -> IpRoute {
        let (address, len) = prefix.split_once('/').unwrap_or_else(|| unreachable!());
        IpRoute {
            prefix: addr(address),
            prefix_len: len.parse().unwrap_or_else(|_| unreachable!()),
            vrfid,
            tableid: 254,
            rtype: RouteType::Bgp,
            distance: 20,
            metric: 100,
            nhops: vec![NextHop {
                fwaction: ForwardAction::Forward,
                address: Some(vtep),
                ifindex: None,
                vrfid,
                encap: Some(NextHopEncap::VXLAN(VxlanEncap { vni: OVERLAY_VNI })),
            }],
        }
    }

    fn rmac_msg(vtep: IpAddr, mac: [u8; 6]) -> Rmac {
        Rmac {
            address: vtep,
            mac: MacAddress::new(mac),
            vni: OVERLAY_VNI,
        }
    }

    fn fib_entries(db: &RoutingDb, vrfid: VrfId, prefix: &str) -> Vec<FibEntry> {
        let prefix = Prefix::from_str(prefix).unwrap_or_else(|_| unreachable!());
        let Prefix::IPV4(wanted) = prefix else {
            unreachable!()
        };
        let vrf = db
            .vrftable
            .get_vrf(vrfid)
            .unwrap_or_else(|e| unreachable!("{e}"));
        let fibw = vrf.fibw.as_ref().unwrap_or_else(|| unreachable!());
        let fib = fibw.enter().unwrap_or_else(|| unreachable!());
        fib.iter_v4()
            .find(|(p, _)| *p == wanted)
            .map(|(_, route)| {
                route
                    .iter()
                    .flat_map(|group| group.entries().iter().cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn entries_are_well_formed(entries: &[FibEntry], at: &str) {
        for entry in entries {
            assert!(entry.is_valid(), "unusable {entry:?} {at}");
            let drop_at = entry
                .iter()
                .position(|inst| matches!(inst, PktInstruction::Drop));
            if let Some(index) = drop_at {
                assert_eq!(index, 0, "a drop is not first in {entry:?} {at}");
            }
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct Fabrics;

    impl ValueGenerator for Fabrics {
        type Output = (usize, usize);

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<(usize, usize)> {
            let vtep = driver.gen_u8(Included(&0), Included(&(NUM_VTEPS - 1)))?;
            let mac = driver.gen_u8(Included(&0), Included(&(NUM_MACS - 1)))?;
            Some((usize::from(vtep), usize::from(mac)))
        }
    }

    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(vteps().len(), usize::from(NUM_VTEPS));
        assert_eq!(macs().len(), usize::from(NUM_MACS));
        let underlay = Prefix::from_str("7.0.0.0/8").unwrap_or_else(|_| unreachable!());
        for vtep in vteps() {
            assert!(underlay.covers_addr(&vtep), "{vtep} is not in the underlay");
        }
    }

    #[test]
    fn an_overlay_route_drops_until_its_router_mac_arrives() {
        bolero::check!().with_generator(Fabrics).cloned().for_each(
            |(vtep, mac): (usize, usize)| {
                let mut db = fabric();
                let vtep = vteps()[vtep];
                let prefix = "10.0.0.0/24";

                assert_eq!(
                    overlay_route(OVERLAY_VRF, prefix, vtep).add(&mut db),
                    RpcResultCode::Ok
                );

                let before = fib_entries(&db, OVERLAY_VRF, prefix);
                entries_are_well_formed(&before, "before the rmac");
                assert!(
                    before
                        .iter()
                        .all(|entry| matches!(entry.iter().next(), Some(PktInstruction::Drop))),
                    "an overlay route with no router mac must drop, got {before:?}"
                );

                assert_eq!(rmac_msg(vtep, macs()[mac]).add(&mut db), RpcResultCode::Ok);

                let after = fib_entries(&db, OVERLAY_VRF, prefix);
                entries_are_well_formed(&after, "after the rmac");
                let expected_mac = Mac::from(macs()[mac]);
                for entry in &after {
                    let mut instructions = entry.iter();
                    match instructions.next() {
                        Some(PktInstruction::Encap(Encapsulation::Vxlan(vxlan))) => {
                            assert_eq!(vxlan.vni.as_u32(), OVERLAY_VNI, "vni in {entry:?}");
                            assert_eq!(vxlan.remote, vtep, "remote in {entry:?}");
                            assert_eq!(vxlan.dmac, Some(expected_mac), "dmac in {entry:?}");
                        }
                        other => panic!("expected an encapsulation first, got {other:?}"),
                    }
                    match instructions.next() {
                        Some(PktInstruction::Egress(egress)) => {
                            assert_eq!(
                                egress.ifindex().map(InterfaceIndex::to_u32),
                                Some(UNDERLAY_IFINDEX),
                                "egress interface in {entry:?}"
                            );
                            assert_eq!(
                                *egress.address(),
                                Some(vtep),
                                "egress address in {entry:?}"
                            );
                        }
                        other => panic!("expected an egress second, got {other:?}"),
                    }
                    assert!(instructions.next().is_none(), "extra work in {entry:?}");
                }
            },
        );
    }

    #[test]
    fn withdrawing_a_router_mac_leaves_the_route_forwarding() {
        bolero::check!().with_generator(Fabrics).cloned().for_each(
            |(vtep, mac): (usize, usize)| {
                let mut db = fabric();
                let vtep = vteps()[vtep];
                let prefix = "10.0.0.0/24";
                let rmac = rmac_msg(vtep, macs()[mac]);

                overlay_route(OVERLAY_VRF, prefix, vtep).add(&mut db);
                rmac.add(&mut db);
                let before = fib_entries(&db, OVERLAY_VRF, prefix);

                assert_eq!(rmac.del(&mut db), RpcResultCode::Ok);
                db.vrftable.refresh_non_default_fibs(&db.rmac_store);

                let after = fib_entries(&db, OVERLAY_VRF, prefix);
                entries_are_well_formed(&after, "after withdrawing the rmac");
                assert_eq!(after, before, "withdrawing a router mac changed the fib");
            },
        );
    }

    #[test]
    fn an_unknown_vrf_fails_on_add_and_forgives_on_delete() {
        let missing = OVERLAY_VRF + 1;
        let prefix = "10.9.0.0/24";
        let vtep = vteps()[0];

        let mut db = fabric();
        assert_eq!(
            overlay_route(missing, prefix, vtep).add(&mut db),
            RpcResultCode::Failure
        );
        assert_eq!(
            overlay_route(missing, prefix, vtep).del(&mut db),
            RpcResultCode::Ok,
            "a delete for an unknown vrf is forgiven while we have no config"
        );

        db.set_config(RouterConfig::new(1));
        assert!(db.have_config());
        assert_eq!(
            overlay_route(missing, prefix, vtep).del(&mut db),
            RpcResultCode::Failure,
            "once a config is applied the same lookup is a real failure"
        );
    }

    #[test]
    fn deleting_the_last_route_of_a_dying_vrf_removes_it() {
        let mut db = fabric();
        let prefix = "10.0.0.0/24";
        let vtep = vteps()[0];
        let route = overlay_route(OVERLAY_VRF, prefix, vtep);
        route.add(&mut db);

        assert_eq!(route.del(&mut db), RpcResultCode::Ok);
        assert!(db.vrftable.contains(OVERLAY_VRF));

        route.add(&mut db);
        db.vrftable
            .get_vrf_mut(OVERLAY_VRF)
            .unwrap_or_else(|e| unreachable!("{e}"))
            .set_status(VrfStatus::Deleting);

        assert_eq!(route.del(&mut db), RpcResultCode::Ok);
        assert!(
            !db.vrftable.contains(OVERLAY_VRF),
            "a vrf that became deletable was left behind"
        );
    }

    #[test]
    fn an_interface_address_is_refused_unless_it_is_usable() {
        let cases = [
            (UNDERLAY_IFINDEX, 24, RpcResultCode::Ok),
            (UNDERLAY_IFINDEX, 0, RpcResultCode::InvalidRequest),
            (UNDERLAY_IFINDEX, 33, RpcResultCode::InvalidRequest),
            (0, 24, RpcResultCode::InvalidRequest),
        ];
        for (ifindex, mask, want) in cases {
            let mut db = fabric();
            let message = IfAddress {
                ifname: "eth0".to_string(),
                address: addr("10.0.0.1"),
                mask_len: mask,
                ifindex,
                vrfid: Vrf::DEFAULT_VRFID,
            };
            let present = |db: &RoutingDb| {
                let iftable = db.iftw.enter().unwrap_or_else(|| unreachable!());
                let Ok(index) = InterfaceIndex::try_new(ifindex) else {
                    return false;
                };
                iftable
                    .get_interface(index)
                    .is_some_and(|iface| !iface.addresses.is_empty())
            };

            assert_eq!(message.add(&mut db), want, "adding {message}");
            assert_eq!(
                present(&db),
                want == RpcResultCode::Ok,
                "after adding {message}"
            );

            assert_eq!(message.del(&mut db), want, "deleting {message}");
            assert!(!present(&db), "the address survived its own deletion");
        }
    }

    #[test]
    fn a_next_hop_in_another_vrf_is_nonlocal() {
        let vtep = vteps()[0];
        let mut route = overlay_route(OVERLAY_VRF, "10.0.0.0/24", vtep);
        assert!(!nonlocal_nhop(&route), "its own vrf is not nonlocal");
        route.nhops[0].vrfid = Vrf::DEFAULT_VRFID;
        assert!(nonlocal_nhop(&route), "another vrf is nonlocal");
        route.nhops.clear();
        assert!(!nonlocal_nhop(&route), "no next-hops, nothing nonlocal");
    }
}
