// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cli handling sumodule

#![allow(clippy::unnecessary_wraps)]

use crate::display::IfTableAddress;
use crate::display::{FibGroups, FibViewV4, FibViewV6};
use crate::display::{VrfV4Nexthops, VrfV6Nexthops, VrfViewV4, VrfViewV6};
use crate::fib::fibtype::{FibGroupV4Filter, FibGroupV6Filter};
use crate::rib::vrf::{Route, RouteOrigin, Vrf, VrfId};
use crate::rib::vrf::{RouteV4Filter, RouteV6Filter};
use crate::rib::vrftable::VrfTable;
use crate::rio::CpiStats;
use crate::routingdb::RoutingDb;

use cli::cliproto::{CliAction, CliError, CliRequest, CliResponse, CliSerialize, RouteProtocol};
use lpm::prefix::{Ipv4Prefix, Ipv6Prefix};
use net::vxlan::Vni;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use tracing::{error, trace};

impl From<&RouteProtocol> for RouteOrigin {
    fn from(proto: &RouteProtocol) -> Self {
        match proto {
            RouteProtocol::Local => RouteOrigin::Local,
            RouteProtocol::Connected => RouteOrigin::Connected,
            RouteProtocol::Static => RouteOrigin::Static,
            RouteProtocol::Ospf => RouteOrigin::Ospf,
            RouteProtocol::Isis => RouteOrigin::Isis,
            RouteProtocol::Bgp => RouteOrigin::Bgp,
        }
    }
}

fn show_vrf_ipv4_routes(vrf: &Vrf, filter: &RouteV4Filter) -> String {
    /* This builds a view of the vrf, with only IPv4 routes
      and maybe not all of them, depending on the filter.
      If other serializations are needed, here we could either build also
      the view and implement serde on the view.
      Alternatively, call vrf.iter_v4() or vrf.filter_v4() to yield
      iterators over the (prefix, Routes).
    */

    let view = VrfViewV4 { vrf, filter };
    format!("{view}")
}

fn show_vrf_ipv6_routes(vrf: &Vrf, filter: &RouteV6Filter) -> String {
    let view = VrfViewV6 { vrf, filter };
    format!("{view}")
}

fn show_ipv4_routes_single_vrf(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    filter: &RouteV4Filter,
) -> Result<CliResponse, CliError> {
    let out;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        out = show_vrf_ipv4_routes(vrf, filter);
    } else {
        return Err(CliError::NotFound(format!("VRF with id {vrfid}")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_ipv4_routes_multi(
    request: CliRequest,
    vrftable: &VrfTable,
    filter: &RouteV4Filter,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        out += show_vrf_ipv4_routes(vrf, filter).as_str();
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_ipv6_routes_single_vrf(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    filter: &RouteV6Filter,
) -> Result<CliResponse, CliError> {
    let out;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        out = show_vrf_ipv6_routes(vrf, filter);
    } else {
        return Err(CliError::NotFound(format!("VRF with id {vrfid}")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_ipv6_routes_multi(
    request: CliRequest,
    vrftable: &VrfTable,
    filter: &RouteV6Filter,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        out += show_vrf_ipv6_routes(vrf, filter).as_str();
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn route_filter_v4(request: &CliRequest) -> RouteV4Filter {
    let filter: RouteV4Filter = if let Some(protocol) = &request.args.protocol {
        let origin = RouteOrigin::from(protocol);
        Box::new(move |(_, route): &(&Ipv4Prefix, &Route)| route.origin == origin)
    } else {
        Box::new(|(_, _)| true)
    };
    filter
}
fn route_filter_v6(request: &CliRequest) -> RouteV6Filter {
    let filter: RouteV6Filter = if let Some(protocol) = &request.args.protocol {
        let origin = RouteOrigin::from(protocol);
        Box::new(move |(_, route): &(&Ipv6Prefix, &Route)| route.origin == origin)
    } else {
        Box::new(|(_, _)| true)
    };
    filter
}
fn show_vrf_routes(
    request: CliRequest,
    db: &RoutingDb,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;

    if ipv4 {
        let filter = route_filter_v4(&request);
        if let Some(vrfid) = request.args.vrfid {
            show_ipv4_routes_single_vrf(request, vrftable, vrfid, &filter)
        } else {
            show_ipv4_routes_multi(request, vrftable, &filter)
        }
    } else {
        let filter = route_filter_v6(&request);
        if let Some(vrfid) = request.args.vrfid {
            show_ipv6_routes_single_vrf(request, vrftable, vrfid, &filter)
        } else {
            show_ipv6_routes_multi(request, vrftable, &filter)
        }
    }
}

fn show_vrf_nexthops_single(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let out: String;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        if ipv4 {
            out = format!("{}", VrfV4Nexthops(vrf));
        } else {
            out = format!("{}", VrfV6Nexthops(vrf));
        }
    } else {
        return Err(CliError::NotFound(format!("with id {vrfid}")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_vrf_nexthops_multi(
    request: CliRequest,
    vrftable: &VrfTable,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        if ipv4 {
            out += format!("{}", VrfV4Nexthops(vrf)).as_ref();
        } else {
            out += format!("{}", VrfV6Nexthops(vrf)).as_ref();
        }
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_vrf_nexthops(
    request: CliRequest,
    db: &RoutingDb,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;

    if let Some(vrfid) = request.args.vrfid {
        show_vrf_nexthops_single(request, vrftable, vrfid, ipv4)
    } else {
        show_vrf_nexthops_multi(request, vrftable, ipv4)
    }
}

fn show_vrfs(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;
    if let Some(vni) = request.args.vni {
        let Ok(checked_vni) = Vni::try_from(vni) else {
            return Err(CliError::NotFound(format!("Invalid vni value: {vni}")));
        };
        if let Ok(vrf) = vrftable.get_vrf_by_vni(checked_vni) {
            Ok(CliResponse::from_request_ok(request, format!("\n{vrf}")))
        } else {
            Err(CliError::NotFound(format!("VRF with vni {checked_vni}")))
        }
    } else {
        Ok(CliResponse::from_request_ok(
            request,
            format!("\n{vrftable}"),
        ))
    }
}

fn show_fibgroups_ipv4(vrf: &Vrf, filter: &FibGroupV4Filter) -> String {
    let view = FibViewV4 { vrf, filter };
    format!("{view}")
}
fn show_fibgroups_ipv6(vrf: &Vrf, filter: &FibGroupV6Filter) -> String {
    let view = FibViewV6 { vrf, filter };
    format!("{view}")
}

fn fibgroup_filter_v4(_request: &CliRequest) -> FibGroupV4Filter {
    // Todo(fredi): filter by prefix, next-hop, interface and encap
    let filter: FibGroupV4Filter = Box::new(|(_, _)| true);
    filter
}
fn fibgroup_filter_v6(_request: &CliRequest) -> FibGroupV6Filter {
    // Todo(fredi): filter by prefix, next-hop, interface and encap
    let filter: FibGroupV6Filter = Box::new(|(_, _)| true);
    filter
}

fn show_single_fib_v4(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    filter: &FibGroupV4Filter,
) -> Result<CliResponse, CliError> {
    let out;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        out = show_fibgroups_ipv4(vrf, filter);
    } else {
        return Err(CliError::NotFound(format!("VRF with id {vrfid}")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_single_fib_v6(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    filter: &FibGroupV6Filter,
) -> Result<CliResponse, CliError> {
    let out;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        out = show_fibgroups_ipv6(vrf, filter);
    } else {
        return Err(CliError::NotFound(format!("VRF with id {vrfid}")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_multi_fib_v4(
    request: CliRequest,
    vrftable: &VrfTable,
    filter: &FibGroupV4Filter,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        out += show_fibgroups_ipv4(vrf, filter).as_str();
    }
    Ok(CliResponse::from_request_ok(request, out))
}
fn show_multi_fib_v6(
    request: CliRequest,
    vrftable: &VrfTable,
    filter: &FibGroupV6Filter,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        out += show_fibgroups_ipv6(vrf, filter).as_str();
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_ip_fib(request: CliRequest, db: &RoutingDb, ipv4: bool) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;
    if ipv4 {
        let filter = fibgroup_filter_v4(&request);
        if let Some(vrfid) = request.args.vrfid {
            show_single_fib_v4(request, vrftable, vrfid, &filter)
        } else {
            show_multi_fib_v4(request, vrftable, &filter)
        }
    } else {
        let filter = fibgroup_filter_v6(&request);
        if let Some(vrfid) = request.args.vrfid {
            show_single_fib_v6(request, vrftable, vrfid, &filter)
        } else {
            show_multi_fib_v6(request, vrftable, &filter)
        }
    }
}

fn show_ip_fib_groups_single(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let out: String;
    if let Ok(vrf) = vrftable.get_vrf(vrfid) {
        if ipv4 {
            out = format!("{}", FibGroups(vrf)); // for the time being we show all
        } else {
            out = format!("{}", FibGroups(vrf)); // for the time being we show all
        }
    } else {
        return Err(CliError::NotFound(format!("VRF with id {vrfid}")));
    }
    Ok(CliResponse::from_request_ok(request, out))
}
fn show_ip_fib_groups_multi(
    request: CliRequest,
    vrftable: &VrfTable,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let mut out = String::new();
    for vrf in vrftable.values() {
        if ipv4 {
            out += format!("{}", FibGroups(vrf)).as_ref();
        } else {
            out += format!("{}", FibGroups(vrf)).as_ref();
        }
    }
    Ok(CliResponse::from_request_ok(request, out))
}

fn show_ip_fib_groups(
    request: CliRequest,
    db: &RoutingDb,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;
    if let Some(vrfid) = request.args.vrfid {
        show_ip_fib_groups_single(request, vrftable, vrfid, ipv4)
    } else {
        show_ip_fib_groups_multi(request, vrftable, ipv4)
    }
}

fn do_handle_cli_request(
    request: CliRequest,
    db: &RoutingDb,
    stats: &CpiStats,
) -> Result<CliResponse, CliError> {
    let response = match request.action {
        CliAction::ShowCpiStats => CliResponse::from_request_ok(request, format!("\n{stats}")),
        CliAction::ShowRouterInterfaces => {
            if let Some(iftable) = db.iftw.enter() {
                CliResponse::from_request_ok(request, format!("\n{}", *iftable))
            } else {
                CliResponse::from_request_fail(request, CliError::InternalError)
            }
        }
        CliAction::ShowRouterInterfaceAddresses => {
            if let Some(iftable) = db.iftw.enter() {
                let iftable_addrs = IfTableAddress(&iftable);
                CliResponse::from_request_ok(request, format!("\n{iftable_addrs}"))
            } else {
                CliResponse::from_request_fail(request, CliError::InternalError)
            }
        }
        CliAction::ShowRouterVrfs => return show_vrfs(request, db),
        CliAction::ShowRouterEvpnRmacStore => {
            let rmac_store = &db.rmac_store;
            CliResponse::from_request_ok(request, format!("\n{rmac_store}"))
        }
        CliAction::ShowRouterEvpnVtep => {
            let vtep = &db.vtep;
            CliResponse::from_request_ok(request, format!("{vtep}"))
        }
        CliAction::ShowAdjacencies => {
            if let Some(atable) = db.atabler.enter() {
                CliResponse::from_request_ok(request, format!("\n{}", *atable))
            } else {
                CliResponse::from_request_fail(request, CliError::InternalError)
            }
        }
        CliAction::ShowRouterIpv4Routes => {
            return show_vrf_routes(request, db, true);
        }
        CliAction::ShowRouterIpv6Routes => {
            return show_vrf_routes(request, db, false);
        }
        CliAction::ShowRouterIpv4NextHops => {
            return show_vrf_nexthops(request, db, true);
        }
        CliAction::ShowRouterIpv6NextHops => {
            return show_vrf_nexthops(request, db, false);
        }
        CliAction::ShowRouterIpv4FibEntries => {
            return show_ip_fib(request, db, true);
        }
        CliAction::ShowRouterIpv6FibEntries => {
            return show_ip_fib(request, db, false);
        }
        CliAction::ShowRouterIpv4FibGroups => {
            return show_ip_fib_groups(request, db, true);
        }
        CliAction::ShowRouterIpv6FibGroups => {
            return show_ip_fib_groups(request, db, false);
        }
        _ => Err(CliError::NotSupported("Not implemented yet".to_owned()))?,
    };
    Ok(response)
}

pub(crate) fn handle_cli_request(
    sock: &UnixDatagram,
    peer: &SocketAddr,
    request: CliRequest,
    db: &RoutingDb,
    stats: &CpiStats,
) {
    trace!("Got cli request: {:#?} from {:?}", request, peer);

    let cliresponse = do_handle_cli_request(request.clone(), db, stats)
        .unwrap_or_else(|e| CliResponse::from_request_fail(request, e));

    /* serialize the response */
    let response = cliresponse.serialize().unwrap_or_else(|_| {
        error!("Failed to serialize CLI response !!");
        "Failure".into()
    });

    let response_len = (response.len() as u64).to_ne_bytes();
    let _ = sock.send_to_addr(&response_len, peer); // FIXME
    match sock.send_to_addr(&response, peer) {
        Ok(len) => trace!("Sent cli response ({len} octets)"),
        Err(e) => error!("Failure sending CLI response: {e}"),
    }
}
