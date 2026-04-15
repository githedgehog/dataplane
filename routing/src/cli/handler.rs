// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cli handling sumodule

#![allow(clippy::unnecessary_wraps)]

use super::display::IfTableAddress;
use super::display::{FibGroups, FibViewV4, FibViewV6};
use super::display::{VrfV4Nexthops, VrfV6Nexthops, VrfViewV4, VrfViewV6};

use crate::fib::fibtype::{FibRouteV4Filter, FibRouteV6Filter};
use crate::rib::vrf::{Route, RouteOrigin, Vrf, VrfId};
use crate::rib::vrf::{RouteV4Filter, RouteV6Filter};
use crate::rib::vrftable::VrfTable;

use crate::router::CliSources;
use crate::router::cpi::rpc_send_control;
use crate::router::revent::ROUTER_EVENTS;
use crate::router::rio::Rio;
use crate::routingdb::RoutingDb;

use chrono::Local;
use cli::cliproto::{CliAction, CliError, CliRequest, CliResponse, RequestArgs, RouteProtocol};
use config::{ConfigSummary, GwConfig, GwConfigMeta};
use lpm::prefix::{Ipv4Prefix, Ipv6Prefix};
use net::vxlan::Vni;
use std::os::unix::net::SocketAddr;
use std::sync::Arc;

use common::cliprovider::{CliDataProvider, Heading};
use strum::IntoEnumIterator;

#[allow(unused)]
use tracing::{error, trace};

use tracectl::{get_trace_ctl, trace_target};
trace_target!("cli", LevelFilter::OFF, &[]);

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

fn show_fibgroups_ipv4(vrf: &Vrf, filter: &FibRouteV4Filter) -> String {
    let view = FibViewV4 { vrf, filter };
    format!("{view}")
}
fn show_fibgroups_ipv6(vrf: &Vrf, filter: &FibRouteV6Filter) -> String {
    let view = FibViewV6 { vrf, filter };
    format!("{view}")
}

fn fibgroup_filter_v4(_request: &CliRequest) -> FibRouteV4Filter {
    // Todo(fredi): filter by prefix, next-hop, interface and encap
    let filter: FibRouteV4Filter = Box::new(|(_, _)| true);
    filter
}
fn fibgroup_filter_v6(_request: &CliRequest) -> FibRouteV6Filter {
    // Todo(fredi): filter by prefix, next-hop, interface and encap
    let filter: FibRouteV6Filter = Box::new(|(_, _)| true);
    filter
}

fn show_single_fib_v4(
    request: CliRequest,
    vrftable: &VrfTable,
    vrfid: VrfId,
    filter: &FibRouteV4Filter,
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
    filter: &FibRouteV6Filter,
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
    filter: &FibRouteV4Filter,
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
    filter: &FibRouteV6Filter,
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
        #[allow(clippy::if_same_then_else)]
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
        #[allow(clippy::if_same_then_else)]
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

fn show_provider(
    request: CliRequest,
    provider: Option<&(dyn CliDataProvider + Send)>,
) -> CliResponse {
    let data = provider.map_or_else(
        || "no data is available".to_string(),
        CliDataProvider::provide,
    );
    CliResponse::from_request_ok(request, data)
}

fn show_config(request: CliRequest, config: Option<&Arc<GwConfig>>) -> CliResponse {
    let Some(config) = config else {
        return CliResponse::from_request_ok(request, "No configuration is applied".to_string());
    };
    let vpc_table = &config.external.overlay.vpc_table;
    let contents = match request.action {
        CliAction::ShowVpc => vpc_table.as_summary().to_string(),
        CliAction::ShowVpcPeerings => vpc_table.as_peerings().to_string(),
        CliAction::ShowGatewayGroups => config.external.gwgroups.to_string(),
        CliAction::ShowGatewayCommunities => config.external.communities.to_string(),
        CliAction::ShowConfigInternal => {
            let heading = Heading("Internal configuration").to_string();
            format!("{heading}{:#?}", config.internal)
        }
        _ => unreachable!(),
    };
    CliResponse::from_request_ok(request, contents)
}
fn show_config_summary(request: CliRequest, summary: &[GwConfigMeta]) -> CliResponse {
    CliResponse::from_request_ok(request, ConfigSummary(summary).to_string())
}

fn show_tech(
    request: CliRequest,
    db: &RoutingDb,
    rio: &mut Rio,
    sources: &CliSources,
) -> CliResponse {
    let excluded = [
        CliAction::ShowTech,
        CliAction::CpiRequestRefresh,
        CliAction::FrrmiApplyLastConfig,
    ];
    let time = Local::now();
    let mut data = format!("time: {}\n", time.format("%Y-%m-%d %H:%M:%S"));

    for action in CliAction::iter().filter(|a| !excluded.contains(a)) {
        let request = CliRequest::new(action, RequestArgs::default());
        if let Ok(response) = do_handle_cli_request(request, db, rio, sources) {
            if let Ok(output) = response.result {
                data += output.as_str();
                data += "\n";
            }
        }
    }

    CliResponse::from_request_ok(request, data)
}

#[allow(clippy::too_many_lines)]
fn do_handle_cli_request(
    request: CliRequest,
    db: &RoutingDb,
    rio: &mut Rio,
    sources: &CliSources,
) -> Result<CliResponse, CliError> {
    let cpi_s = &rio.cpistats;
    let frrmi = &rio.frrmi;
    let response = match request.action {
        CliAction::ShowTech => show_tech(request, db, rio, sources),
        CliAction::ShowVpc
        | CliAction::ShowVpcPeerings
        | CliAction::ShowGatewayCommunities
        | CliAction::ShowGatewayGroups
        | CliAction::ShowConfigInternal => show_config(request, rio.gwconfig.as_ref()),
        CliAction::ShowConfigSummary => show_config_summary(request, rio.cfg_history.as_ref()),
        CliAction::ShowTracingTargets => match get_trace_ctl().as_string() {
            Ok(out) => CliResponse::from_request_ok(request, format!("\n {out}")),
            Err(_) => CliResponse::from_request_fail(request, CliError::InternalError),
        },
        CliAction::ShowTracingTagGroups => match get_trace_ctl().as_string_by_tag() {
            Ok(out) => CliResponse::from_request_ok(request, format!("\n {out}")),
            Err(_) => CliResponse::from_request_fail(request, CliError::InternalError),
        },
        CliAction::ShowCpiStats => CliResponse::from_request_ok(request, format!("\n {cpi_s}")),
        CliAction::ShowFrrmiStats => CliResponse::from_request_ok(request, format!("\n{frrmi}")),
        CliAction::ShowFrrmiLastConfig => match frrmi.get_applied_cfg() {
            Some(cfg) => CliResponse::from_request_ok(request, format!("\n{cfg}")),
            None => CliResponse::from_request_ok(request, "\n No config is applied".to_string()),
        },
        CliAction::FrrmiApplyLastConfig => {
            if let Some(genid) = db.current_config() {
                rio.reapply_frr_config(db);
                CliResponse::from_request_ok(
                    request,
                    format!("Requested to apply config for gen {genid}"),
                )
            } else {
                CliResponse::from_request_ok(request, "There is no configuration".to_string())
            }
        }
        CliAction::CpiRequestRefresh => {
            let Some(peer) = &rio.cpistats.peer else {
                return Ok(CliResponse::from_request_ok(
                    request,
                    "No connection over CPI".to_string(),
                ));
            };
            rpc_send_control(&mut rio.cpi_sock, peer, true);
            CliResponse::from_request_ok(request, "Requested refresh...".to_string())
        }
        CliAction::RouterEventLog => ROUTER_EVENTS.with(|el| {
            let el = el.borrow();
            CliResponse::from_request_ok(request, format!("{el}"))
        }),
        CliAction::ShowRouterInterfaces => {
            let iftable = db.iftw.enter().ok_or(CliError::InternalError)?;
            CliResponse::from_request_ok(request, format!("\n{}", *iftable))
        }
        CliAction::ShowRouterInterfaceAddresses => {
            let iftable = db.iftw.enter().ok_or(CliError::InternalError)?;
            let iftable_addrs = IfTableAddress(&iftable);
            CliResponse::from_request_ok(request, format!("\n{iftable_addrs}"))
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
            let atable = db.atabler.enter().ok_or(CliError::InternalError)?;
            CliResponse::from_request_ok(request, format!("\n{}", *atable))
        }
        CliAction::ShowRouterIpv4Routes => show_vrf_routes(request, db, true)?,
        CliAction::ShowRouterIpv6Routes => show_vrf_routes(request, db, false)?,
        CliAction::ShowRouterIpv4NextHops => show_vrf_nexthops(request, db, true)?,
        CliAction::ShowRouterIpv6NextHops => show_vrf_nexthops(request, db, false)?,
        CliAction::ShowRouterIpv4FibEntries => show_ip_fib(request, db, true)?,
        CliAction::ShowRouterIpv6FibEntries => show_ip_fib(request, db, false)?,
        CliAction::ShowRouterIpv4FibGroups => show_ip_fib_groups(request, db, true)?,
        CliAction::ShowRouterIpv6FibGroups => show_ip_fib_groups(request, db, false)?,
        CliAction::ShowFlowTable => show_provider(request, sources.flow_table.as_deref()),
        CliAction::ShowFlowFilter => show_provider(request, sources.flow_filter.as_deref()),
        CliAction::ShowPortForwarding => show_provider(request, sources.portfw_table.as_deref()),
        CliAction::ShowStaticNat => show_provider(request, sources.nat_tables.as_deref()),
        CliAction::ShowMasquerading => show_provider(request, sources.masquerade_state.as_deref()),
        CliAction::ShowPacketStats => show_provider(request, sources.pkt_stats.as_deref()),
        _ => Err(CliError::NotSupported("Not implemented yet".to_string()))?,
    };
    Ok(response)
}

#[allow(clippy::cast_possible_truncation)]
pub(crate) fn handle_cli_request(
    rio: &mut Rio,
    peer: &SocketAddr,
    request: CliRequest,
    db: &RoutingDb,
    cli_sources: &CliSources,
) {
    trace!("Got cli request: {request:#?} from {peer:?}");

    // handle the request
    let cliresponse = do_handle_cli_request(request.clone(), db, rio, cli_sources)
        .unwrap_or_else(|e| CliResponse::from_request_fail(request, e));

    // serialize the response and send it. Response may be sent in multiple chunks.
    // If not all of them can be sent, they will be cached.
    if let Err(e) = cliresponse.send(peer, &rio.clisock, &mut rio.cli_cache) {
        error!("Failed to send response: {e}");
    }
}
