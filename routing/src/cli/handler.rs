// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cli handling sumodule

#![allow(clippy::unnecessary_wraps)]

use super::display::IfTableAddress;
use super::display::RmacStoreView;
use super::display::{FibGroups, FibViewV4, FibViewV6};
use super::display::{VrfV4Nexthops, VrfV6Nexthops, VrfViewV4, VrfViewV6};

use crate::Vtep;
use crate::evpn::{RmacFilter, RmacStore};
use crate::fib::fibtype::{FibRouteV4Filter, FibRouteV6Filter};
use crate::frr::frrmi::Frrmi;
use crate::rib::vrf::{RouteOrigin, Vrf};
use crate::rib::vrf::{RouteV4Filter, RouteV6Filter};
use crate::rib::vrftable::VrfTable;

use crate::router::CliSources;
use crate::router::cpi::rpc_send_control;
use crate::router::revent::ROUTER_EVENTS;
use crate::router::rio::Rio;
use crate::routingdb::RoutingDb;

use chrono::Local;
use cli::cliproto::{
    CliAction, CliError, CliRequest, CliResponse, PrefetchSelector, PrefetchedData, RequestArgs,
    RouteProtocol,
};
use concurrency::sync::Arc;
use config::{ConfigSummary, GwConfigMeta, ValidatedGwConfig};
use lpm::prefix::{Ipv4Prefix, Ipv6Prefix, Prefix};
use net::eth::mac::SourceMac;
use net::vxlan::Vni;
use std::os::unix::net::SocketAddr;

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
    VrfViewV4 { vrf, filter }.to_string()
}
fn show_vrf_ipv6_routes(vrf: &Vrf, filter: &RouteV6Filter) -> String {
    VrfViewV6 { vrf, filter }.to_string()
}

fn show_ipv4_routes(request: CliRequest, vrfs: &[&Vrf], filter: &RouteV4Filter) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        out += show_vrf_ipv4_routes(vrf, filter).as_str();
    }
    CliResponse::from_request_ok(request, out)
}
fn show_ipv6_routes(request: CliRequest, vrfs: &[&Vrf], filter: &RouteV6Filter) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        out += show_vrf_ipv6_routes(vrf, filter).as_str();
    }
    CliResponse::from_request_ok(request, out)
}

fn get_ipv4_prefix(request: &CliRequest) -> Result<Option<Ipv4Prefix>, CliError> {
    let Some((addr, plen)) = &request.args.prefix else {
        return Ok(None);
    };
    let prefix =
        Prefix::try_from((*addr, *plen)).map_err(|e| CliError::WrongFilter(e.to_string()))?;
    match prefix {
        Prefix::IPV4(ipv4) => Ok(Some(ipv4)),
        Prefix::IPV6(_) => Err(CliError::WrongFilter("prefix is not ipv4".into())),
    }
}
fn get_ipv6_prefix(request: &CliRequest) -> Result<Option<Ipv6Prefix>, CliError> {
    let Some((addr, plen)) = &request.args.prefix else {
        return Ok(None);
    };
    let prefix =
        Prefix::try_from((*addr, *plen)).map_err(|e| CliError::WrongFilter(e.to_string()))?;
    match prefix {
        Prefix::IPV4(_) => Err(CliError::WrongFilter("prefix is not ipv6".into())),
        Prefix::IPV6(ipv6) => Ok(Some(ipv6)),
    }
}

fn route_filter_v4(request: &CliRequest) -> Result<RouteV4Filter, CliError> {
    // filter by ipv4 prefix
    let prefix = get_ipv4_prefix(request)?;

    // filter by prefix length
    let prefix_len = request.args.prefix_len;
    if let Some(len) = prefix_len
        && len > 32
    {
        return Err(CliError::InvalidPrefixLength(len));
    }

    // filter by protocol
    let protocol = request.args.protocol.as_ref().map(RouteOrigin::from);

    // build filter
    Ok(RouteV4Filter::new(prefix, prefix_len, protocol))
}
fn route_filter_v6(request: &CliRequest) -> Result<RouteV6Filter, CliError> {
    // filter by ipv6 prefix
    let prefix = get_ipv6_prefix(request)?;

    // filter by prefix length
    let prefix_len = request.args.prefix_len;
    if let Some(len) = prefix_len
        && len > 128
    {
        return Err(CliError::InvalidPrefixLength(len));
    }

    // filter by protocol
    let protocol = request.args.protocol.as_ref().map(RouteOrigin::from);

    // build filter
    Ok(RouteV6Filter::new(prefix, prefix_len, protocol))
}

// Look up vrf(s) depending on the request. A particular vrf can be looked up from
// vpc name, vrfid and vni. Multiple of these fields may be specified. The precedence
// is: 1) vpc 2) vrfid 3) vni. In the case of vpc names, multiple vrfs may be returned.
fn lookup_vrfs<'a>(vrftable: &'a VrfTable, request: &CliRequest) -> Result<Vec<&'a Vrf>, CliError> {
    if let Some(vpc) = &request.args.vpc {
        let vrfs = vrftable
            .get_vrfs_by_vpc(vpc.as_str())
            .map_err(|_| CliError::NotFound(format!("VRF with with descr {vpc}")))?;

        Ok(vrfs)
    } else if let Some(vrfid) = request.args.vrfid {
        let vrf = vrftable
            .get_vrf(vrfid)
            .map_err(|_| CliError::NotFound(format!("VRF with id {vrfid}")))?;

        Ok(vec![vrf])
    } else if let Some(vni) = &request.args.vni {
        let checked_vni = Vni::try_from(*vni)
            .map_err(|_| CliError::NotFound(format!("Invalid vni value: {vni}")))?;

        let vrf = vrftable
            .get_vrf_by_vni(checked_vni)
            .map_err(|_| CliError::NotFound(format!("VRF with vni {checked_vni}")))?;

        Ok(vec![vrf])
    } else {
        // all vrfs
        let vrfs = vrftable.values().collect();
        Ok(vrfs)
    }
}

fn show_vrf_routes(
    request: CliRequest,
    db: &RoutingDb,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;
    let found = lookup_vrfs(vrftable, &request)?;

    let response = if ipv4 {
        let filter = route_filter_v4(&request)?;
        show_ipv4_routes(request, found.as_slice(), &filter)
    } else {
        let filter = route_filter_v6(&request)?;
        show_ipv6_routes(request, found.as_slice(), &filter)
    };
    Ok(response)
}

fn show_vrf_nexthops_ip(request: CliRequest, vrfs: &[&Vrf], ipv4: bool) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        if ipv4 {
            out += VrfV4Nexthops(vrf).to_string().as_str();
        } else {
            out += VrfV6Nexthops(vrf).to_string().as_str();
        }
    }
    CliResponse::from_request_ok(request, out)
}

fn show_vrf_nexthops(
    request: CliRequest,
    db: &RoutingDb,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;
    let found = lookup_vrfs(vrftable, &request)?;
    let response = show_vrf_nexthops_ip(request, found.as_slice(), ipv4);
    Ok(response)
}

fn show_fib_ipv4(vrf: &Vrf, filter: &FibRouteV4Filter) -> String {
    FibViewV4 { vrf, filter }.to_string()
}
fn show_fib_ipv6(vrf: &Vrf, filter: &FibRouteV6Filter) -> String {
    FibViewV6 { vrf, filter }.to_string()
}

fn fibgroup_filter_v4(request: &CliRequest) -> Result<FibRouteV4Filter, CliError> {
    let prefix = get_ipv4_prefix(request)?;
    let filter = FibRouteV4Filter::new(prefix, request.args.prefix_len);
    Ok(filter)
}
fn fibgroup_filter_v6(request: &CliRequest) -> Result<FibRouteV6Filter, CliError> {
    let prefix = get_ipv6_prefix(request)?;
    let filter = FibRouteV6Filter::new(prefix, request.args.prefix_len);
    Ok(filter)
}

fn show_ip_fib_v4(request: CliRequest, vrfs: &[&Vrf], filter: &FibRouteV4Filter) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        out += show_fib_ipv4(vrf, filter).as_str();
    }
    CliResponse::from_request_ok(request, out)
}
fn show_ip_fib_v6(request: CliRequest, vrfs: &[&Vrf], filter: &FibRouteV6Filter) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        out += show_fib_ipv6(vrf, filter).as_ref();
    }
    CliResponse::from_request_ok(request, out)
}

fn show_ip_fib(request: CliRequest, db: &RoutingDb, ipv4: bool) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;
    let found = lookup_vrfs(vrftable, &request)?;

    let response = if ipv4 {
        let filter = fibgroup_filter_v4(&request)?;
        show_ip_fib_v4(request, found.as_slice(), &filter)
    } else {
        let filter = fibgroup_filter_v6(&request)?;
        show_ip_fib_v6(request, found.as_slice(), &filter)
    };
    Ok(response)
}

#[allow(clippy::if_same_then_else)]
fn show_ip_fib_groups_vrf(request: CliRequest, vrfs: &[&Vrf], ipv4: bool) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        if ipv4 {
            out += FibGroups(vrf).to_string().as_str();
        } else {
            out += FibGroups(vrf).to_string().as_str();
        }
    }
    CliResponse::from_request_ok(request, out)
}

fn show_ip_fib_groups(
    request: CliRequest,
    db: &RoutingDb,
    ipv4: bool,
) -> Result<CliResponse, CliError> {
    let vrftable = &db.vrftable;
    let found = lookup_vrfs(vrftable, &request)?;
    let response = show_ip_fib_groups_vrf(request, found.as_slice(), ipv4);
    Ok(response)
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

fn show_config(request: CliRequest, config: Option<&Arc<ValidatedGwConfig>>) -> CliResponse {
    let Some(config) = config else {
        return CliResponse::from_request_ok(request, "No configuration is applied".to_string());
    };
    let vpc_table = &config.external().overlay().vpc_table();
    let contents = match request.action {
        CliAction::ShowVpc => vpc_table.as_summary().to_string(),
        CliAction::ShowVpcPeerings => vpc_table.as_peerings().to_string(),
        CliAction::ShowVpcRouting => vpc_table.as_route_tables().to_string(),
        CliAction::ShowGatewayGroups => config.external().gwgroups().to_string(),
        CliAction::ShowGatewayCommunities => config.external().communities().to_string(),
        CliAction::ShowConfigInternal => {
            let heading = Heading("Internal configuration").to_string();
            format!("{heading}{:#?}", config.internal())
        }
        _ => unreachable!(),
    };
    CliResponse::from_request_ok(request, contents)
}
fn show_config_summary(request: CliRequest, summary: &[GwConfigMeta]) -> CliResponse {
    CliResponse::from_request_ok(request, ConfigSummary(summary).to_string())
}

fn show_tracing_targets(request: CliRequest) -> CliResponse {
    match get_trace_ctl().as_string() {
        Ok(out) => CliResponse::from_request_ok(request, format!("\n {out}")),
        Err(e) => CliResponse::from_request_fail(request, CliError::InternalError(e.to_string())),
    }
}
fn show_tracing_tags(request: CliRequest) -> CliResponse {
    match get_trace_ctl().as_string_by_tag() {
        Ok(out) => CliResponse::from_request_ok(request, format!("\n {out}")),
        Err(e) => CliResponse::from_request_fail(request, CliError::InternalError(e.to_string())),
    }
}
fn show_vrfs(request: CliRequest, vrftable: &VrfTable) -> CliResponse {
    CliResponse::from_request_ok(request, vrftable.to_string())
}

fn rmac_filter(request: &CliRequest) -> Result<RmacFilter, CliError> {
    let vni = request
        .args
        .vni
        .map(|vni| Vni::new_checked(vni).map_err(|e| CliError::WrongFilter(e.to_string())))
        .transpose()?;

    let mac = request
        .args
        .mac
        .as_ref()
        .map(|m| SourceMac::try_from(m.as_str()).map_err(|e| CliError::WrongFilter(e.to_string())))
        .transpose()?;

    let filter = RmacFilter::new(vni, request.args.address, mac);
    Ok(filter)
}

fn show_rmac_store(request: CliRequest, rmac_store: &RmacStore) -> Result<CliResponse, CliError> {
    let filter = rmac_filter(&request)?;
    let out = RmacStoreView { rmac_store, filter };

    Ok(CliResponse::from_request_ok(request, out.to_string()))
}

fn show_vtep(request: CliRequest, vtep: &Vtep) -> CliResponse {
    CliResponse::from_request_ok(request, vtep.to_string())
}
fn show_adjacency_table(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    let atable = db.atabler.enter().ok_or(CliError::Inacessible)?;
    Ok(CliResponse::from_request_ok(request, atable.to_string()))
}
fn show_interfaces(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    let iftable = db.iftw.enter().ok_or(CliError::Inacessible)?;
    Ok(CliResponse::from_request_ok(request, iftable.to_string()))
}
fn show_interface_addresses(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    let iftable = db.iftw.enter().ok_or(CliError::Inacessible)?;
    let iftable_addrs = IfTableAddress(&iftable);
    Ok(CliResponse::from_request_ok(
        request,
        iftable_addrs.to_string(),
    ))
}
fn show_frr_last_applied_config(request: CliRequest, frrmi: &Frrmi) -> CliResponse {
    match frrmi.get_applied_cfg() {
        Some(cfg) => CliResponse::from_request_ok(request, format!("\n{cfg}")),
        None => CliResponse::from_request_ok(request, "\n No config is applied".to_string()),
    }
}
fn show_router_events(request: CliRequest) -> CliResponse {
    ROUTER_EVENTS.with(|el| {
        let el = el.borrow();
        CliResponse::from_request_ok(request, el.to_string())
    })
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

fn reapply_frr_config(request: CliRequest, db: &RoutingDb, rio: &mut Rio) -> CliResponse {
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
fn request_refresh(request: CliRequest, rio: &mut Rio) -> CliResponse {
    let Some(peer) = &rio.cpistats.peer else {
        return CliResponse::from_request_ok(request, "No connection over CPI".to_string());
    };
    rpc_send_control(&mut rio.cpi_sock, peer, true);
    CliResponse::from_request_ok(request, "Requested refresh...".to_string())
}

/* prefetch handling */
fn prefetch_vpcs(cfg: Option<&Arc<ValidatedGwConfig>>) -> PrefetchedData {
    let vpcs = if let Some(cfg) = cfg {
        cfg.external()
            .overlay()
            .vpc_table()
            .values()
            .map(|vpc| vpc.name().to_string())
            .collect()
    } else {
        vec![]
    };
    PrefetchedData::with_data(PrefetchSelector::Vpcs, vpcs)
}
fn prefetch_vnis(cfg: Option<&Arc<ValidatedGwConfig>>) -> PrefetchedData {
    let vpcs = if let Some(cfg) = cfg {
        cfg.external()
            .overlay()
            .vpc_table()
            .values()
            .map(|vpc| vpc.vni().to_string())
            .collect()
    } else {
        vec![]
    };
    PrefetchedData::with_data(PrefetchSelector::Vnis, vpcs)
}
fn prefetch_interfaces(db: &RoutingDb) -> PrefetchedData {
    let interfaces: Vec<String> = if let Some(iftable) = db.iftw.enter() {
        iftable
            .values()
            .map(|iface| iface.name.to_string())
            .collect()
    } else {
        vec![]
    };
    PrefetchedData::with_data(PrefetchSelector::Interfaces, interfaces)
}
fn prefetch_rmac_ips(db: &RoutingDb) -> PrefetchedData {
    let mut rmacs: Vec<String> = db
        .rmac_store
        .values()
        .map(|e| e.address.to_string())
        .collect();

    rmacs.sort_unstable();
    rmacs.dedup();
    PrefetchedData::with_data(PrefetchSelector::RmacIp, rmacs)
}
fn prefetch_rmac_macs(db: &RoutingDb) -> PrefetchedData {
    let mut rmacs: Vec<String> = db.rmac_store.values().map(|e| e.mac.to_string()).collect();

    rmacs.sort_unstable();
    rmacs.dedup();
    PrefetchedData::with_data(PrefetchSelector::RmacIp, rmacs)
}

fn prefetch(request: CliRequest, rio: &Rio, db: &RoutingDb) -> CliResponse {
    let Some(selector) = request.args.selector else {
        return CliResponse::with_prefetch_data(request, PrefetchedData::default());
    };
    let data = match selector {
        PrefetchSelector::Vpcs => prefetch_vpcs(rio.gwconfig.as_ref()),
        PrefetchSelector::Vnis => prefetch_vnis(rio.gwconfig.as_ref()),
        PrefetchSelector::Interfaces => prefetch_interfaces(db),
        PrefetchSelector::RmacIp => prefetch_rmac_ips(db),
        PrefetchSelector::RmacMac => prefetch_rmac_macs(db),
    };
    CliResponse::with_prefetch_data(request, data)
}

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
        | CliAction::ShowVpcRouting
        | CliAction::ShowGatewayCommunities
        | CliAction::ShowGatewayGroups
        | CliAction::ShowConfigInternal => show_config(request, rio.gwconfig.as_ref()),
        CliAction::ShowConfigSummary => show_config_summary(request, rio.cfg_history.as_ref()),
        CliAction::ShowTracingTargets => show_tracing_targets(request),
        CliAction::ShowTracingTagGroups => show_tracing_tags(request),
        CliAction::ShowCpiStats => CliResponse::from_request_ok(request, format!("\n {cpi_s}")),
        CliAction::ShowFrrmiStats => CliResponse::from_request_ok(request, format!("\n{frrmi}")),
        CliAction::ShowFrrmiLastConfig => show_frr_last_applied_config(request, frrmi),
        CliAction::FrrmiApplyLastConfig => reapply_frr_config(request, db, rio),
        CliAction::CpiRequestRefresh => request_refresh(request, rio),
        CliAction::RouterEventLog => show_router_events(request),
        CliAction::ShowRouterInterfaces => show_interfaces(request, db)?,
        CliAction::ShowRouterInterfaceAddresses => show_interface_addresses(request, db)?,
        CliAction::ShowRouterVrfs => show_vrfs(request, &db.vrftable),
        CliAction::ShowRouterEvpnRmacStore => show_rmac_store(request, &db.rmac_store)?,
        CliAction::ShowRouterEvpnVtep => show_vtep(request, &db.vtep),
        CliAction::ShowAdjacencies => show_adjacency_table(request, db)?,
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
        CliAction::ShowDriverStatus => show_provider(request, sources.driver_status.as_deref()),

        /* prefetching */
        CliAction::Prefetch => prefetch(request, rio, db),

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
