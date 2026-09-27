// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cli handling sumodule

#![allow(clippy::unnecessary_wraps)]

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
use tracing::{debug, error, trace};

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

fn show_ipv4_routes(request: CliRequest, vrfs: &[&Vrf], filter: &RouteV4Filter) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        out += vrf.cli_ipv4_rib().filter(filter).to_string().as_str();
    }
    CliResponse::from_request_ok(request, out)
}
fn show_ipv6_routes(request: CliRequest, vrfs: &[&Vrf], filter: &RouteV6Filter) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        out += vrf.cli_ipv6_rib().filter(filter).to_string().as_str();
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

    Ok(RouteV6Filter::new(prefix, prefix_len, protocol))
}

// Look up vrf(s) depending on the request. A particular vrf can be looked up from
// vpc name, vrfid and vni. Multiple of these fields may be specified. The precedence
// is: 1) vpc 2) vrfid 3) vni. In the case of vpc names, multiple vrfs may be returned.
fn lookup_vrfs<'a>(vrftable: &'a VrfTable, request: &CliRequest) -> Result<Vec<&'a Vrf>, CliError> {
    if let Some(vpc) = &request.args.vpc {
        let vrfs = vrftable
            .get_vrfs_by_vpc(vpc.as_str())
            .map_err(|_| CliError::NotFound(format!("VRF with for VPC {vpc}")))?;

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
            out += vrf.cli_ipv4_nhops().to_string().as_str();
        } else {
            out += vrf.cli_ipv6_nhops().to_string().as_str();
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
        out += vrf.cli_ipv4_fib().filter(filter).to_string().as_str();
    }
    CliResponse::from_request_ok(request, out)
}
fn show_ip_fib_v6(request: CliRequest, vrfs: &[&Vrf], filter: &FibRouteV6Filter) -> CliResponse {
    let mut out = String::new();
    for vrf in vrfs {
        out += vrf.cli_ipv6_fib().filter(filter).to_string().as_str();
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
            out += vrf.cli_fib_groups().to_string().as_str();
        } else {
            out += vrf.cli_fib_groups().to_string().as_str();
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
    let out = rmac_store.cli_view().filter(&filter);

    Ok(CliResponse::from_request_ok(request, out.to_string()))
}

fn show_vtep(request: CliRequest, vtep: &Vtep) -> CliResponse {
    CliResponse::from_request_ok(request, vtep.to_string())
}
fn show_adjacency_table(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    let atable = db.atabler.enter().ok_or(CliError::Inaccessible)?;
    Ok(CliResponse::from_request_ok(request, atable.to_string()))
}
fn show_interfaces(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    let iftable = db.iftw.enter().ok_or(CliError::Inaccessible)?;
    Ok(CliResponse::from_request_ok(request, iftable.to_string()))
}

fn show_interface_addresses(request: CliRequest, db: &RoutingDb) -> Result<CliResponse, CliError> {
    let iftable = db.iftw.enter().ok_or(CliError::Inaccessible)?;
    let iftable_addrs = &iftable.cli_addresses();
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
    PrefetchedData::with_data(PrefetchSelector::RmacMac, rmacs)
}

fn prefetch(
    request: CliRequest,
    gwconfig: Option<&Arc<ValidatedGwConfig>>,
    db: &RoutingDb,
) -> CliResponse {
    let Some(selector) = request.args.selector else {
        return CliResponse::with_prefetch_data(request, PrefetchedData::default());
    };
    let data = match selector {
        PrefetchSelector::Vpcs => prefetch_vpcs(gwconfig),
        PrefetchSelector::Vnis => prefetch_vnis(gwconfig),
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
    let gwconfig = rio.gwconfig.as_ref();

    let response = match request.action {
        CliAction::ShowTech => show_tech(request, db, rio, sources),
        CliAction::ShowVpc
        | CliAction::ShowVpcPeerings
        | CliAction::ShowVpcRouting
        | CliAction::ShowGatewayCommunities
        | CliAction::ShowGatewayGroups
        | CliAction::ShowConfigInternal => show_config(request, gwconfig),
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
        CliAction::Prefetch => prefetch(request, gwconfig, db),

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

#[cfg(test)]
mod tests_cli_handling {
    use crate::AttachConfig;
    use crate::bmp::bmp_render::BgpNeighEvent;
    use crate::interfaces::interface::{IfDataEthernet, IfType, RouterInterfaceConfig};
    use crate::rib::vrf::RouterVrfConfig;
    use crate::{IfState, Vtep};
    use crate::{Router, RouterConfig, RouterCtlSender, RouterParams, RouterParamsBuilder};

    use clock::Duration;
    use concurrency::sync::Arc;
    use config::ValidatedGwConfig;
    use config::internal::status::BgpNeighborSessionState;

    use interface_manager::monitor::EthEvent;
    use lifecycle::{CancellationToken, Subsystem};

    use net::eth::mac::{Mac, SourceMac};
    use net::interface::{InterfaceIndex, InterfaceName};
    use net::route::RouteTableId;
    use net::vxlan::Vni;

    use std::net::IpAddr;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use tokio::task::JoinHandle;

    use bytes::Bytes;
    use cli::cliproto::{CliAction, CliError, CliRequest, CliResponse, RequestArgs};
    use dplane_rpc::msg::{
        ConnectInfo, ForwardAction, IfAddress, IpRoute, MacAddress, NextHop, Rmac, RouteType,
        RpcMsg, RpcObject, RpcOp, RpcRequest, RpcResultCode, VerInfo, WrapMsg,
    };
    use dplane_rpc::wire::Wire;

    use crate::frr::test::fake_frr_agent::fake_frr_agent;

    // max time to wait for a response from the router, over the CPI or the CLI
    const RECV_TIMEOUT: Duration = Duration::from_secs(5);

    // == Constants used by the tests == //
    const GENID_CFG_META: i64 = 1879;
    const IFINDEX: u32 = 13;
    const IFNAME: &str = "eth0";
    const IF_MAC: &str = "02:00:01:02:03:01";
    const IF_NEW_MAC: &str = "02:00:01:02:03:02";
    const IF_ADDR: &str = "10.0.1.99";
    const IF_ADDR_LEN: u8 = 27;

    const VRFID: u32 = 981;
    const VRFNAME: &str = "Vrf-test-1";
    const VRF_TBL_ID: u32 = 1234;
    const VNI: u32 = 3000;
    const VPC: &str = "VPC-1";
    const VTEP_IP: &str = "7.0.0.1";
    const VTEP_MAC: &str = "02:aa:bb:cc:dd:ee";

    const RMAC_IP: &str = "7.0.0.2";
    const RMAC_MAC: &str = "02:FF:AA:CC:EE:01";
    const RMAC_VNI: u32 = 4000;

    const ROUTE_PREFIX: &str = "192.168.50.0";
    const ROUTE_PREFIX_LEN: u8 = 24;
    const NHOP_ADDR: &str = "10.0.1.97";
    const NHOP_VRFID: u32 = VRFID;

    const ROUTE_PREFIX_V6: &str = "3000:a:b::";
    const ROUTE_PREFIX_V6_LEN: u8 = 64;
    const NHOP_ADDR_V6: &str = "2000:1:2:3:4:6:0:1";

    const BGP_PEER: &str = RMAC_IP;
    const BGP_PEER_ASN: u32 = 65123;

    const UNKNOWN_VPC: &str = "VPC-does-not-exist";

    const FRR_CONFIGURATION: &str = " !This is the FRR configuration";

    // ctl: router config builders
    fn build_router_vrf_config() -> RouterVrfConfig {
        RouterVrfConfig::new(VRFID, VRFNAME)
            .set_tableid(RouteTableId::try_from(VRF_TBL_ID).unwrap())
            .set_vpcname(VPC)
            .set_vni(Some(Vni::try_from(VNI).unwrap()))
    }
    fn build_router_interface_config() -> RouterInterfaceConfig {
        let name = InterfaceName::try_from(IFNAME).expect("Bad ifname");
        let ifindex = InterfaceIndex::try_from(IFINDEX).expect("Bad ifindex");
        let eth = IfDataEthernet::new(SourceMac::try_from(IF_MAC).expect("Bad mac"));
        let iftype = IfType::Ethernet(eth);
        let mut ifconfig = RouterInterfaceConfig::new(name, ifindex);
        ifconfig.set_iftype(iftype);
        ifconfig.set_admin_state(IfState::Up);
        ifconfig.set_attach_cfg(Some(AttachConfig::Vrf(VRFID)));
        ifconfig
    }
    fn build_vtep() -> Vtep {
        let mut vtep = Vtep::new();
        vtep.set_ip(IpAddr::from_str(VTEP_IP).unwrap());
        vtep.set_mac(Mac::try_from(VTEP_MAC).unwrap());
        vtep
    }
    fn build_router_config() -> RouterConfig {
        let vrfconfig = build_router_vrf_config();
        let ifconfig = build_router_interface_config();
        let vtep = build_vtep();
        let mut config = RouterConfig::new(1);
        config.add_vrf(vrfconfig);
        config.add_interface(ifconfig);
        config.set_vtep(vtep);
        config.set_frr_config(FRR_CONFIGURATION.to_string());
        config
    }

    // ctl: send messages to router
    async fn send_router_config(ctl: &RouterCtlSender, config: RouterConfig) {
        ctl.configure(config).await.unwrap();
    }
    async fn enable_cpi(ctl: &RouterCtlSender) {
        ctl.unlock().await.expect("cpi should unlock");
    }
    async fn send_gw_config(ctl: &RouterCtlSender) {
        let config = ValidatedGwConfig::blank();
        let mut meta = config.meta().load().as_ref().clone();
        meta.genid = GENID_CFG_META;
        ctl.send_config(config.into()).await.unwrap();
        ctl.send_config_history(Arc::new(vec![meta])).await.unwrap();
    }

    // Most ctl messages do not produce a reply.
    // This issues a request that the router replies to.
    // Getting the reply means that all prior messages were processed.
    async fn ctl_sync(ctl: &RouterCtlSender) {
        ctl.get_frr_applied_config()
            .await
            .expect("router should reply to ctl requests");
    }

    // ctl: send events to router
    async fn send_if_event_ifup(ctl: &RouterCtlSender) {
        let ifindex = InterfaceIndex::try_from(IFINDEX).expect("Bad ifindex");
        let ev = EthEvent::new(ifindex, true, true, true);
        ctl.send_ifevent(ev).await.unwrap();
    }
    async fn send_if_event_mac_change(ctl: &RouterCtlSender) {
        let ifindex = InterfaceIndex::try_from(IFINDEX).expect("Bad ifindex");
        let ev = EthEvent::new(ifindex, true, true, true)
            .set_mac(Some(SourceMac::try_from(IF_NEW_MAC).expect("Bad mac")));
        ctl.send_ifevent(ev).await.unwrap();
    }
    async fn send_bgp_neigh_change(ctl: &RouterCtlSender) {
        let bgp_ev = BgpNeighEvent::new(
            BGP_PEER.into(),
            BGP_PEER.into(),
            BGP_PEER_ASN,
            BgpNeighborSessionState::Idle,
            BgpNeighborSessionState::Established,
            None,
            None,
        );
        ctl.send_bgp_neigh_change(bgp_ev).await.unwrap();
    }

    #[track_caller]
    // Receive a message from cpi sock and check that it is a response and success
    fn cpi_recv_response(sock: &UnixDatagram) {
        let mut raw = vec![0; 1000];
        let (len, _a) = sock
            .recv_from(raw.as_mut_slice())
            .expect("No CPI response received in time");
        let mut buf_rx = Bytes::copy_from_slice(&raw[0..len]);
        let msg = RpcMsg::decode(&mut buf_rx).expect("Failure decoding CPI message");
        let response = msg
            .get_response()
            .expect("Got a msg but was not a response");
        assert_eq!(response.rescode, RpcResultCode::Ok, "CPI request failed");
    }

    // send a message (request) to the CPI, receive the response and check it is ok
    fn cpi_send_msg_and_recv_response(sock: &UnixDatagram, msg: &RpcMsg) {
        let cpi_addr: SocketAddr = sock.peer_addr().expect("cpi sock should be connected");
        msg.send(sock, &cpi_addr).unwrap();
        cpi_recv_response(sock);
    }

    // CPI message builders
    fn cpi_connect_request_msg() -> RpcMsg {
        let coninfo = ConnectInfo {
            pid: 999,
            name: "pseudo-frr".to_string(),
            verinfo: VerInfo::default(),
            synt: 0,
        };
        let object = RpcObject::ConnectInfo(coninfo);
        RpcRequest::new(RpcOp::Connect, 1)
            .set_object(object)
            .wrap_in_msg()
    }
    fn cpi_add_ifaddr_request_msg() -> RpcMsg {
        let ifaddr = IfAddress {
            ifname: IFNAME.to_string(),
            address: IpAddr::from_str(IF_ADDR).unwrap(),
            mask_len: IF_ADDR_LEN,
            ifindex: IFINDEX,
            vrfid: VRFID,
        };
        let object = RpcObject::IfAddress(ifaddr);
        RpcRequest::new(RpcOp::Add, 2)
            .set_object(object)
            .wrap_in_msg()
    }
    fn cpi_add_rmac_request_msg() -> RpcMsg {
        let rmac = Rmac {
            address: IpAddr::from_str(RMAC_IP).unwrap(),
            vni: RMAC_VNI,
            mac: MacAddress::new(Mac::try_from(RMAC_MAC).unwrap().as_ref().to_owned()),
        };
        let object = RpcObject::Rmac(rmac);
        RpcRequest::new(RpcOp::Add, 3)
            .set_object(object)
            .wrap_in_msg()
    }
    fn cpi_add_ipv4_route_request_msg() -> RpcMsg {
        let nexthop = NextHop {
            fwaction: ForwardAction::Forward,
            address: Some(IpAddr::from_str(NHOP_ADDR).unwrap()),
            ifindex: Some(IFINDEX),
            vrfid: NHOP_VRFID,
            encap: None,
        };
        let iproute = IpRoute {
            prefix: IpAddr::from_str(ROUTE_PREFIX).unwrap(),
            prefix_len: ROUTE_PREFIX_LEN,
            vrfid: VRFID,
            tableid: VRF_TBL_ID,
            rtype: RouteType::Bgp,
            distance: 50,
            metric: 100,
            nhops: vec![nexthop],
        };
        let object = RpcObject::IpRoute(iproute);
        RpcRequest::new(RpcOp::Add, 4)
            .set_object(object)
            .wrap_in_msg()
    }
    fn cpi_add_ipv6_route_request_msg() -> RpcMsg {
        let nexthop = NextHop {
            fwaction: ForwardAction::Forward,
            address: Some(IpAddr::from_str(NHOP_ADDR_V6).unwrap()),
            ifindex: Some(IFINDEX),
            vrfid: NHOP_VRFID,
            encap: None,
        };
        let iproute = IpRoute {
            prefix: IpAddr::from_str(ROUTE_PREFIX_V6).unwrap(),
            prefix_len: ROUTE_PREFIX_V6_LEN,
            vrfid: VRFID,
            tableid: VRF_TBL_ID,
            rtype: RouteType::Bgp,
            distance: 50,
            metric: 100,
            nhops: vec![nexthop],
        };
        let object = RpcObject::IpRoute(iproute);
        RpcRequest::new(RpcOp::Add, 5)
            .set_object(object)
            .wrap_in_msg()
    }

    // CPI send and recv
    fn cpi_send_connect_request(sock: &UnixDatagram) {
        cpi_send_msg_and_recv_response(sock, &cpi_connect_request_msg());
    }
    fn cpi_send_add_ifaddress(sock: &UnixDatagram) {
        cpi_send_msg_and_recv_response(sock, &cpi_add_ifaddr_request_msg());
    }
    fn cpi_send_add_rmac(sock: &UnixDatagram) {
        cpi_send_msg_and_recv_response(sock, &cpi_add_rmac_request_msg());
    }
    fn cpi_send_add_ipv4_route(sock: &UnixDatagram) {
        cpi_send_msg_and_recv_response(sock, &cpi_add_ipv4_route_request_msg());
    }
    fn cpi_send_add_ipv6_route(sock: &UnixDatagram) {
        cpi_send_msg_and_recv_response(sock, &cpi_add_ipv6_route_request_msg());
    }

    // Per-test directory for the unix sockets, so that tests running in parallel (in this
    // process or in others) never share socket paths. It is removed on drop.
    struct SockDir(PathBuf);
    impl SockDir {
        fn new(test: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("routing-{test}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("Failed to create socket dir");
            Self(dir)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for SockDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    // Guard to stop the router if an assertion fails
    struct RouterGuard {
        router: Router,
        frr_agent: JoinHandle<()>,
    }
    impl Drop for RouterGuard {
        fn drop(&mut self) {
            self.router.stop();
            self.frr_agent.abort();
        }
    }

    // util: open + connect unix sock
    fn unix_sock(bind_addr: &Path, remote_addr: &Path) -> Result<UnixDatagram, &'static str> {
        let sock = UnixDatagram::bind(bind_addr).map_err(|_| "Failed to bind socket")?;
        sock.connect(remote_addr)
            .map_err(|_| "Failed to connect socket")?;
        Ok(sock)
    }

    // open & connect socks for CLI and CPI
    fn open_socks(dir: &SockDir, cpi_path: &Path, cli_path: &Path) -> (UnixDatagram, UnixDatagram) {
        let cpi = unix_sock(&dir.path("frr-plugin"), cpi_path).expect("Failed to open cpi sock");

        cpi.set_read_timeout(Some(RECV_TIMEOUT))
            .expect("Failed to set cpi sock timeout");

        let cli = unix_sock(&dir.path("cli-client"), cli_path).expect("Failed to open cli sock");
        (cpi, cli)
    }

    // subsystem
    fn rio_subsystem() -> Subsystem {
        Subsystem::new("router", CancellationToken::new())
    }

    // issue cli request and receive the response
    fn cli_send_req(
        action: CliAction,
        sock: &UnixDatagram,
        args: Option<RequestArgs>,
    ) -> CliResponse {
        // send request
        let request = CliRequest::new(action, args.unwrap_or_default());
        request.send(sock).unwrap();

        // receive response
        CliResponse::recv_sync_timeout(sock, RECV_TIMEOUT).expect("Failure receiving CLI response")
    }

    // setup: cli/cpi endpoints
    fn router_params(dir: &SockDir) -> RouterParams {
        RouterParamsBuilder::default()
            .cpi_sock_path(dir.path("cpi.sock"))
            .cli_sock_path(dir.path("cli.sock"))
            .frr_agent_path(dir.path("frr-agent.sock"))
            .build()
            .expect("No reason to fail")
    }

    // setup: start router with its sockets in the given dir
    fn router(subsystem: &Subsystem, dir: &SockDir) -> Router {
        let params = router_params(dir);
        Router::new(subsystem, params, None).expect("No reason to fail")
    }

    #[tokio::test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn test_cli_handling() {
        // N.B. declared before the router so that the router is dropped (stopped) first
        let dir = SockDir::new("cli-handling");
        let subsystem = rio_subsystem();
        let router = router(&subsystem, &dir);
        let cpi_path = router.get_cpi_sock_path().clone();
        let cli_path = router.get_cli_sock_path().clone();
        let frr_agent_path = router.get_frr_agent_path().to_str().unwrap();
        let ctl = router.get_ctl_tx();

        // start fake frr agent
        let frr_agent = fake_frr_agent(frr_agent_path).await;

        // build guard so that router and frr_agent get stopped on asserts
        let _guard = RouterGuard { router, frr_agent };

        // open the cli and cpi socks to talk to router
        let (cpi, cli) = open_socks(&dir, &cpi_path, &cli_path);

        println!("Updating router state...");

        // enable the cpi: the router ignores the CPI until it is unlocked
        enable_cpi(&ctl).await;

        // mgmt: send (empty) config and update history
        send_gw_config(&ctl).await;

        // mgmt: send a router config with one VRF and interface
        send_router_config(&ctl, build_router_config()).await;

        // CPI: connect, add interface address, rmac, routes ...
        cpi_send_connect_request(&cpi);
        cpi_send_add_ifaddress(&cpi);
        cpi_send_add_rmac(&cpi);
        cpi_send_add_ipv4_route(&cpi);
        cpi_send_add_ipv6_route(&cpi);

        // ctl: update state of interface, mac and report bgp event
        send_if_event_ifup(&ctl).await;
        send_bgp_neigh_change(&ctl).await;
        send_if_event_mac_change(&ctl).await;

        // ctl: request the last config applied in frr.
        ctl_sync(&ctl).await;

        println!("Router state has been updated successfully. Will test cli..");

        // =============================================================== //
        // Tests: issue cli requests and check that the responses contain
        // data aligned with the inputs above.
        // =============================================================== //
        check_show_config_summary(&cli);
        check_show_event_log(&cli);
        check_show_vrfs(&cli);
        check_show_evpn_vtep(&cli);
        check_show_interfaces(&cli);
        check_show_interface_addresses(&cli);
        check_show_evpn_router_macs(&cli);
        check_show_ipv4_routes(&cli);
        check_show_ipv4_fib(&cli);
        check_show_ipv4_next_hops(&cli);
        check_show_ipv6_routes(&cli);
        check_show_ipv6_fib(&cli);
        check_show_ipv6_next_hops(&cli);
        check_show_last_frr_config(&cli);
        check_unknown_vpc_fails(&cli);
    }

    #[track_caller]
    fn has(output: &str, patterns: &[impl AsRef<str>], reason: &str) {
        for pattern in patterns {
            let pattern = pattern.as_ref();
            assert!(
                output.contains(pattern),
                "FAILURE:: {pattern} was not shown and it should: {reason}.\nOutput was:\n{output}"
            );
        }
    }

    // args to filter by the test VPC
    fn vpc_args(vpc: &str) -> RequestArgs {
        RequestArgs {
            vpc: Some(vpc.to_string()),
            ..Default::default()
        }
    }

    // wrapper around cli_send_req that expects a positive response to a cli request
    #[track_caller]
    fn send_cli(cli: &UnixDatagram, action: CliAction, args: Option<RequestArgs>) -> String {
        match cli_send_req(action, cli, args).result {
            Ok(output) => output,
            Err(e) => panic!("CLI request {action:?} failed: {e}"),
        }
    }

    fn check_show_config_summary(cli: &UnixDatagram) {
        println!(" * Testing that config summary is shown");
        let r = send_cli(cli, CliAction::ShowConfigSummary, None);
        has(&r, &[GENID_CFG_META.to_string()], "Config summary was sent");
    }
    fn check_show_event_log(cli: &UnixDatagram) {
        println!(" * Testing that event log captured relevant events");
        let r = send_cli(cli, CliAction::RouterEventLog, None);

        let bgp_status = BgpNeighborSessionState::Established.to_string();
        has(&r, &["Connected"], "CPI issue connected");
        has(&r, &[BGP_PEER, bgp_status.as_str()], "BGP event was sent");
        has(&r, &[IF_MAC, IF_NEW_MAC], "If event with Mac change sent");
        has(&r, &[IFNAME, "oper state"], "Event for op state sent");
    }
    fn check_show_vrfs(cli: &UnixDatagram) {
        println!(" * Testing that VRFs are shown");
        let r = send_cli(cli, CliAction::ShowRouterVrfs, None);

        has(&r, &[VRFNAME], "VRF name");
        has(&r, &[VRFID.to_string()], "VRF Id");
        has(&r, &[VRF_TBL_ID.to_string()], "VRF table id");
        has(&r, &[VNI.to_string()], "VRF vni");
        has(&r, &[VPC], "VRF VPC");
    }
    fn check_show_evpn_vtep(cli: &UnixDatagram) {
        println!(" * Testing that evpn vtep is shown");
        let r = send_cli(cli, CliAction::ShowRouterEvpnVtep, None);

        has(&r, &[VTEP_IP, VTEP_MAC], "Vtep was configured");
    }
    fn check_show_interfaces(cli: &UnixDatagram) {
        println!(" * Testing that interfaces are displayed");
        let r = send_cli(cli, CliAction::ShowRouterInterfaces, None);

        has(
            &r,
            &[IFNAME, IFINDEX.to_string().as_str()],
            "Interface was configured",
        );
        has(&r, &[IF_NEW_MAC], "Mac of interface changed");
    }
    fn check_show_interface_addresses(cli: &UnixDatagram) {
        println!(" * Testing that interface addresses are displayed");
        let r = send_cli(cli, CliAction::ShowRouterInterfaceAddresses, None);

        has(
            &r,
            &[IFNAME, IfState::Up.to_string().as_str(), IF_ADDR],
            "An ip address was configured",
        );
    }
    fn check_show_evpn_router_macs(cli: &UnixDatagram) {
        println!(" * Testing that evpn router macs are shown");
        let r = send_cli(cli, CliAction::ShowRouterEvpnRmacStore, None);

        has(&r, &[RMAC_IP], "Rmac IP should be shown");
        has(&r, &[RMAC_MAC.to_lowercase()], "Rmac MAC should be shown");
        has(&r, &[RMAC_VNI.to_string()], "Rmac VNI should be shown");
    }
    fn check_show_ipv4_routes(cli: &UnixDatagram) {
        println!(" * Testing that ipv4 routes are displayed");
        let r = send_cli(cli, CliAction::ShowRouterIpv4Routes, Some(vpc_args(VPC)));

        has(&r, &[VRFNAME, VPC], "Vrf is there");
        has(
            &r,
            &[format!("{ROUTE_PREFIX}/{ROUTE_PREFIX_LEN}")],
            "Route was added",
        );
        has(&r, &[NHOP_ADDR], "Route had next-hop");
    }
    fn check_show_ipv4_fib(cli: &UnixDatagram) {
        println!(" * Testing that ipv4 fib routes are displayed");
        let r = send_cli(
            cli,
            CliAction::ShowRouterIpv4FibEntries,
            Some(vpc_args(VPC)),
        );

        has(&r, &[VRFNAME, VPC], "Vrf is there");
        has(
            &r,
            &[format!("{ROUTE_PREFIX}/{ROUTE_PREFIX_LEN}")],
            "Route was added",
        );
        has(&r, &[NHOP_ADDR], "Route had next-hop");
    }
    fn check_show_ipv4_next_hops(cli: &UnixDatagram) {
        println!(" * Testing that ipv4 next-hops are displayed");
        let r = send_cli(cli, CliAction::ShowRouterIpv4NextHops, Some(vpc_args(VPC)));

        has(&r, &[NHOP_ADDR], "Route had next-hop");
    }
    fn check_show_ipv6_routes(cli: &UnixDatagram) {
        println!(" * Testing that ipv6 routes are displayed");
        let r = send_cli(cli, CliAction::ShowRouterIpv6Routes, Some(vpc_args(VPC)));

        has(&r, &[VRFNAME, VPC], "Vrf is there");
        has(
            &r,
            &[format!("{ROUTE_PREFIX_V6}/{ROUTE_PREFIX_V6_LEN}")],
            "Route was added",
        );
        has(&r, &[NHOP_ADDR_V6], "Route had next-hop");
    }
    fn check_show_ipv6_fib(cli: &UnixDatagram) {
        println!(" * Testing that ipv6 fib routes are displayed");
        let r = send_cli(
            cli,
            CliAction::ShowRouterIpv6FibEntries,
            Some(vpc_args(VPC)),
        );

        has(&r, &[VRFNAME, VPC], "Vrf is there");
        has(
            &r,
            &[format!("{ROUTE_PREFIX_V6}/{ROUTE_PREFIX_V6_LEN}")],
            "Route was added",
        );
        has(&r, &[NHOP_ADDR_V6], "Route had next-hop");
    }
    fn check_show_ipv6_next_hops(cli: &UnixDatagram) {
        println!(" * Testing that ipv6 next-hops are displayed");
        let r = send_cli(cli, CliAction::ShowRouterIpv6NextHops, Some(vpc_args(VPC)));

        has(&r, &[NHOP_ADDR_V6], "Route had next-hop");
    }
    fn check_show_last_frr_config(cli: &UnixDatagram) {
        println!(" * Testing that FRR config can be retrieved");
        let r = send_cli(cli, CliAction::ShowFrrmiLastConfig, None);
        has(&r, &[FRR_CONFIGURATION], "Frr config was applied");
    }
    fn check_unknown_vpc_fails(cli: &UnixDatagram) {
        println!(" * Testing that filtering by an unknown VPC fails");
        let response = cli_send_req(
            CliAction::ShowRouterIpv4Routes,
            cli,
            Some(vpc_args(UNKNOWN_VPC)),
        );
        assert!(
            matches!(response.result, Err(CliError::NotFound(_))),
            "Expected NotFound for unknown VPC, got {:?}",
            response.result
        );
    }
}
