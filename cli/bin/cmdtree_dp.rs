// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Builds our command tree for dataplane

use crate::cmdtree::{Node, NodeArg};
use dataplane_cli::cliproto::{CliAction, RouteProtocol};
use log::Level;
use std::convert::AsRef;
use strum::IntoEnumIterator;

fn vrf_prefetcher() -> Vec<String> {
    // todo
    vec![]
}

fn cmd_show_router_cpi() -> Node {
    let mut root = Node::new("cpi");
    root += Node::new("stats")
        .desc("Show control-plane interface")
        .action(CliAction::ShowCpiStats as u16);
    root
}
fn cmd_show_router_frrmi() -> Node {
    let mut root = Node::new("frrmi");
    root += Node::new("stats")
        .desc("Show frr management interface")
        .action(CliAction::ShowFrrmiStats as u16);
    root += Node::new("last-config")
        .desc("Show last frr config applied over the frrmi")
        .action(CliAction::ShowFrrmiLastConfig as u16);

    root
}
fn cmd_show_router_eventlog() -> Node {
    Node::new("events")
        .desc("Show relevant router events")
        .action(CliAction::RouterEventLog as u16)
}
fn cmd_show_router() -> Node {
    let mut root = Node::new("router");
    root += cmd_show_router_frrmi();
    root += cmd_show_router_cpi();
    root += cmd_show_router_eventlog();
    root
}

fn cmd_show_gateway() -> Node {
    let mut root = Node::new("gateway");

    root += Node::new("groups")
        .desc("Show gateway group settings")
        .action(CliAction::ShowGatewayGroups as u16);

    root += Node::new("communities")
        .desc("Show BGP communities used by gateways")
        .action(CliAction::ShowGatewayCommunities as u16);

    root
}
fn cmd_show_pipelines() -> Node {
    let mut root = Node::new("pipeline")
        .desc("Show packet-processing pipelines")
        .action(CliAction::ShowPipeline as u16);

    root += Node::new("stages")
        .desc("Show packet-processing stages")
        .action(CliAction::ShowPipelineStages as u16);

    root += Node::new("stats")
        .desc("Show packet-processing pipeline statistics")
        .action(CliAction::ShowPipelineStats as u16);

    root
}
fn cmd_show_vpc() -> Node {
    let mut root = Node::new("vpc");
    root += Node::new("summary")
        .desc("Show a summary of VPCs")
        .action(CliAction::ShowVpc as u16);

    root += Node::new("peerings")
        .desc("Show the peerings of each vpc")
        .action(CliAction::ShowVpcPeerings as u16);
    root
}
fn cmd_show_ip() -> Node {
    let mut root = Node::new("ip");
    let mut routes = Node::new("route")
        .desc("Display IPv4 routes")
        .action(CliAction::ShowRouterIpv4Routes as u16)
        .arg("prefix");

    let arg = NodeArg::new("vrfid").prefetcher(vrf_prefetcher);
    routes = routes.arg_add(arg);
    let mut arg = NodeArg::new("protocol");
    RouteProtocol::iter().for_each(|proto| arg.add_choice(proto.as_ref()));
    routes = routes.arg_add(arg);

    routes += Node::new("summary").action(CliAction::ShowRouterIpv4Routes as u16);

    root += routes;

    root += Node::new("next-hop")
        .desc("Display IPv4 next-hops")
        .action(CliAction::ShowRouterIpv4NextHops as u16)
        .arg("address");

    let mut fib = Node::new("fib")
        .desc("Display IPv4 forwarding entries")
        .action(CliAction::ShowRouterIpv4FibEntries as u16)
        .arg("prefix")
        .arg("vrfid");

    fib += Node::new("group")
        .desc("Display IPv4 FIB groups")
        .action(CliAction::ShowRouterIpv4FibGroups as u16);

    root += fib;

    root
}
fn cmd_show_ipv6() -> Node {
    let mut root = Node::new("ipv6");
    let mut routes = Node::new("route")
        .desc("Display IPv6 routes")
        .action(CliAction::ShowRouterIpv6Routes as u16)
        .arg("prefix")
        .arg("vrfid");

    let mut arg = NodeArg::new("protocol");
    RouteProtocol::iter().for_each(|proto| arg.add_choice(proto.as_ref()));
    routes = routes.arg_add(arg);
    root += routes;

    root += Node::new("next-hop")
        .desc("Display IPv6 next-hops")
        .action(CliAction::ShowRouterIpv6NextHops as u16)
        .arg("address");

    let mut fib = Node::new("fib")
        .desc("Display IPv6 forwarding entries")
        .action(CliAction::ShowRouterIpv6FibEntries as u16)
        .arg("prefix")
        .arg("vrfid");

    fib += Node::new("group")
        .desc("Display IPv6 FIB groups")
        .action(CliAction::ShowRouterIpv6FibGroups as u16);

    root += fib;

    root
}
fn cmd_show_vrf() -> Node {
    Node::new("vrf")
        .desc("Show a summary of the VRFs")
        .action(CliAction::ShowRouterVrfs as u16)
        .arg("vni")
}
fn cmd_show_evpn() -> Node {
    let mut root = Node::new("evpn");

    root += Node::new("vrfs")
        .desc("Show EVPN VRFs")
        .action(CliAction::ShowRouterEvpnVrfs as u16);

    root += Node::new("rmac-store")
        .desc("Show the contents of the router mac store")
        .action(CliAction::ShowRouterEvpnRmacStore as u16);

    root += Node::new("vtep")
        .desc("Show EVPN VTEP configuration")
        .action(CliAction::ShowRouterEvpnVtep as u16);

    root
}
fn cmd_show_adjacency_table() -> Node {
    Node::new("adjacency-table")
        .desc("Show neighboring information")
        .action(CliAction::ShowAdjacencies as u16)
}
fn cmd_show_interface() -> Node {
    let mut root = Node::new("interface")
        .desc("show network interfaces")
        .action(CliAction::ShowRouterInterfaces as u16)
        .arg("ifname");

    let arg = NodeArg::new("iftype")
        .choice("ethernet")
        .choice("vlan")
        .choice("vxlan");
    root = root.arg_add(arg);

    root += Node::new("address")
        .desc("Display interface IP addresses")
        .action(CliAction::ShowRouterInterfaceAddresses as u16)
        .arg("address");

    root
}
fn cmd_show_routing() -> Node {
    let mut root = Node::new("");
    root += cmd_show_adjacency_table();
    root += cmd_show_interface();
    root += cmd_show_evpn();
    root += cmd_show_vrf();
    root += cmd_show_ip();
    root += cmd_show_ipv6();

    root
}
fn cmd_show_dpdk() -> Node {
    let mut root = Node::new("dpdk");
    let mut ports = Node::new("port").desc("DPDK port information");
    ports += Node::new("stats").desc("DPDK port stats");
    root += ports;
    root
}
fn cmd_show_kernel() -> Node {
    let mut root = Node::new("kernel");
    root += Node::new("interfaces").desc("Kernel interface status");
    root
}
fn cmd_show_tracing() -> Node {
    let mut root = Node::new("tracing");
    root += Node::new("targets")
        .desc("Show tracing target configuration")
        .action(CliAction::ShowTracingTargets as u16);
    root += Node::new("tag-groups")
        .desc("Show tracing targets organized by tag groups")
        .action(CliAction::ShowTracingTagGroups as u16);
    root
}
fn cmd_show_flow_table() -> Node {
    let mut root = Node::new("flow-table");
    root += Node::new("entries")
        .desc("Show entries in the flow table")
        .action(CliAction::ShowFlowTable as u16);

    root
}
fn cmd_show_flow_filter() -> Node {
    let mut root = Node::new("flow-filter");
    root += Node::new("table")
        .desc("Show the flow-filter table")
        .action(CliAction::ShowFlowFilter as u16);

    root
}
fn cmd_show_port_forwarding_rules() -> Node {
    let mut root = Node::new("port-forwarding");
    root += Node::new("rules")
        .desc("Show configured port-forwarding rules")
        .action(CliAction::ShowPortForwarding as u16);
    root
}
fn cmd_show_masquerading() -> Node {
    let mut root = Node::new("masquerading");
    root += Node::new("state")
        .desc("Show the state of IP and port allocation for masquerading")
        .action(CliAction::ShowMasquerading as u16);
    root
}
fn cmd_show_static_nat() -> Node {
    let mut root = Node::new("static-nat");
    root += Node::new("rules")
        .desc("Show configured static NAT rules")
        .action(CliAction::ShowStaticNat as u16);
    root
}
fn cmd_show_nat() -> Node {
    let mut root = Node::new("");
    root += cmd_show_static_nat();
    root += cmd_show_port_forwarding_rules();
    root += cmd_show_masquerading();
    root
}
fn cmd_show_config_summary() -> Node {
    let mut root = Node::new("config");
    root += Node::new("summary")
        .desc("Show a summary of configuration changes")
        .action(CliAction::ShowConfigSummary as u16);
    root
}

fn cmd_show() -> Node {
    let mut root: Node = Node::new("show");
    root += cmd_show_router();
    root += cmd_show_vpc();
    root += cmd_show_pipelines();
    root += cmd_show_nat();
    root += cmd_show_routing();
    root += cmd_show_dpdk();
    root += cmd_show_kernel();
    root += cmd_show_tracing();
    root += cmd_show_flow_table();
    root += cmd_show_flow_filter();
    root += cmd_show_gateway();
    root += cmd_show_config_summary();
    root
}
fn cmd_loglevel() -> Node {
    let mut root = Node::new("log")
        .desc("Set logging level")
        .action(CliAction::SetLoglevel as u16);
    let arg = NodeArg::new("level")
        .choice(Level::Trace.as_str().to_lowercase().as_str())
        .choice(Level::Debug.as_str().to_lowercase().as_str())
        .choice(Level::Info.as_str().to_lowercase().as_str())
        .choice(Level::Warn.as_str().to_lowercase().as_str())
        .choice(Level::Error.as_str().to_lowercase().as_str());
    root = root.arg_add(arg);
    root
}
fn cmd_set() -> Node {
    let mut root = Node::new("set");
    root += cmd_loglevel();

    root
}
fn cmd_mgmt() -> Node {
    let mut root = Node::new("");
    root += cmd_set();
    root
}
fn cmd_local() -> Node {
    let mut root = Node::new("");
    root += Node::new("clear")
        .desc("Clears the screen")
        .action(CliAction::Clear as u16);
    root += Node::new("help")
        .desc("Shows this help")
        .action(CliAction::Help as u16);
    root += Node::new("connect")
        .desc("Connect to dataplane")
        .action(CliAction::Connect as u16)
        .arg("path")
        .arg("bind-address");
    root += Node::new("disconnect")
        .desc("Disconnect from dataplane")
        .action(CliAction::Disconnect as u16);
    root += Node::new("exit")
        .desc("Exits this program")
        .action(CliAction::Quit as u16);
    root += Node::new("quit")
        .desc("Exits this program")
        .action(CliAction::Quit as u16);

    root += Node::new("q").action(CliAction::Quit as u16).hidden();
    root += Node::new("?").action(CliAction::Help as u16).hidden();
    root
}

fn cmd_frrmi_apply_last() -> Node {
    let mut root = Node::new("apply");
    root += Node::new("last-config")
        .desc("Apply the last config in FRR")
        .action(CliAction::FrrmiApplyLastConfig as u16);
    root
}
fn cmd_frrmi() -> Node {
    let mut root = Node::new("frrmi");
    root += cmd_frrmi_apply_last();
    root
}

fn cmd_cpi_request_refresh() -> Node {
    let mut root = Node::new("request");
    root += Node::new("refresh")
        .desc("Request routing state")
        .action(CliAction::CpiRequestRefresh as u16);
    root
}
fn cmd_cpi() -> Node {
    let mut root = Node::new("cpi");
    root += cmd_cpi_request_refresh();
    root
}

pub fn gw_cmd_tree() -> Node {
    let mut root = Node::new("");
    root += cmd_local();
    root += cmd_mgmt();
    root += cmd_show();
    root += cmd_frrmi();
    root += cmd_cpi();

    root
}
