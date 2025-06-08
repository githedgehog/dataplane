// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Builds our command tree for dataplane

use crate::cmdtree::{Node, NodeArg};
use dataplane_cli::cliproto::{CliAction, RouteProtocol};
use log::Level;
use std::convert::AsRef;
use strum::IntoEnumIterator;

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
fn cmd_show_peering() -> Node {
    let mut root = Node::new("peering");

    root += Node::new("interfaces")
        .desc("show details about the peering interfaces")
        .action(CliAction::ShowVpcPifs as u16);

    root += Node::new("policies")
        .desc("show the peering policies")
        .action(CliAction::ShowVpcPolicies as u16);
    root
}
fn cmd_show_vpc() -> Node {
    let mut root = Node::new("vpc")
        .desc("Show VPCs")
        .action(CliAction::ShowVpc as u16);
    root += cmd_show_peering();
    root
}
fn cmd_show_ip() -> Node {
    let mut root = Node::new("ip");
    let mut routes = Node::new("route")
        .desc("Display IPv4 routes")
        .action(CliAction::ShowRouterIpv4Routes as u16)
        .arg("prefix")
        .arg("vrfid");

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
    root += Node::new("cpi").desc("show the status of the routing interface");
    root += cmd_show_adjacency_table();
    root += cmd_show_interface();
    root += cmd_show_evpn();
    root += cmd_show_vrf();
    root += cmd_show_ip();
    root += cmd_show_ipv6();

    root
}
fn cmd_show_nat() -> Node {
    let mut root = Node::new("nat").desc("Show NAT (network address translation)");
    root += Node::new("rules").desc("Dump the current NAT mappings");
    root += Node::new("port-usage").desc("Usage of transport ports");
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
fn cmd_show() -> Node {
    let mut root: Node = Node::new("show");
    root += cmd_show_vpc();
    root += cmd_show_pipelines();
    root += cmd_show_nat();
    root += cmd_show_routing();
    root += cmd_show_dpdk();
    root += cmd_show_kernel();
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

#[allow(unused)]
pub fn gw_cmd_tree() -> Node {
    let mut root = Node::new("");
    root += cmd_local();
    root += cmd_mgmt();
    root += cmd_show();
    root
}
