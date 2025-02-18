// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Builds our command tree for dataplane

use crate::cliproto::CliAction;
use crate::cmdtree::{Node, NodeArg};
use log::Level;

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

    root += Node::new("route")
        .desc("Display IPv4 routes")
        .action(CliAction::ShowRouterIpv4Routes as u16)
        .arg("prefix")
        .arg("vrf");

    root += Node::new("address")
        .desc("Display IPv4 addresses")
        .action(CliAction::ShowRouterIpv4Addresses as u16)
        .arg("address");
    root
}
fn cmd_show_ipv6() -> Node {
    let mut root = Node::new("ipv6");

    root += Node::new("route")
        .desc("Display IPv6 routes")
        .action(CliAction::ShowRouterIpv6Routes as u16)
        .arg("prefix")
        .arg("vrf");

    root += Node::new("address")
        .desc("Display IPv6 addresses")
        .action(CliAction::ShowRouterIpv6Addresses as u16)
        .arg("address");
    root
}
fn cmd_show_vrf() -> Node {
    Node::new("vrf")
        .desc("Show a summary of the VRFs")
        .action(CliAction::ShowRouterVrfs as u16)
}
fn cmd_show_evpn() -> Node {
    let mut root = Node::new("evpn");

    root += Node::new("vrfs")
        .desc("Show EVPN VRFs")
        .action(CliAction::ShowRouterEvpnVrfs as u16);

    root += Node::new("rmac-store")
        .desc("Show the contents of the router mac store")
        .action(CliAction::ShowRouterEvpnRmacStore as u16);

    root
}
fn cmd_show_interface() -> Node {
    let root = Node::new("interface")
        .desc("show network interfaces")
        .action(CliAction::ShowRouterInterfaces as u16)
        .arg("ifname");

    let arg = NodeArg::new("iftype")
        .choice("ethernet")
        .choice("vlan")
        .choice("vxlan");
    root.arg_add(arg)
}
fn cmd_show_routing() -> Node {
    let mut root = Node::new("routing");
    root += Node::new("cpi").desc("show the status of the routing interface");
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
    root += Node::new("restart")
        .desc("Restart the dataplane")
        .action(CliAction::Restart as u16);
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
        .arg("path");
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
