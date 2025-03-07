// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements Display for routing objects

use crate::adjacency::{Adjacency, AdjacencyTable};
use crate::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::interface::{IfDataDot1q, IfDataEthernet, IfState, IfTable, IfType, Interface};
use crate::nexthop::{FwAction, Nhop, NhopKey, NhopStore};
use crate::pretty_utils::{Heading, line};
use crate::rmac::{RmacEntry, RmacStore, Vtep};
use crate::route_processor::{EgressObject, FibEntry, FibEntryGroup, PktInstruction};
use crate::routingdb::VrfTable;
use crate::vrf::{Route, ShimNhop, Vrf};

use iptrie::map::RTrieMap;
use iptrie::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use std::fmt::Display;
use std::sync::Arc;
use std::sync::RwLock;

//================================= Common ==========================//
fn fmt_opt_value<T: Display>(
    f: &mut std::fmt::Formatter<'_>,
    name: &str,
    value: Option<T>,
    nl: bool,
) -> Result<(), std::fmt::Error> {
    match value {
        Option::None => write!(f, "{}: --", name),
        Some(value) => write!(f, "{}: {}", name, value),
    }?;
    if nl { writeln!(f) } else { Ok(()) }
}

//=================== VRFs, routes and next-hops ====================//
impl Display for VxlanEncapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Vxlan (vni {}), remote {}",
            self.vni.as_u32(),
            self.remote
        )?;
        fmt_opt_value(f, " local", self.local, false)?;
        fmt_opt_value(f, " smac", self.smac, false)?;
        fmt_opt_value(f, " dmac", self.dmac, false)
    }
}
impl Display for Encapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")?;
        match self {
            Encapsulation::Vxlan(encap) => encap.fmt(f)?,
            //write!(f, "Vxlan (vni:{})", e.vni.as_u32())?,
            Encapsulation::Mpls(label) => write!(f, "MPLS (label:{})", label)?,
        }
        Ok(())
    }
}

//=================== VRFs, routes and next-hops ====================//

impl Display for NhopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(address) = self.address {
            write!(f, " via {address}")?;
        }
        if let Some(ifindex) = self.ifindex {
            write!(f, " interface {ifindex}")?;
        }
        if let Some(encap) = self.encap {
            write!(f, " encap {encap}")?;
        }
        if self.fwaction != FwAction::Forward {
            write!(f, " action {:?}", self.fwaction)?;
        }
        Ok(())
    }
}
impl Display for Nhop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.key)?;
        fmt_nhop_resolvers(f, self, 1)
    }
}

fn fmt_nhop_resolvers(f: &mut std::fmt::Formatter<'_>, rc: &Nhop, depth: u8) -> std::fmt::Result {
    let resolvers = rc.resolvers.read().expect("poisoned");
    let tab = 6 * depth as usize;
    let indent = String::from_utf8(vec![b' '; tab]).unwrap();
    if !resolvers.is_empty() {
        for r in resolvers.iter() {
            writeln!(f, "{} {}", indent, r.key)?;
            fmt_nhop_resolvers(f, r, depth + 1)?;
        }
    }
    Ok(())
}

// formats nhop using the display of the key, recoursing over resolvers
// Does not use Nhop::fmt().
fn fmt_nhop_rec(f: &mut std::fmt::Formatter<'_>, rc: &Arc<Nhop>, depth: u8) -> std::fmt::Result {
    let tab = 8 * depth as usize;
    let indent = String::from_utf8(vec![b' '; tab]).unwrap();

    let sym = if depth == 0 { "NH" } else { "ref" };
    writeln!(
        f,
        "{} ({}) {} = {}",
        indent,
        Arc::strong_count(rc),
        sym,
        rc.key
    )?;

    for r in rc.resolvers.read().expect("poisoned").iter() {
        fmt_nhop_rec(f, r, depth + 1)?;
    }
    Ok(())
}
impl Display for NhopStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("Next-hop Store ({})", self.len())).fmt(f)?;
        for nhop in self.iter() {
            fmt_nhop_rec(f, nhop, 0)?;
        }
        line(f)
    }
}

impl Display for ShimNhop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ext_vrf) = self.ext_vrf {
            write!(f, "(from VRF {})", ext_vrf)?;
        }
        self.rc.fmt(f) // Nhop
    }
}
impl Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?} [{}/{}]", self.origin, self.distance, self.metric)?;
        for slim in &self.s_nhops {
            writeln!(f, "       {slim}")?;
        }
        Ok(())
    }
}

fn fmt_vrf_trie<P: IpPrefix, F: Fn(&(&P, &Route)) -> bool>(
    f: &mut std::fmt::Formatter<'_>,
    show_string: &str,
    trie: &RTrieMap<P, Route>,
    _route_filter: F,
) -> std::fmt::Result {
    Heading(format!("{show_string} routes ({})", trie.len())).fmt(f)?;
    for (prefix, route) in trie.iter() {
        writeln!(f, "  {prefix:?} {route}")?;
    }
    Ok(())
}

impl Display for Vrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " Vrf: '{}' (id: {})", self.name, self.vrfid)?;
        fmt_vrf_trie(f, "Ipv4", &self.routesv4, |_| true)?;
        fmt_vrf_trie(f, "Ipv6", &self.routesv6, |_| true)?;
        self.nhstore.fmt(f)
    }
}

pub struct VrfViewV4<'a, F>
where
    F: Fn(&(&Ipv4Prefix, &Route)) -> bool,
{
    pub vrf: &'a Vrf,
    pub filter: &'a F,
}
impl<F: for<'a> Fn(&'a (&Ipv4Prefix, &Route)) -> bool> Display for VrfViewV4<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // apply the filter
        let rt_iter = self.vrf.iter_v4().filter(&self.filter);

        // total number of routes
        let total_routes = self.vrf.len_v4();

        // displayed routes
        let mut displayed = 0;

        // display !
        writeln!(
            f,
            "\n ━━━━━━━━━\n Vrf: '{}' (id: {})",
            self.vrf.name, self.vrf.vrfid
        )?;
        Heading(format!("Ipv4 routes ({})", total_routes)).fmt(f)?;
        for (prefix, route) in rt_iter {
            write!(f, "  {:?} {}", prefix, route)?;
            displayed += 1;
        }
        if displayed != total_routes {
            writeln!(
                f,
                "\n  (Displayed {} routes out of {})",
                displayed, total_routes
            )?;
        }
        Ok(())
    }
}

pub struct VrfViewV6<'a, F>
where
    F: Fn(&(&Ipv6Prefix, &Route)) -> bool,
{
    pub vrf: &'a Vrf,
    pub filter: &'a F,
}
impl<F: for<'a> Fn(&'a (&Ipv6Prefix, &Route)) -> bool> Display for VrfViewV6<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // apply the filter
        let rt_iter = self.vrf.iter_v6().filter(&self.filter);

        // total number of routes
        let total_routes = self.vrf.len_v6();

        // displayed routes
        let mut displayed = 0;

        // display !
        writeln!(
            f,
            "\n ━━━━━━━━━\n Vrf: '{}' (id: {})",
            self.vrf.name, self.vrf.vrfid
        )?;
        Heading(format!("Ipv6 routes ({})", total_routes)).fmt(f)?;
        for (prefix, route) in rt_iter {
            write!(f, "  {:?} {}", prefix, route)?;
            displayed += 1;
        }
        if displayed != total_routes {
            writeln!(
                f,
                "\n  (Displayed {} routes out of {})",
                displayed, total_routes
            )?;
        }
        Ok(())
    }
}

// ================================================= //

pub struct VrfV4Nexthops<'a>(pub &'a Vrf);
impl Display for VrfV4Nexthops<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " Vrf: '{}' (id: {})", self.0.name, self.0.vrfid)?;
        Heading("Ipv4 Next-hops".to_string()).fmt(f)?;
        let iter =
            self.0.nhstore.iter().filter(|nh| {
                nh.key.address.is_some_and(|a| a.is_ipv4()) || nh.key.address.is_none()
            });

        for nhop in iter {
            fmt_nhop_rec(f, nhop, 0)?;
        }
        line(f)
    }
}
pub struct VrfV6Nexthops<'a>(pub &'a Vrf);
impl Display for VrfV6Nexthops<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " Vrf: '{}' (id: {})", self.0.name, self.0.vrfid)?;
        Heading("Ipv6 Next-hops".to_string()).fmt(f)?;
        let iter =
            self.0.nhstore.iter().filter(|nh| {
                nh.key.address.is_some_and(|a| a.is_ipv6()) || nh.key.address.is_none()
            });

        for nhop in iter {
            fmt_nhop_rec(f, nhop, 0)?;
        }
        line(f)
    }
}

macro_rules! VRF_TBL_FMT {
    () => {
        "{:>16} {:>8} {:>8} {:>12} {:>12}"
    };
}
fn fmt_vrf_summary_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            VRF_TBL_FMT!(),
            "name", "id", "vni", "Ipv4-routes", "Ipv6-routes"
        )
    )
}
fn fmt_vrf_summary(f: &mut std::fmt::Formatter<'_>, vrf: &Arc<RwLock<Vrf>>) -> std::fmt::Result {
    if let Ok(vrf) = vrf.read() {
        writeln!(
            f,
            "{}",
            format_args!(
                VRF_TBL_FMT!(),
                vrf.name,
                vrf.vrfid,
                vrf.vni.map_or_else(|| 0, |vni| vni.as_u32()),
                vrf.routesv4.len(),
                vrf.routesv6.len()
            )
        )?;
    }
    Ok(())
}

impl Display for VrfTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("VRFs ({})", self.len())).fmt(f)?;
        fmt_vrf_summary_heading(f)?;
        for vrf in self.values() {
            fmt_vrf_summary(f, vrf)?;
        }
        Ok(())
    }
}

//========================= Interfaces ================================//

macro_rules! INTERFACE_TBL_FMT {
    () => {
        " {:<16} {:>4} {:>10} {:<10} {:20} {:>12} {}"
    };
}
fn fmt_interface_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            INTERFACE_TBL_FMT!(),
            "name", "id", "opState", "AdmState", "VRF", "addresses", "type"
        )
    )
}

impl Display for IfState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            IfState::Unknown => write!(f, "unknown")?,
            IfState::Up => write!(f, "up")?,
            IfState::Down => write!(f, "down")?,
        }
        Ok(())
    }
}
impl Display for IfDataEthernet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mac:{}", self.mac)
    }
}
impl Display for IfDataDot1q {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mac:{} vlanid:{}", self.mac, self.vlanid)
    }
}
fn fmt_iftype_name(f: &mut std::fmt::Formatter<'_>, t: &str) -> std::fmt::Result {
    write!(f, "{:width$}", t, width = 16)
}
impl Display for IfType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IfType::Unknown => fmt_iftype_name(f, "Unknown"),
            IfType::Loopback => fmt_iftype_name(f, "Loopback"),
            IfType::Ethernet(e) => {
                fmt_iftype_name(f, "Ethernet")?;
                e.fmt(f)
            }
            IfType::Dot1q(e) => {
                fmt_iftype_name(f, "802.1q")?;
                e.fmt(f)
            }
            IfType::Vxlan => fmt_iftype_name(f, "VxLAN"),
        }
    }
}
impl Display for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vrf_name = self
            .get_vrf_name()
            .map_or_else(|| "-detached-".to_owned(), |name| name);
        write!(
            f,
            "{}",
            format_args!(
                INTERFACE_TBL_FMT!(),
                self.name,
                self.ifindex.to_string(),
                self.admin_state,
                self.oper_state,
                vrf_name,
                self.addresses.len(),
                self.iftype,
            )
        )?;

        Ok(())
    }
}
impl Display for IfTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("interfaces ({})", self.len())).fmt(f)?;
        fmt_interface_heading(f)?;
        for iface in self.values() {
            writeln!(f, " {iface}")?;
        }
        Ok(())
    }
}
//========================= Interface addresses ================================//
#[repr(transparent)]
pub struct IfTableAddress<'a>(pub &'a IfTable);

macro_rules! INTERFACE_ADDR_FMT {
    () => {
        " {:<16} {:10} {:<}"
    };
}
fn fmt_interface_addr_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(INTERFACE_ADDR_FMT!(), "name", "opState", "addresses")
    )
}
fn fmt_interface_addresses(f: &mut std::fmt::Formatter<'_>, iface: &Interface) -> std::fmt::Result {
    write!(
        f,
        "{}",
        format_args!(INTERFACE_ADDR_FMT!(), iface.name, iface.oper_state, "")
    )?;
    for (addr, mask_len) in iface.addresses.iter() {
        write!(f, " {}/{}", addr, mask_len)?;
    }
    writeln!(f)
}
impl Display for IfTableAddress<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("interface addresses".to_string()).fmt(f)?;
        fmt_interface_addr_heading(f)?;
        for iface in self.0.values() {
            fmt_interface_addresses(f, iface)?;
        }
        Ok(())
    }
}

//========================= Rmac Store ================================//
macro_rules! RMAC_TBL_FMT {
    () => {
        " {:<5} {:<20} {:<18}"
    };
}
fn fmt_rmac_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(RMAC_TBL_FMT!(), "vni", "address", "mac")
    )
}

impl Display for RmacEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_args!(RMAC_TBL_FMT!(), self.vni.as_u32(), self.address, self.mac)
        )
    }
}
impl Display for RmacStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("Rmac store ({})", self.len())).fmt(f)?;
        fmt_rmac_heading(f)?;
        for rmac in self.values() {
            writeln!(f, " {rmac}")?;
        }
        Ok(())
    }
}

//========================= Rmac Store ================================//
impl Display for Vtep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n ───────── Local VTEP ─────────")?;
        fmt_opt_value(f, "ip address", self.get_ip(), true)?;
        fmt_opt_value(f, "Mac address", self.get_mac(), true)
    }
}

//========================= Adjacencies ================================//
macro_rules! ADJ_TBL_FMT {
    () => {
        " {:<10} {:<20} {:<18}"
    };
}
fn fmt_adjacency_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(ADJ_TBL_FMT!(), "ifindex", "address", "mac")
    )
}

impl Display for Adjacency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_args!(
                ADJ_TBL_FMT!(),
                self.get_ifindex(),
                self.get_ip(),
                self.get_mac()
            )
        )
    }
}
impl Display for AdjacencyTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("Adjacency table ({})", self.len())).fmt(f)?;
        fmt_adjacency_heading(f)?;
        for a in self.values() {
            writeln!(f, "{}", a)?
        }
        Ok(())
    }
}

//========================= Fib ================================//

impl Display for EgressObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "if: {}", self.ifindex)?;
        fmt_opt_value(f, " addr", self.address, false)?;
        fmt_opt_value(f, " smac", self.smac, false)?;
        fmt_opt_value(f, " dmac", self.dmac, false)
    }
}

impl Display for PktInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            PktInstruction::Drop => write!(f, "drop"),
            PktInstruction::Xmit(egress) => write!(f, "xmit: {}", egress),
            PktInstruction::Encap(encap) => write!(f, "encap: {}", encap),
            PktInstruction::Nat => write!(f, "NAT"),
        }
    }
}
impl Display for FibEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        for (n, inst) in self.iter().enumerate() {
            writeln!(f, "     {} {}", n, inst)?;
        }
        Ok(())
    }
}
impl Display for FibEntryGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "FibGroup:")?;
        for (n, entry) in self.iter().enumerate() {
            writeln!(f, "  Fibentry {}:", n)?;
            writeln!(f, "{}", entry)?;
        }
        Ok(())
    }
}
