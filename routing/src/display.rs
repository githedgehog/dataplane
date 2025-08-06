// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements Display for routing objects

use crate::atable::adjacency::{Adjacency, AdjacencyTable};
use crate::cpi::{CpiStats, CpiStatus, StatsRow};
use crate::fib::fibgroupstore::FibRoute;
use crate::fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};
use crate::fib::fibtable::FibTable;
use crate::fib::fibtype::{Fib, FibId};
use crate::frr::frrmi::{FrrAppliedConfig, Frrmi, FrrmiStats};

use crate::rib::VrfTable;
use crate::rib::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::rib::nexthop::{FwAction, Nhop, NhopKey, NhopStore};
use crate::rib::vrf::{Route, RouteOrigin, ShimNhop, Vrf, VrfStatus};

use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::Attachment;
use crate::interfaces::interface::{IfDataDot1q, IfDataEthernet};
use crate::interfaces::interface::{IfState, IfType, Interface};

use crate::evpn::{RmacEntry, RmacStore, Vtep};
use crate::pretty_utils::{Heading, line};

use chrono::DateTime;
use lpm::prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix};
use lpm::trie::{PrefixMapTrie, TrieMap};
use net::vxlan::Vni;
use std::fmt::Display;
use std::os::unix::net::SocketAddr;
use std::rc::Rc;

use tracing::{error, warn};

//================================= Common ==========================//
fn fmt_opt_value<T: Display>(
    f: &mut std::fmt::Formatter<'_>,
    name: &str,
    value: &Option<T>,
    nl: bool,
) -> Result<(), std::fmt::Error> {
    match value {
        Option::None => write!(f, "{name}: --"),
        Some(value) => write!(f, "{name}: {value}"),
    }?;
    if nl { writeln!(f) } else { Ok(()) }
}

//========================= Encapsulations ==========================//
impl Display for VxlanEncapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Vxlan (vni {}), remote {}",
            self.vni.as_u32(),
            self.remote
        )?;
        fmt_opt_value(f, " dmac", &self.dmac, false)
    }
}
impl Display for Encapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")?;
        match self {
            Encapsulation::Vxlan(encap) => encap.fmt(f)?,
            Encapsulation::Mpls(label) => write!(f, "MPLS (label:{label})")?,
        }
        Ok(())
    }
}

//=================== VRFs, routes and next-hops ====================//
impl Display for RouteOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteOrigin::Local => write!(f, "local"),
            RouteOrigin::Connected => write!(f, "connected"),
            RouteOrigin::Static => write!(f, "static"),
            RouteOrigin::Ospf => write!(f, "ospf"),
            RouteOrigin::Isis => write!(f, "is-is"),
            RouteOrigin::Bgp => write!(f, "bgp"),
            RouteOrigin::Other => write!(f, "other"),
        }
    }
}
impl Display for NhopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(address) = self.address {
            write!(f, " via {address}")?;
        }
        if let Some(ifname) = &self.ifname {
            write!(f, " interface {ifname}")?;
        }
        if let Some(ifindex) = self.ifindex {
            write!(f, " (idx {ifindex})")?;
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
        write!(f, "{}", self.key)?;
        fmt_nhop_resolvers(f, self, 2)
    }
}

fn fmt_nhop_resolvers(f: &mut std::fmt::Formatter<'_>, rc: &Nhop, depth: u8) -> std::fmt::Result {
    let Ok(resolvers) = rc.resolvers.try_borrow() else {
        warn!("Try-borrow on nhop resolvers failed!");
        return Ok(());
    };
    let tab = 5 * depth as usize;
    let indent = " ".repeat(tab);
    if !resolvers.is_empty() {
        for r in resolvers.iter() {
            write!(f, "\n{indent} {}", r.key)?;
            fmt_nhop_resolvers(f, r, depth + 1)?;
        }
    }
    Ok(())
}

fn fmt_nhop_instruction(f: &mut std::fmt::Formatter<'_>, rc: &Nhop) -> std::fmt::Result {
    let Ok(instructions) = &rc.instructions.try_borrow() else {
        warn!("Try-borrow failed on nhop instruction!");
        return Ok(());
    };
    if instructions.is_empty() {
        return Ok(());
    }
    writeln!(f, "  Fib Instructions:")?;
    for (i, inst) in instructions.iter().enumerate() {
        writeln!(f, "   [{i}] {inst}")?;
    }
    Ok(())
}

// formats nhop using the display of the key, recoursing over resolvers
// Does not use Nhop::fmt().
fn fmt_nhop_rec(f: &mut std::fmt::Formatter<'_>, rc: &Rc<Nhop>, depth: u8) -> std::fmt::Result {
    let tab = 8 * depth as usize;
    let indent = " ".repeat(tab);

    let sym = if depth == 0 { "NH" } else { "ref" };
    writeln!(
        f,
        "{} ({}) {} = {}",
        indent,
        Rc::strong_count(rc),
        sym,
        rc.key
    )?;
    //    fmt_nhop_instruction(f, rc)?;

    let Ok(resolvers) = rc.resolvers.try_borrow() else {
        error!("Try-borrow on next-hop resolvers failed!");
        return Ok(());
    };
    for r in resolvers.iter() {
        fmt_nhop_rec(f, r, depth + 1)?;
    }
    //    if let Ok(fg) = rc.as_ref().fibgroup.read() {
    //        writeln!(f, "FibG {}", fg)?;
    //    }

    Ok(())
}
impl Display for NhopStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("Next-hop Store ({})", self.len())).fmt(f)?;
        for nhop in self.iter() {
            fmt_nhop_rec(f, nhop, 0)?;
            fmt_nhop_instruction(f, nhop)?;
        }
        line(f)
    }
}

impl Display for ShimNhop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ext_vrf) = self.ext_vrf {
            write!(f, "(from VRF {ext_vrf})")?;
        }
        self.rc.fmt(f) // Nhop
    }
}
impl Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} [{}/{}]", self.origin, self.distance, self.metric)?;
        for shim in &self.s_nhops {
            writeln!(f, "       {shim}")?;
        }
        Ok(())
    }
}

fn fmt_vrf_trie<P: IpPrefix, F: Fn(&(&P, &Route)) -> bool>(
    f: &mut std::fmt::Formatter<'_>,
    show_string: &str,
    trie: &PrefixMapTrie<P, Route>,
    _route_filter: F,
) -> std::fmt::Result {
    Heading(format!("{show_string} routes ({})", trie.len())).fmt(f)?;
    for (prefix, route) in trie.iter() {
        writeln!(f, "  {prefix:?} {route}")?;
    }
    Ok(())
}

impl Display for VrfStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VrfStatus::Active => write!(f, "active"),
            VrfStatus::Deleting => write!(f, "deleting"),
            VrfStatus::Deleted => write!(f, "deleted"),
        }
    }
}

fn fmt_vrf_oneline(vrf: &Vrf, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let description = vrf.description.clone().unwrap_or_else(|| "--".to_string());
    writeln!(
        f,
        "\n ━━━━━━━━━\n Vrf: '{}' (id: {}) description: {description}",
        vrf.name, vrf.vrfid
    )?;
    Ok(())
}

impl Display for Vrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            " Vrf: '{}' id: {} status: {}",
            self.name, self.vrfid, self.status
        )?;
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

        fmt_vrf_oneline(&self.vrf, f)?;
        Heading(format!("Ipv4 routes ({total_routes})")).fmt(f)?;
        for (prefix, route) in rt_iter {
            write!(f, "  {prefix:?} {route}")?;
            displayed += 1;
        }
        if displayed != total_routes {
            writeln!(
                f,
                "\n  (Displayed {displayed} routes out of {total_routes})"
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

        fmt_vrf_oneline(&self.vrf, f)?;
        Heading(format!("Ipv6 routes ({total_routes})")).fmt(f)?;
        for (prefix, route) in rt_iter {
            write!(f, "  {prefix:?} {route}")?;
            displayed += 1;
        }
        if displayed != total_routes {
            writeln!(
                f,
                "\n  (Displayed {displayed} routes out of {total_routes})"
            )?;
        }
        Ok(())
    }
}

// ================================================= //

pub struct VrfV4Nexthops<'a>(pub &'a Vrf);
impl Display for VrfV4Nexthops<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_vrf_oneline(&self.0, f)?;
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
        fmt_vrf_oneline(&self.0, f)?;
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
        "{:>16} {:>8} {:>8} {:>12} {:>12} {:>8} {:>8} {:<}"
    };
}
fn fmt_vrf_summary_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            VRF_TBL_FMT!(),
            "name", "id", "vni", "Ipv4-routes", "Ipv6-routes", "status", "table-id", "description"
        )
    )
}
fn fmt_vrf_summary(f: &mut std::fmt::Formatter<'_>, vrf: &Vrf) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            VRF_TBL_FMT!(),
            vrf.name,
            vrf.vrfid,
            vrf.vni.map_or_else(|| 0, Vni::as_u32),
            vrf.routesv4.len(),
            vrf.routesv6.len(),
            vrf.status.to_string(),
            vrf.tableid
                .map_or_else(|| "--".to_owned(), |t| t.to_string()),
            &vrf.description.as_ref().map_or_else(|| "", |t| t.as_str())
        )
    )
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

impl Display for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attachment::BD => write!(f, "BD")?,
            Attachment::VRF(fibr) => {
                if let Some(id) = fibr.get_id() {
                    write!(f, "VRF: {id}")?;
                } else {
                    write!(f, "missing fib id!")?;
                }
            }
        }
        Ok(())
    }
}

macro_rules! INTERFACE_TBL_FMT {
    () => {
        " {:<16} {:>4} {:>6} {:9} {:9} {:<20} {}"
    };
}
fn fmt_interface_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            INTERFACE_TBL_FMT!(),
            "name", "id", "mtu", "AdmStatus", "OpStatus", "attachment", "type"
        )
    )
}

impl Display for IfState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            IfState::Unknown => write!(f, "{:9}", "unknown")?,
            IfState::Up => write!(f, "{:9}", "up")?,
            IfState::Down => write!(f, "{:9}", "down")?,
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
        let attachment = if let Some(attachment) = &self.attachment {
            format!("{attachment}")
        } else {
            "---".to_string()
        };
        let mtu = self
            .mtu
            .map(|m| m.to_string())
            .unwrap_or_else(|| "--".to_string());
        write!(
            f,
            "{}",
            format_args!(
                INTERFACE_TBL_FMT!(),
                self.name,
                format!("{:>4}", self.ifindex),
                mtu,
                self.admin_state,
                self.oper_state,
                attachment,
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
            writeln!(f, "{iface}")?;
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
    for (addr, mask_len) in &iface.addresses {
        write!(f, " {addr}/{mask_len}")?;
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
            writeln!(f, "{rmac}")?;
        }
        Ok(())
    }
}

//========================= Rmac Store ================================//
impl Display for Vtep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n ───────── Local VTEP configuration ─────────")?;
        fmt_opt_value(f, " ip address", &self.get_ip(), true)?;
        fmt_opt_value(f, " Mac address", &self.get_mac(), true)
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
            writeln!(f, "{a}")?;
        }
        Ok(())
    }
}

//========================= Fib ================================//
impl Display for FibId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            FibId::Id(vrfid) => write!(f, "vrfid: {vrfid}")?,
            FibId::Vni(vni) => write!(f, "vni: {vni:?}")?,
            FibId::Unset => write!(f, "Unset!")?,
        }
        Ok(())
    }
}
impl Display for EgressObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt_opt_value(f, " interface", &self.ifname, false)?;
        fmt_opt_value(f, " idx", &self.ifindex, false)?;
        fmt_opt_value(f, " addr", &self.address, false)
    }
}
impl Display for PktInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            PktInstruction::Drop => write!(f, "drop"),
            PktInstruction::Local(ifindex) => write!(f, "Local (if {ifindex})"),
            PktInstruction::Egress(egress) => write!(f, "egress: {egress}"),
            PktInstruction::Encap(encap) => write!(f, "encap: {encap}"),
        }
    }
}
impl Display for FibEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "        - entry:")?;
        for (n, inst) in self.iter().enumerate() {
            writeln!(f, "            {n} {inst}")?;
        }
        Ok(())
    }
}
impl Display for FibGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "     ■ group ({} entries):", self.len())?;
        for entry in self.iter() {
            write!(f, "{entry}")?;
        }
        writeln!(f)
    }
}
impl Display for FibRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "via {} groups, {} entries:",
            self.num_groups(),
            self.len()
        )?;
        for group in self.iter() {
            group.fmt(f)?;
        }
        Ok(())
    }
}

fn fmt_fib_trie<P: IpPrefix, F: Fn(&(&P, &FibRoute)) -> bool>(
    f: &mut std::fmt::Formatter<'_>,
    fibid: FibId,
    show_string: &str,
    trie: &PrefixMapTrie<P, FibRoute>,
    group_filter: F,
) -> std::fmt::Result {
    Heading(format!(
        "{show_string} Fib ({fibid}) -- {} prefixes",
        trie.len()
    ))
    .fmt(f)?;
    for (prefix, route) in trie.iter().filter(group_filter) {
        write!(f, "  {prefix:?}: {route}")?;
    }
    Ok(())
}

impl Display for Fib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt_fib_trie(f, self.get_id(), "Ipv4", self.get_v4_trie(), |_| true)?;
        fmt_fib_trie(f, self.get_id(), "Ipv6", self.get_v6_trie(), |_| true)?;
        Ok(())
    }
}
impl Display for FibTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        Heading(format!(" Fib Table ({} fibs)", self.len())).fmt(f)?;
        for (_fibid, fibr) in self.iter() {
            if let Some(fib) = fibr.enter() {
                write!(f, "{}", *fib)?;
            }
        }
        Ok(())
    }
}

pub struct FibViewV4<'a, F>
where
    F: Fn(&(&Ipv4Prefix, &FibRoute)) -> bool,
{
    pub vrf: &'a Vrf,
    pub filter: &'a F,
}
impl<F: for<'a> Fn(&'a (&Ipv4Prefix, &FibRoute)) -> bool> Display for FibViewV4<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(fibw) = &self.vrf.fibw else {
            return writeln!(f, "No fib");
        };
        let Some(fibr) = fibw.enter() else {
            return writeln!(f, "Unable to read fib!");
        };

        let rt_iter = fibr.iter_v4().filter(&self.filter);
        let total_entries = fibr.len_v4();
        let mut displayed = 0;

        fmt_vrf_oneline(&self.vrf, f)?;
        Heading(format!("Ipv4 FIB ({total_entries} destinations)")).fmt(f)?;
        for (prefix, route) in rt_iter {
            write!(f, "  {prefix:?} {route}")?;
            displayed += 1;
        }
        if displayed != total_entries {
            writeln!(
                f,
                "\n  (Displayed {displayed} destinations out of {total_entries})",
            )?;
        }

        Ok(())
    }
}

pub struct FibViewV6<'a, F>
where
    F: Fn(&(&Ipv6Prefix, &FibRoute)) -> bool,
{
    pub vrf: &'a Vrf,
    pub filter: &'a F,
}
impl<F: for<'a> Fn(&'a (&Ipv6Prefix, &FibRoute)) -> bool> Display for FibViewV6<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(fibw) = &self.vrf.fibw else {
            return writeln!(f, "No fib");
        };
        let Some(fibr) = fibw.enter() else {
            return writeln!(f, "Unable to read fib!");
        };

        let rt_iter = fibr.iter_v6().filter(&self.filter);
        let total_entries = fibr.len_v6();
        let mut displayed = 0;

        fmt_vrf_oneline(&self.vrf, f)?;
        Heading(format!("Ipv6 FIB ({total_entries} destinations)")).fmt(f)?;
        for (prefix, route) in rt_iter {
            write!(f, "  {prefix:?} {route}")?;
            displayed += 1;
        }

        if displayed != total_entries {
            writeln!(
                f,
                "\n  (Displayed {displayed} destinations out of {total_entries})",
            )?;
        }

        Ok(())
    }
}

// We show the same fib groups for Ipv4 and Ipv6 for the time being, since filtering
// them according to ip version is not yet possible.
pub struct FibGroups<'a>(pub &'a Vrf);

impl<'a> Display for FibGroups<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(ref fibw) = self.0.fibw else {
            writeln!(f, "No fib")?;
            return Ok(());
        };
        let Some(ref fibr) = fibw.enter() else {
            writeln!(f, "No fib")?;
            return Ok(());
        };
        let num_groups = fibr.len_groups();
        let vrf_name = &self.0.name;
        let vrfid = self.0.vrfid;
        let fibid = fibr.get_id();
        Heading(format!("FIB groups")).fmt(f)?;
        writeln!(f, " vrf: {vrf_name}, Id: {vrfid}")?;
        writeln!(f, " fib: {fibid}")?;
        writeln!(f, " groups: {num_groups}\n")?;

        for group in fibr.group_iter() {
            write!(f, " {group}")?;
        }
        Ok(())
    }
}

//========================= Time utils =========================//
use chrono::Local;
pub(crate) fn fmt_time(time: &DateTime<Local>) -> String {
    //let fmt_iso8 = "%Y-%m-%dT%H:%M:%S%.3f%:z";
    let fmt_simple = "%Y-%m-%dT %H:%M:%S";
    let mut out = time.format(fmt_simple).to_string();
    out += " (";

    let now = Local::now();
    let elapsed = (now - time).num_seconds();
    let weeks = elapsed / (7 * 24 * 60 * 60);
    let days = (elapsed % (7 * 24 * 60 * 60)) / (24 * 60 * 60);
    let hours = (elapsed % (24 * 60 * 60)) / (60 * 60);
    let minutes = (elapsed % (60 * 60)) / 60;
    let seconds = elapsed % 60;

    if weeks > 0 {
        out += &format!("{} weeks ", weeks);
    }
    if days > 0 {
        out += &format!("{} days ", days);
    }
    if hours > 0 {
        out += &format!("{} hours ", hours);
    }
    if minutes > 0 {
        out += &format!("{} min ", minutes);
    }
    out += &format!("{} s ago)", seconds);
    out
}

//========================= CPI ================================//
macro_rules! STATS_ROW_FMT {
    () => {
        " {:<16} {:<12} {:<12} {:<12} {:<12} {:<12}"
    };
}
fn fmt_cpi_stats_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            STATS_ROW_FMT!(),
            "op", "Ok", "Ignored", "Failure", "Invalid", "Unsupp"
        )
    )
}
fn fmt_stats_row(f: &mut std::fmt::Formatter<'_>, name: &str, row: &StatsRow) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            STATS_ROW_FMT!(),
            name, row.0[0], row.0[1], row.0[2], row.0[3], row.0[4],
        )
    )
}

fn fmt_socketaddr(addr: &SocketAddr) -> String {
    match addr.as_pathname() {
        Some(path) => path.display().to_string(),
        None => "abstract".to_string(),
    }
}

impl Display for CpiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CpiStatus::NotConnected => write!(f, "Not-connected"),
            CpiStatus::Incompatible => write!(f, "Incompatible"),
            CpiStatus::Connected => write!(f, "Connected"),
            CpiStatus::FrrRestarted => write!(f, "Frr-restarted"),
            CpiStatus::NeedRefresh => write!(f, "Need refresh"),
        }
    }
}

impl Display for CpiStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let empty = "--".to_string();
        let connect_t = &self
            .connect_time
            .map(|t| fmt_time(&t))
            .unwrap_or_else(|| "never".to_string());
        let last_msg_rx_t = &self
            .last_msg_rx
            .map(|t| fmt_time(&t))
            .unwrap_or_else(|| "--".to_string());
        let pid = self
            .last_pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| empty);
        let peer = match &self.peer {
            Some(a) => fmt_socketaddr(a),
            None => "--".to_string(),
        };

        Heading("Control-plane interface".to_string()).fmt(f)?;
        writeln!(f, " STATUS: {}", self.status)?;
        writeln!(f, " last connect: {connect_t} pid: {pid} peer: {peer}")?;
        writeln!(f, " last msg rx : {last_msg_rx_t}")?;
        writeln!(f, " decode failures: {}", self.decode_failures)?;
        writeln!(f, " ctl/keepalives : {}", self.control_rx)?;
        writeln!(f)?;

        fmt_cpi_stats_heading(f)?;
        fmt_stats_row(f, "connect", &self.connect)?;
        fmt_stats_row(f, "Add route", &self.add_route)?;
        fmt_stats_row(f, "Upd route", &self.update_route)?;
        fmt_stats_row(f, "Del route", &self.del_route)?;

        fmt_stats_row(f, "Add ifAddr", &self.add_ifaddr)?;
        fmt_stats_row(f, "Del ifAddr", &self.del_ifaddr)?;

        fmt_stats_row(f, "Add rmac", &self.add_rmac)?;
        fmt_stats_row(f, "Del rmac", &self.del_rmac)?;
        Ok(())
    }
}

//========================= Frrmi ================================//
impl Display for FrrmiStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let last_conn_time = &self
            .last_conn_time
            .map(|t| fmt_time(&t))
            .unwrap_or_else(|| "never".to_string());

        let last_disconn_time = &self
            .last_disconn_time
            .map(|t| fmt_time(&t))
            .unwrap_or_else(|| "never".to_string());

        let last_ok_t = &self
            .last_ok_time
            .map(|t| fmt_time(&t))
            .unwrap_or_else(|| "".to_string());

        let last_fail_t = &self
            .last_fail_time
            .map(|t| fmt_time(&t))
            .unwrap_or_else(|| "".to_string());

        let last_ok_genid = self
            .last_ok_genid
            .map(|genid| genid.to_string())
            .unwrap_or_else(|| "none".to_string());

        let last_fail_genid = self
            .last_fail_genid
            .map(|genid| genid.to_string())
            .unwrap_or_else(|| "none".to_string());

        writeln!(f, " Last connection : {last_conn_time}")?;
        writeln!(f, " Last disconnect : {last_disconn_time}")?;
        writeln!(f, " Last cfg applied: {last_ok_genid} {last_ok_t}")?;
        writeln!(f, " Last cfg failure: {last_fail_genid} {last_fail_t}")?;
        writeln!(f, " Configs applied : {}", self.apply_oks)?;
        writeln!(f, " Configs failed  : {}", self.apply_failures)?;
        Ok(())
    }
}

impl Display for Frrmi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("FRR Management interface".to_string()).fmt(f)?;
        let status = if self.has_sock() {
            "connected"
        } else {
            "not connnected"
        };
        writeln!(f, " status: {status}")?;
        writeln!(f, " remote: {}", self.get_remote())?;
        self.get_stats().fmt(f)
    }
}

impl Display for FrrAppliedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Last FRR config applied".to_string()).fmt(f)?;
        writeln!(f, " genid: {}", self.genid)?;
        writeln!(f, " \n{}", self.cfg)
    }
}
