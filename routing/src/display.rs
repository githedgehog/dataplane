// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements Display for routing objects

use crate::atable::adjacency::{Adjacency, AdjacencyTable};
use crate::fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};
use crate::fib::fibtable::FibTable;
use crate::fib::fibtype::{Fib, FibId};

use crate::rib::VrfTable;
use crate::rib::encapsulation::{Encapsulation, VxlanEncapsulation};
use crate::rib::nexthop::{FwAction, Nhop, NhopKey, NhopStore};
use crate::rib::vrf::{Route, ShimNhop, Vrf, VrfStatus};

use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::Attachment;
use crate::interfaces::interface::{IfDataDot1q, IfDataEthernet};
use crate::interfaces::interface::{IfState, IfType, Interface};

use crate::evpn::{RmacEntry, RmacStore, Vtep};
use crate::pretty_utils::{Heading, line};
use crate::testfib::TestFib;

use net::ipv4::Ipv4Prefix;
use net::ipv6::Ipv6Prefix;
use net::vxlan::Vni;
use prefix_trie::{Prefix, PrefixMap};
use std::fmt::Display;
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
            //write!(f, "Vxlan (vni:{})", e.vni.as_u32())?,
            Encapsulation::Mpls(label) => write!(f, "MPLS (label:{label})")?,
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
        writeln!(f, "{:?} [{}/{}]", self.origin, self.distance, self.metric)?;
        for slim in &self.s_nhops {
            writeln!(f, "       {slim}")?;
        }
        Ok(())
    }
}

fn fmt_vrf_trie<P: Prefix, F: Fn(&(&P, &Route)) -> bool>(
    f: &mut std::fmt::Formatter<'_>,
    show_string: &str,
    trie: &PrefixMap<P, Route>,
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

//========================= Test Fib ================================//
impl Display for TestFib {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        Heading(format!("TestFib ({} entries)", self.len())).fmt(f)?;
        for entry in self.iter() {
            write!(f, " {entry}")?;
        }
        Ok(())
    }
}

//========================= Fib ================================//

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
            PktInstruction::Nat => write!(f, "NAT"),
        }
    }
}
impl Display for FibEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "     ■ FibEntry ({} actions):", self.len())?;
        for (n, inst) in self.iter().enumerate() {
            writeln!(f, "         {n} {inst}")?;
        }
        Ok(())
    }
}
impl Display for FibGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "FibGroup ({} entries):", self.len())?;
        for entry in self.iter() {
            writeln!(f, "{entry}")?;
        }
        Ok(())
    }
}

impl Display for FibId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            FibId::Id(vrfid) => write!(f, "vrfid: {vrfid}")?,
            FibId::Vni(vni) => write!(f, "vni: {vni:?}")?,
        }
        Ok(())
    }
}

fn fmt_fib_trie<P: Prefix, F: Fn(&(&P, &Rc<FibGroup>)) -> bool>(
    f: &mut std::fmt::Formatter<'_>,
    fibid: FibId,
    show_string: &str,
    trie: &PrefixMap<P, Rc<FibGroup>>,
    group_filter: F,
) -> std::fmt::Result {
    Heading(format!(
        "{show_string} Fib ({fibid}) -- {} prefixes",
        trie.len()
    ))
    .fmt(f)?;
    for (prefix, group) in trie.iter().filter(group_filter) {
        write!(f, "  {prefix:?}: {group}")?;
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
    F: Fn(&(&Ipv4Prefix, &Rc<FibGroup>)) -> bool,
{
    pub vrf: &'a Vrf,
    pub filter: &'a F,
}
impl<F: for<'a> Fn(&'a (&Ipv4Prefix, &Rc<FibGroup>)) -> bool> Display for FibViewV4<'_, F> {
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
        for (prefix, group) in rt_iter {
            write!(f, "  {prefix:?} {group}")?;
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
    F: Fn(&(&Ipv6Prefix, &Rc<FibGroup>)) -> bool,
{
    pub vrf: &'a Vrf,
    pub filter: &'a F,
}
impl<F: for<'a> Fn(&'a (&Ipv6Prefix, &Rc<FibGroup>)) -> bool> Display for FibViewV6<'_, F> {
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
        for (prefix, group) in rt_iter {
            write!(f, "  {prefix:?} {group}")?;
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
            write!(f, " ({}) {group}", Rc::strong_count(group))?;
        }
        Ok(())
    }
}
