// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements Display for routing objects
//!
//! Note: most of the objects for which Display is implemented here belong to
//! the routing database which is fully and only owned by the routing thread.
//! This includes the Fib contents since fibs belong to vrfs.
//! So:
//!    - it is Okay to call any of this from the routing thread (cli)
//!    - Display for Fib objects visible from dataplane workers can be safely called.
//!    - Cli thread does not need a read handle cache to inspect Fib contents
//!    - Still, FIXME(fredi): make that distinction clearer

use crate::atable::adjacency::{Adjacency, AdjacencyTable};
use crate::fib::fibgroupstore::FibRoute;
use crate::fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};
use crate::fib::fibtype::{Fib, FibKey, FibRouteV4Filter, FibRouteV6Filter};
use crate::frr::frrmi::{FrrAppliedConfig, Frrmi, FrrmiStats};
use crate::router::cpi::{CpiStats, CpiStatus, StatsRow};

use crate::rib::VrfTable;
use crate::rib::encapsulation::{
    Encapsulation, ResolvedEncapsulation, ResolvedVxlan, VxlanEncapsulation,
};
#[cfg(test)]
use crate::rib::nexthop::NhopStore;
use crate::rib::nexthop::{FwAction, Nhop, NhopKey};

use crate::rib::vrf::{Route, RouteFlags, RouteOrigin, ShimNhop, Vrf, VrfStatus};
use crate::rib::vrf::{RouteV4Filter, RouteV6Filter};

use crate::interfaces::iftable::IfTable;
use crate::interfaces::interface::Attachment;
use crate::interfaces::interface::{IfDataDot1q, IfDataEthernet};
use crate::interfaces::interface::{IfState, IfType, Interface};

use crate::evpn::rmac::RmacFilter;
use crate::evpn::{RmacEntry, RmacStore, Vtep};

use chrono::DateTime;
use common::cliprovider::Heading;

use clock::{Duration, Instant};
use lpm::prefix::IpPrefix;
use lpm::trie::{PrefixMapTrie, TrieMap};
use net::vxlan::Vni;
use std::borrow::Cow;
use std::fmt::Display;
use std::fmt::Write;
use std::os::unix::net::SocketAddr;
use std::rc::{Rc, Weak};

use tracing::warn;

// ========================= Common ========================== //
fn fmt_opt_value<T: Display>(
    f: &mut std::fmt::Formatter<'_>,
    name: &str,
    value: Option<T>,
    nl: bool,
) -> Result<(), std::fmt::Error> {
    match value {
        Option::None => write!(f, "{name}: --"),
        Some(value) => write!(f, "{name}: {value}"),
    }?;
    if nl { writeln!(f) } else { Ok(()) }
}

// ===================== Encapsulations ====================== //
impl Display for VxlanEncapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Vxlan (vni {}), remote {}",
            self.vni.as_u32(),
            self.remote
        )
    }
}
impl Display for ResolvedVxlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Vxlan (vni {}), remote {} dmac {}",
            self.vni.as_u32(),
            self.remote,
            self.dmac
        )
    }
}
impl Display for ResolvedEncapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvedEncapsulation::Vxlan(encap) => encap.fmt(f),
            ResolvedEncapsulation::Mpls(label) => write!(f, "MPLS (label:{label})"),
        }
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

// =============== VRFs, routes and next-hops ================= //
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
impl Display for RouteFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.contains(RouteFlags::STALE) {
            write!(f, "s")?;
        }
        Ok(())
    }
}
pub struct PrettyDuration(Duration);
impl PrettyDuration {
    #[must_use]
    pub fn new(d: Duration) -> Self {
        Self(d)
    }
}
impl Display for PrettyDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total = self.0.as_secs();
        let days = total / 86_400;
        let hours = (total % 86_400) / 3_600;
        let minutes = (total % 3_600) / 60;
        let seconds = total % 60;

        if days != 0 {
            write!(f, "{days:02}d")?;
        }
        write!(f, "{hours:02}:{minutes:02}:{seconds:02}")?;
        Ok(())
    }
}

struct Age(Instant);
impl Display for Age {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let duration = clock::elapsed(self.0);
        PrettyDuration(duration).fmt(f)
    }
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

impl Display for NhopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ifname = self.ifindex.and_then(name_of);

        if let Some(address) = self.address {
            write!(f, " via {address}")?;
        }
        if let Some(name) = ifname {
            write!(f, " interface {name}")?;
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
        write!(f, "  ({})", self.origin)?;
        Ok(())
    }
}
impl Display for Nhop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_nhop(f, self, 0)
    }
}
fn indent_depth(f: &mut std::fmt::Formatter<'_>, depth: u8) -> std::fmt::Result {
    let indent = " ".repeat(4 * depth as usize);
    write!(f, "{indent}")
}
fn fmt_nhop(f: &mut std::fmt::Formatter<'_>, nhop: &Nhop, depth: u8) -> std::fmt::Result {
    indent_depth(f, depth)?;
    nhop.key.fmt(f)?;
    if nhop.invalid.get() {
        write!(f, " (INVALID)")?;
    }
    if nhop.is_unresolved() {
        write!(f, " (unresolved)")?;
    }
    writeln!(f)?;

    // resolvers
    if let Some(resolvers) = nhop.get_resolvers() {
        for r in resolvers.iter().filter_map(Weak::upgrade) {
            fmt_nhop(f, &r, depth.saturating_add(1))?;
        }
    }
    Ok(())
}
fn fmt_shim_nhop(f: &mut std::fmt::Formatter<'_>, shim: &ShimNhop) -> std::fmt::Result {
    fmt_nhop(f, &shim.rc, 1)
}
fn fmt_route(f: &mut std::fmt::Formatter<'_>, route: &Route) -> std::fmt::Result {
    let age = Age(route.tstamp);
    writeln!(
        f,
        "{} [{}/{}] {age}",
        route.origin, route.distance, route.metric
    )?;
    for shim in &route.s_nhops {
        fmt_shim_nhop(f, shim)?;
    }
    writeln!(f)
}
fn fmt_vrf_oneline(vrf: &Vrf, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let vpc = vrf.vpcname.as_deref().unwrap_or("--");
    let vni = vrf
        .vni
        .map_or_else(|| "--".to_string(), |vni| vni.to_string());

    writeln!(
        f,
        " Vrf: '{}' (id: {}) VPC: {vpc} vni: {vni}\n",
        vrf.name, vrf.vrfid
    )?;
    Ok(())
}

#[allow(dead_code)] // we don't display this atm
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

fn fmt_nhop_internals(
    f: &mut std::fmt::Formatter<'_>,
    rc: &Rc<Nhop>,
    depth: u8,
) -> std::fmt::Result {
    let tab = 8 * depth as usize;
    let indent = " ".repeat(tab);

    let sym = if depth == 0 { "NH" } else { "ref" };
    write!(f, "{indent} ({}) {sym} = {}", Rc::strong_count(rc), rc.key)?;
    if rc.is_unresolved() {
        write!(f, " (UNRESOLVED)")?;
    }
    writeln!(f)?;

    let Some(resolvers) = rc.get_resolvers() else {
        return Ok(());
    };
    for r in resolvers.iter().filter_map(Weak::upgrade) {
        fmt_nhop_internals(f, &r, depth.saturating_add(1))?;
    }
    Ok(())
}

#[cfg(test)] // only used in tests atm
impl Display for NhopStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("Next-hop Store ({})", self.len())).fmt(f)?;
        for nhop in self.iter() {
            fmt_nhop_internals(f, nhop, 0)?;
        }
        Ok(())
    }
}

impl Display for ShimNhop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_shim_nhop(f, self)
    }
}

impl Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_route(f, self)
    }
}

#[cfg(test)] // only used in tests atm
fn fmt_vrf_trie<P: IpPrefix, F: Fn(&(P, &Route)) -> bool>(
    f: &mut std::fmt::Formatter<'_>,
    show_string: &str,
    trie: &PrefixMapTrie<P, Route>,
    _route_filter: F,
) -> std::fmt::Result {
    Heading(format!("{show_string} routes ({})", trie.len())).fmt(f)?;
    for (prefix, route) in trie.iter() {
        writeln!(f, " {}  {prefix:?} {route}", route.flags)?;
    }
    Ok(())
}

#[cfg(test)] // only used in tests atm
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

pub(crate) struct VrfViewV4<'a> {
    vrf: &'a Vrf,
    filter: Option<&'a RouteV4Filter>,
}
impl<'a> VrfViewV4<'a> {
    #[must_use]
    pub fn filter(mut self, filter: &'a RouteV4Filter) -> Self {
        self.filter = Some(filter);
        self
    }
}

impl Display for VrfViewV4<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filter = self
            .filter
            .map_or_else(|| Cow::Owned(RouteV4Filter::default()), Cow::Borrowed);

        // apply the filter
        let rt_iter = self.vrf.filtered_ipv4(&filter);

        // total number of routes
        let total = self.vrf.len_v4();

        // displayed routes
        let mut displayed = 0;

        Heading(format!("Ipv4 routes ({total})")).fmt(f)?;
        fmt_vrf_oneline(self.vrf, f)?;

        for (prefix, route) in rt_iter {
            write!(f, "{}  {prefix} ", route.flags)?;
            fmt_route(f, route)?;
            displayed += 1;
        }
        if displayed != total {
            writeln!(f, "\n  (Displayed {displayed} routes out of {total})")?;
        }
        Ok(())
    }
}

pub(crate) struct VrfViewV6<'a> {
    vrf: &'a Vrf,
    filter: Option<&'a RouteV6Filter>,
}
impl<'a> VrfViewV6<'a> {
    #[must_use]
    pub fn filter(mut self, filter: &'a RouteV6Filter) -> Self {
        self.filter = Some(filter);
        self
    }
}
impl Display for VrfViewV6<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filter = self
            .filter
            .map_or_else(|| Cow::Owned(RouteV6Filter::default()), Cow::Borrowed);

        // apply the filter
        let rt_iter = self.vrf.filtered_ipv6(&filter);

        // total number of routes
        let total = self.vrf.len_v6();

        // displayed routes
        let mut displayed = 0;

        Heading(format!("Ipv6 routes ({total})")).fmt(f)?;
        fmt_vrf_oneline(self.vrf, f)?;

        for (prefix, route) in rt_iter {
            write!(f, "{}  {prefix} ", route.flags)?;
            fmt_route(f, route)?;
            displayed += 1;
        }
        if displayed != total {
            writeln!(f, "\n  (Displayed {displayed} routes out of {total})")?;
        }
        Ok(())
    }
}

// ================================================= //

pub(crate) struct VrfV4Nexthops<'a> {
    vrf: &'a Vrf,
}

impl Display for VrfV4Nexthops<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Ipv4 Next-hops").fmt(f)?;
        fmt_vrf_oneline(self.vrf, f)?;

        let iter = self
            .vrf
            .nhstore
            .iter()
            .filter(|nh| nh.key.address.is_none_or(|a| a.is_ipv4()));

        for nhop in iter {
            fmt_nhop_internals(f, nhop, 0)?;
        }
        Ok(())
    }
}
pub(crate) struct VrfV6Nexthops<'a> {
    vrf: &'a Vrf,
}

impl Display for VrfV6Nexthops<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Ipv6 Next-hops").fmt(f)?;
        fmt_vrf_oneline(self.vrf, f)?;

        let iter = self
            .vrf
            .nhstore
            .iter()
            .filter(|nh| nh.key.address.is_none_or(|a| a.is_ipv6()));

        for nhop in iter {
            fmt_nhop_internals(f, nhop, 0)?;
        }
        Ok(())
    }
}

// ======================= Vrf table ======================== //

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
            "name", "id", "vni", "Ipv4-routes", "Ipv6-routes", "status", "table-id", "vpc"
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
            &vrf.vpcname.as_ref().map_or_else(|| "", |t| t.as_str())
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

// ======================= Interfaces ======================== //
impl Display for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attachment::BridgeDomain => write!(f, "BD"),
            Attachment::Vrf(fibkey) => write!(f, "VRF: {fibkey}"),
        }
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
        let s = match *self {
            IfState::Unknown => "unknown",
            IfState::Up => "up",
            IfState::Down => "down",
        };
        f.pad(s)
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
        let mtu = self.mtu.map_or_else(|| "--".to_string(), |m| m.to_string());
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

// =================== Interface addresses =================== //
#[repr(transparent)]
pub(crate) struct IfTableAddress<'a>(&'a IfTable);
impl IfTable {
    #[must_use]
    pub(crate) fn cli_addresses(&self) -> IfTableAddress<'_> {
        IfTableAddress(self)
    }
}

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
    for ifaddr in &iface.addresses {
        write!(f, " {ifaddr}")?;
    }
    writeln!(f)
}
impl Display for IfTableAddress<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("interface addresses").fmt(f)?;
        fmt_interface_addr_heading(f)?;
        for iface in self.0.values() {
            fmt_interface_addresses(f, iface)?;
        }
        Ok(())
    }
}

// ======================= RMAC store ======================== //
macro_rules! RMAC_TBL_FMT {
    () => {
        " {:<5} {:<20} {:<18} {:<8}"
    };
}
fn fmt_rmac_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(RMAC_TBL_FMT!(), "vni", "address", "mac", "status")
    )
}

impl Display for RmacEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let valid = if self.is_stale() { "stale" } else { "ok" };
        write!(
            f,
            "{}",
            format_args!(
                RMAC_TBL_FMT!(),
                self.vni.as_u32(),
                self.address,
                self.mac,
                valid
            )
        )
    }
}

pub(crate) struct RmacStoreView<'a> {
    rmac_store: &'a RmacStore,
    filter: Option<&'a RmacFilter>,
}
impl<'a> RmacStoreView<'a> {
    #[must_use]
    pub fn filter(mut self, filter: &'a RmacFilter) -> Self {
        self.filter = Some(filter);
        self
    }
}

impl Display for RmacStoreView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let store = self.rmac_store;
        let filter = self
            .filter
            .map_or_else(|| Cow::Owned(RmacFilter::default()), Cow::Borrowed);

        Heading(format!(
            "Router macs (entries: {} stale: {})",
            store.len(),
            store.stale()
        ))
        .fmt(f)?;

        fmt_rmac_heading(f)?;

        let total_entries = store.len();
        let mut displayed = 0;
        for entry in store.filtered(&filter) {
            writeln!(f, "{entry}")?;
            displayed += 1;
        }
        if displayed != total_entries {
            writeln!(
                f,
                "\n  (Displayed {displayed} entries out of {total_entries})"
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
impl Display for RmacStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!(
            "Router macs (entries: {} stale: {})",
            self.len(),
            self.stale()
        ))
        .fmt(f)?;

        fmt_rmac_heading(f)?;
        for rmac in self.values() {
            writeln!(f, "{rmac}")?;
        }
        Ok(())
    }
}

// ================ Local VTEP configuration ================= //
impl Display for Vtep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Local VTEP configuration").fmt(f)?;
        writeln!(f, " ip address: {}", self.ip())?;
        writeln!(f, " Mac address: {}", self.mac())
    }
}

// ======================= Adjacencies ======================= //
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

// =========================== FIB =========================== //
impl Display for FibKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            FibKey::Id(vrfid) => write!(f, "vrfid: {vrfid}")?,
            FibKey::Vni(vni) => write!(f, "vni: {vni:?}")?,
        }
        Ok(())
    }
}
fn fmt_egress_object(
    f: &mut std::fmt::Formatter<'_>,
    egress: &EgressObject,
) -> Result<(), std::fmt::Error> {
    write!(f, "egress:")?;
    let ifname = egress.ifindex.and_then(name_of);
    fmt_opt_value(f, " interface", ifname, false)?;
    fmt_opt_value(f, " idx", egress.ifindex.as_ref(), false)?;
    fmt_opt_value(f, " addr", egress.address.as_ref(), false)
}
fn fmt_local_instruction(
    f: &mut std::fmt::Formatter<'_>,
    ifindex: InterfaceIndex,
) -> Result<(), std::fmt::Error> {
    match name_of(ifindex) {
        Some(ifname) => write!(f, "Local ({ifname}, ifindex {ifindex})"),
        None => write!(f, "Local (ifindex {ifindex})"),
    }
}

fn fmt_pkt_instruction(
    f: &mut std::fmt::Formatter<'_>,
    pki: &PktInstruction,
) -> Result<(), std::fmt::Error> {
    match pki {
        PktInstruction::Drop => write!(f, "drop"),
        PktInstruction::Local(ifindex) => fmt_local_instruction(f, *ifindex),
        PktInstruction::Egress(egress) => fmt_egress_object(f, egress),
        PktInstruction::Encap(encap) => write!(f, "encap: {encap}"),
    }
}
fn fmt_fib_entry(f: &mut std::fmt::Formatter<'_>, entry: &FibEntry) -> Result<(), std::fmt::Error> {
    writeln!(f, "        - entry:")?;
    for (n, inst) in entry.iter().enumerate() {
        write!(f, "            {n} ")?;
        fmt_pkt_instruction(f, inst)?;
        writeln!(f)?;
    }
    Ok(())
}
fn fmt_fibgroup(
    f: &mut std::fmt::Formatter<'_>,
    fibgroup: &FibGroup,
) -> Result<(), std::fmt::Error> {
    writeln!(f, "     ■ group ({} entries):", fibgroup.len())?;
    for entry in fibgroup.iter() {
        fmt_fib_entry(f, entry)?;
    }
    writeln!(f)
}
fn fmt_fib_route(f: &mut std::fmt::Formatter<'_>, route: &FibRoute) -> std::fmt::Result {
    writeln!(
        f,
        "via {} groups, {} entries:",
        route.num_groups(),
        route.len()
    )?;
    for group in route.iter() {
        fmt_fibgroup(f, group)?;
    }
    Ok(())
}

impl Display for EgressObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt_egress_object(f, self)
    }
}
impl Display for PktInstruction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt_pkt_instruction(f, self)
    }
}
impl Display for FibEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt_fib_entry(f, self)
    }
}
impl Display for FibGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt_fibgroup(f, self)
    }
}
impl Display for FibRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_fib_route(f, self)
    }
}
fn fmt_fib_trie<P: IpPrefix, F: Fn(&(P, &FibRoute)) -> bool>(
    f: &mut std::fmt::Formatter<'_>,
    fibid: FibKey,
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

pub(crate) struct FibViewV4<'a> {
    vrf: &'a Vrf,
    filter: Option<&'a FibRouteV4Filter>,
}
impl<'a> FibViewV4<'a> {
    #[must_use]
    pub fn filter(mut self, filter: &'a FibRouteV4Filter) -> Self {
        self.filter = Some(filter);
        self
    }
}

impl Display for FibViewV4<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(fibr) = self.vrf.fibw.enter() else {
            return writeln!(f, "Unable to read fib!");
        };

        let filter = self
            .filter
            .map_or_else(|| Cow::Owned(FibRouteV4Filter::default()), Cow::Borrowed);

        let rt_iter = fibr.filtered_v4(&filter);
        let total = fibr.len_v4();
        let mut displayed = 0;

        Heading(format!("Ipv4 FIB ({total} destinations)")).fmt(f)?;
        fmt_vrf_oneline(self.vrf, f)?;

        for (prefix, route) in rt_iter {
            write!(f, "  {prefix:?} ")?;
            fmt_fib_route(f, route)?;
            displayed += 1;
        }
        if displayed != total {
            writeln!(f, "\n  (Displayed {displayed} destinations out of {total})")?;
        }
        Ok(())
    }
}

pub(crate) struct FibViewV6<'a> {
    vrf: &'a Vrf,
    filter: Option<&'a FibRouteV6Filter>,
}
impl<'a> FibViewV6<'a> {
    #[must_use]
    pub fn filter(mut self, filter: &'a FibRouteV6Filter) -> Self {
        self.filter = Some(filter);
        self
    }
}
impl Display for FibViewV6<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(fibr) = self.vrf.fibw.enter() else {
            return writeln!(f, "Unable to read fib!");
        };

        let filter = self
            .filter
            .map_or_else(|| Cow::Owned(FibRouteV6Filter::default()), Cow::Borrowed);

        let rt_iter = fibr.filtered_v6(&filter);
        let total = fibr.len_v6();
        let mut displayed = 0;

        Heading(format!("Ipv6 FIB ({total} destinations)")).fmt(f)?;
        fmt_vrf_oneline(self.vrf, f)?;

        for (prefix, route) in rt_iter {
            write!(f, "  {prefix:?} ")?;
            fmt_fib_route(f, route)?;
            displayed += 1;
        }

        if displayed != total {
            writeln!(f, "\n  (Displayed {displayed} destinations out of {total})")?;
        }

        Ok(())
    }
}

// We show the same fib groups for Ipv4 and Ipv6 for the time being, since filtering
// them according to ip version is not yet possible.
pub(crate) struct FibGroups<'a> {
    vrf: &'a Vrf,
}
impl Display for FibGroups<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(ref fibr) = self.vrf.fibw.enter() else {
            writeln!(f, "Unable to access fib")?;
            return Ok(());
        };
        let num_groups = fibr.len_groups();
        let vrf_name = &self.vrf.name;
        let vrfid = self.vrf.vrfid;
        let fibid = fibr.get_id();
        Heading("FIB groups").fmt(f)?;

        writeln!(f, " vrf: {vrf_name}, Id: {vrfid} fibId: {fibid}")?;
        writeln!(f, " groups: {num_groups}\n")?;

        for group in fibr.group_iter() {
            fmt_fibgroup(f, group)?;
        }
        Ok(())
    }
}

// ===================== Time utilities ====================== //
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
        let _ = write!(out, "{weeks} weeks ");
    }
    if days > 0 {
        let _ = write!(out, "{days} days ");
    }
    if hours > 0 {
        let _ = write!(out, "{hours} hours ");
    }
    if minutes > 0 {
        let _ = write!(out, "{minutes} min ");
    }
    let _ = write!(out, "{seconds} s ago)");
    out
}

// =========================== CPI =========================== //
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
            .map_or_else(|| "never".to_string(), |t| fmt_time(&t));
        let last_msg_rx_t = &self
            .last_msg_rx
            .map_or_else(|| "--".to_string(), |t| fmt_time(&t));
        let pid = self.last_pid.map_or_else(|| empty, |pid| pid.to_string());
        let peer = match &self.peer {
            Some(a) => fmt_socketaddr(a),
            None => "--".to_string(),
        };

        Heading("Control-plane interface").fmt(f)?;
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

// ========================== FRRMI ========================== //
impl Display for FrrmiStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let last_conn_time = &self
            .last_conn_time
            .map_or_else(|| "never".to_string(), |t| fmt_time(&t));
        let last_disconn_time = &self
            .last_disconn_time
            .map_or_else(|| "never".to_string(), |t| fmt_time(&t));
        let last_ok_t = &self.last_ok_time.map(|t| fmt_time(&t)).unwrap_or_default();
        let last_fail_t = &self
            .last_fail_time
            .map(|t| fmt_time(&t))
            .unwrap_or_default();
        let last_ok_genid = self
            .last_ok_genid
            .map_or_else(|| "none".to_string(), |genid| genid.to_string());
        let last_fail_genid = self
            .last_fail_genid
            .map_or_else(|| "none".to_string(), |genid| genid.to_string());

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
        Heading("FRR Management interface").fmt(f)?;
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
        Heading("Last FRR config applied").fmt(f)?;
        writeln!(f, " genid: {}", self.genid)?;
        writeln!(f, " \n{}", self.cfg)
    }
}

// ========================== Cli displays ========================== //

impl Vrf {
    #[must_use]
    pub(crate) fn cli_ipv4_rib(&self) -> VrfViewV4<'_> {
        VrfViewV4 {
            vrf: self,
            filter: None,
        }
    }

    #[must_use]
    pub(crate) fn cli_ipv6_rib(&self) -> VrfViewV6<'_> {
        VrfViewV6 {
            vrf: self,
            filter: None,
        }
    }

    #[must_use]
    pub(crate) fn cli_ipv4_nhops(&self) -> VrfV4Nexthops<'_> {
        VrfV4Nexthops { vrf: self }
    }

    #[must_use]
    pub(crate) fn cli_ipv6_nhops(&self) -> VrfV6Nexthops<'_> {
        VrfV6Nexthops { vrf: self }
    }

    #[must_use]
    pub(crate) fn cli_ipv4_fib(&self) -> FibViewV4<'_> {
        FibViewV4 {
            vrf: self,
            filter: None,
        }
    }

    #[must_use]
    pub(crate) fn cli_ipv6_fib(&self) -> FibViewV6<'_> {
        FibViewV6 {
            vrf: self,
            filter: None,
        }
    }

    #[must_use]
    pub(crate) fn cli_fib_groups(&self) -> FibGroups<'_> {
        FibGroups { vrf: self }
    }
}

impl RmacStore {
    #[must_use]
    pub(crate) fn cli_view(&self) -> RmacStoreView<'_> {
        RmacStoreView {
            rmac_store: self,
            filter: None,
        }
    }
}

// ========================== Ifindex translation ========================== //
use crate::interfaces::iftablerw::IfTableReader;
use net::interface::{InterfaceIndex, InterfaceName};
use std::cell::RefCell;

thread_local! {
    static IFMAP: RefCell<Option<IfTableReader>> = const { RefCell::new(None) };
}
/// Initialize the thread-local `IFMAP` with the given `IfTableReader`
pub(crate) fn ifmap_init(iftr: IfTableReader) {
    IFMAP.set(Some(iftr));
}

/// Resolve an `InterfaceIndex` to a `InterfaceName`.
/// N.B. this provides an owned `InterfaceName`. This clone could be
/// avoided, but interface names are very short.
fn name_of(ifindex: InterfaceIndex) -> Option<InterfaceName> {
    IFMAP.with_borrow(|iftr| {
        iftr.as_ref().and_then(|iftr| {
            iftr.enter().and_then(|iftable| {
                iftable
                    .get_interface(ifindex)
                    .map(|iface| iface.name.clone())
            })
        })
    })
}
