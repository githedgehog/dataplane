// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements Display for routing objects

use crate::encapsulation::Encapsulation;
use crate::interface::{IfDataDot1q, IfDataEthernet, IfState, IfTable, IfType, Interface};
use crate::nexthop::{FwAction, Nhop, NhopKey, NhopStore};
use crate::pretty_utils::{line, Heading};
use crate::vrf::{Route, ShimNhop, Vrf};
use iptrie::RTrieMap;
use std::fmt::Display;
use std::sync::Arc;

//=================== VRFs, routes and next-hops ====================//

impl Display for NhopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(address) = self.address {
            write!(f, " via {address}")?;
        }
        if let Some(ifindex) = self.ifindex {
            write!(f, " interface:{ifindex}")?;
        }
        if let Some(encap) = self.encap {
            write!(f, " encap:{encap}")?;
        }
        if self.fwaction != FwAction::Forward {
            write!(f, " action:{:?}", self.fwaction)?;
        }
        Ok(())
    }
}
impl Display for Nhop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.key, f)
    }
}

fn fmt_nhop_rec(f: &mut std::fmt::Formatter<'_>, rc: &Arc<Nhop>, depth: u8) -> std::fmt::Result {
    let tab = 8 * depth as usize;
    let indent = String::from_utf8(vec![b' '; tab]).unwrap();

    let sym = if depth == 0 { "NH" } else { "ref" };
    writeln!(f, "{} ({}) {} = {}", indent, Arc::strong_count(rc), sym, rc)?;

    for r in rc.resolvers.read().expect("poisoned").iter() {
        fmt_nhop_rec(f, r, depth + 1)?;
    }
    Ok(())
}
impl Display for NhopStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("Next-hop Store ({})", self.0.len())).fmt(f)?;
        for nhop in self.0.iter() {
            fmt_nhop_rec(f, nhop, 0)?;
        }
        line(f)
    }
}

impl Display for ShimNhop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.rc.fmt(f) // Nhop, which displays NhopKey
    }
}
impl Display for Encapsulation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "")?;
        match self {
            Encapsulation::Vxlan(e) => write!(f, "Vxlan (vni:{})", e.vni.as_u32())?,
            Encapsulation::Mpls(label) => write!(f, "MPLS (label:{})", label)?,
        }
        Ok(())
    }
}

impl Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:?} [{}/{}]", self.rtype, self.distance, self.metric)?;
        for slim in &self.s_nhops {
            writeln!(f, "       {}", slim)?;
        }
        Ok(())
    }
}

fn fmt_vrf_trie<P: iptrie::IpPrefix>(
    f: &mut std::fmt::Formatter<'_>,
    show_string: &str,
    trie: &RTrieMap<P, Route>,
) -> std::fmt::Result {
    Heading(format!("{} routes ({})", show_string, trie.len())).fmt(f)?;
    for (prefix, route) in trie.iter() {
        writeln!(f, "  {:?} {}", prefix, route)?;
    }
    Ok(())
}

impl Display for Vrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " Vrf: '{}' (id: {})", self.name, self.vrfid)?;
        fmt_vrf_trie(f, "Ipv4", &self.routesv4)?;
        fmt_vrf_trie(f, "Ipv6", &self.routesv6)?;
        self.nhstore.fmt(f)?;
        Ok(())
    }
}

//========================= Interfaces ================================//

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
        f.pad(&format!(
            "  {:>12} ({}) {}|{} {:<16} ",
            self.name, self.ifindex, self.admin_state, self.oper_state, vrf_name,
        ))?;
        self.iftype.fmt(f)?;
        if !self.addresses.is_empty() {
            write!(f, "      addresses:")?;
            for (addr, mask_len) in self.addresses.iter() {
                write!(f, " {}/{}", addr, mask_len)?;
            }
        }
        Ok(())
    }
}
impl Display for IfTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading(format!("interfaces ({})", self.0.len())).fmt(f)?;
        for iface in self.0.values() {
            writeln!(f, " {}", iface)?;
        }
        Ok(())
    }
}
