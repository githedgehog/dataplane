// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements Display for routing objects

use crate::encapsulation::Encapsulation;
use crate::nexthop::{FwAction, Nhop, NhopKey, NhopStore};
use crate::pretty_utils::{line, Heading};
use crate::vrf::{Route, ShimNhop, Vrf};
use iptrie::RTrieMap;
use std::fmt::Display;
use std::rc::Rc;

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

fn fmt_nhop_rec(f: &mut std::fmt::Formatter<'_>, rc: &Rc<Nhop>, depth: u8) -> std::fmt::Result {
    let tab = 8 * depth as usize;
    let indent = String::from_utf8(vec![b' '; tab]).unwrap();

    let sym = if depth == 0 { "NH" } else { "ref" };
    writeln!(f, "{} ({}) {} = {}", indent, Rc::strong_count(rc), sym, rc)?;

    for r in rc.resolvers.borrow().iter() {
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
