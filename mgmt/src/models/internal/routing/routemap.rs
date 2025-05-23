// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: route maps

use net::vxlan::Vni;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum MatchingPolicy {
    Deny,
    Permit,
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RouteMapMatch {
    SrcVrf(String),
    Ipv4AddressPrefixList(String),
    Ipv6AddressPrefixList(String),
    Ipv4PrefixLen(u8),
    Ipv6PrefixLen(u8),
    Ipv4NextHopPrefixList(String),
    Ipv6NextHopPrefixList(String),
    Metric(u32),
    EvpnRouteType(u8),
    EvpnVni(Vni),
    // TODO: complete as needed
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum RouteMapSetAction {
    Tag(u32),
    Distance(u8),
    Weight(u32),
    LocalPreference(u32),
    Community(Vec<Community>, bool),
    //TODO: complete as needed
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Community {
    None,
    ASNVAL(u16, u16),
    NoAdvertise,
    NoExport,
    NoPeer,
    Blackhole,
    LocalAs,
    GracefulShutdown,
    AcceptOwn,
    //TODO: complete as needed
}

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct RouteMapEntry {
    pub seq: u32,
    pub policy: MatchingPolicy,
    pub matches: Vec<RouteMapMatch>,
    pub actions: Vec<RouteMapSetAction>,
}

#[derive(Clone, Debug)]
pub struct RouteMap {
    pub name: String,
    pub entries: BTreeSet<RouteMapEntry>,
}

#[derive(Clone, Debug, Default)]
pub struct RouteMapTable(BTreeMap<String, RouteMap>);

/* Impl basic ops */
impl RouteMapEntry {
    pub fn new(seq: u32, policy: MatchingPolicy) -> Self {
        Self {
            seq,
            policy,
            matches: vec![],
            actions: vec![],
        }
    }
    pub fn add_match(mut self, m: RouteMapMatch) -> Self {
        self.matches.push(m);
        self
    }
    pub fn add_action(mut self, action: RouteMapSetAction) -> Self {
        self.actions.push(action);
        self
    }
}
impl RouteMap {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            entries: BTreeSet::new(),
        }
    }
    pub fn add_entry(&mut self, entry: RouteMapEntry) {
        self.entries.insert(entry);
    }
}
impl RouteMapTable {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_route_map(&mut self, rmap: RouteMap) {
        self.0.insert(rmap.name.clone(), rmap);
    }
    pub fn values(&self) -> impl Iterator<Item = &RouteMap> {
        self.0.values()
    }
}
