// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: route maps

use crate::models::external::{ConfigError, ConfigResult};
use net::vxlan::Vni;
use std::collections::{BTreeMap, BTreeSet};
use tracing::error;

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
    pub policy: MatchingPolicy,
    pub matches: Vec<RouteMapMatch>,
    pub actions: Vec<RouteMapSetAction>,
}

#[derive(Clone, Debug)]
pub struct RouteMap {
    pub name: String,
    next_seq: u32,
    pub entries: BTreeMap<u32, RouteMapEntry>,
}

#[derive(Clone, Debug, Default)]
pub struct RouteMapTable(BTreeMap<String, RouteMap>);

/* Impl basic ops */
impl RouteMapEntry {
    pub fn new(policy: MatchingPolicy) -> Self {
        Self {
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
            next_seq: 1,
            entries: BTreeMap::new(),
        }
    }
    pub fn add_entry(&mut self, seq: Option<u32>, entry: RouteMapEntry) -> ConfigResult {
        let seq = match seq {
            Some(n) => n,
            None => {
                let value = self.next_seq;
                self.next_seq += 1;
                value
            }
        };
        if self.entries.contains_key(&seq) {
            let msg = format!(
                "Duplicate route-mape seq {} in route map {}",
                seq, self.name
            );
            error!("{msg}");
            return Err(ConfigError::InternalFailure(msg));
        }
        self.entries.insert(seq, entry);
        Ok(())
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
