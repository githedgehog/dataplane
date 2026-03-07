// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow filter. This should not go here

use crate::portfw::PortRange;
use crate::portfw::portfwtable::lpmmap::LpmMap;
use crate::portfw::portfwtable::rangeset::RangeSetError;
use ahash::RandomState;
use config::GenId;
use lpm::prefix::Prefix;
use lpm::trie::IpPrefixTrie;
use net::ip::NextHeader;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZero;
use std::sync::Arc;
use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum VpcRoutingError {
    #[error("Routing overlap")]
    OverlapErr(#[from] RangeSetError),
    #[error("Invalid route")]
    InvalidRoute,
    #[error("Error: a VPC can have one default at the most")]
    SingleDefault,
}

#[derive(Debug, PartialEq, Eq)]
pub struct IngressKey {
    pub(crate) src_vpcd: VpcDiscriminant,
    pub(crate) proto: Option<NextHeader>, // None => don't care
}
impl IngressKey {
    #[must_use]
    pub fn new(src_vpcd: VpcDiscriminant, proto: Option<NextHeader>) -> Self {
        Self { src_vpcd, proto }
    }
}
impl Hash for IngressKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.src_vpcd.hash(state);
        if let Some(proto) = self.proto
            && (proto == NextHeader::TCP || proto == NextHeader::UDP)
        {
            self.proto.hash(state);
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Action {
    Drop,
    Forward,
    PortForward,
    Masquerade,
    StaticNat,
}

#[derive(Debug)]
pub struct OvelayRoute {
    pub(crate) dst_vpcd: VpcDiscriminant,
    pub(crate) prefix: Prefix,               // not really needed
    pub(crate) proto: Option<NextHeader>,    // not really needed
    pub(crate) portrange: Option<PortRange>, // not really needed
    pub(crate) action: Action,
}
impl OvelayRoute {
    #[must_use]
    pub fn new(
        dst_vpcd: VpcDiscriminant,
        prefix: Prefix,
        proto: Option<NextHeader>,
        portrange: Option<PortRange>,
        action: Action,
    ) -> Self {
        Self {
            dst_vpcd,
            prefix,
            proto,
            portrange,
            action,
        }
    }
}

/// The routing table for a single VPC and protocol
#[derive(Debug, Default)]
pub struct VpcRoutingTable {
    pub(crate) rt: LpmMap<Arc<OvelayRoute>>,
    pub(crate) default_route: Option<OvelayRoute>,
}
impl VpcRoutingTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_default(&mut self, route: OvelayRoute) -> Result<(), VpcRoutingError> {
        if self.default_route.is_some() {
            return Err(VpcRoutingError::SingleDefault);
        }
        debug!("Set default overlay route to {route}");
        self.default_route = Some(route);
        Ok(())
    }

    pub fn insert_route(&mut self, route: Arc<OvelayRoute>) -> Result<(), VpcRoutingError> {
        let portrange = route.portrange.unwrap_or(PortRange::all_ports());
        self.rt.insert(route.prefix, portrange, route)?;
        self.rt.resolve_overlaps()?;
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = (Prefix, &OvelayRoute)> {
        self.rt.iter().flat_map(|(prefix, rangeset)| {
            rangeset
                .iter()
                .map(move |(_first, _last, route)| (prefix, route.as_ref()))
        })
    }

    #[must_use]
    pub fn lookup(&self, dst_addr: IpAddr, dst_port: Option<NonZero<u16>>) -> Option<&OvelayRoute> {
        let dst_port = dst_port.unwrap_or_else(|| unsafe { NonZero::new_unchecked(1) });
        let route = self
            .rt
            .lookup(dst_addr, dst_port)
            .map(std::convert::AsRef::as_ref);
        if route.is_none() {
            self.default_route.as_ref()
        } else {
            route
        }
    }
}

/* later optimization
fn proto2index(proto: NextHeader) -> u8 {
    match proto {
        NextHeader::TCP => 0,
        NextHeader::UDP => 1,
        _ => 2
    }
}

#[derive(Default, Debug)]
pub struct VpcRib {
    rt_tables: ArrayVec<Arc<VpcRoutingTable>,3>,
    egress_policy: EgressVpcPolicy
}
 */

/// A table of `VpcRoutingTable`s
#[derive(Debug)]
pub struct IngressMap(HashMap<IngressKey, VpcRoutingTable, RandomState>);

impl Default for IngressMap {
    fn default() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
}

impl IngressMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_route(
        &mut self,
        src_vpcd: VpcDiscriminant,
        route: &Arc<OvelayRoute>,
    ) -> Result<(), VpcRoutingError> {
        // proto is mandatory if ports are provided
        if route.portrange.is_some() && route.proto.is_none() {
            return Err(VpcRoutingError::InvalidRoute);
        }
        // proto is mandatory with port-forwarding. We leave ports optional. If unspecified, all ports
        if route.action == Action::PortForward && route.proto.is_none() {
            return Err(VpcRoutingError::InvalidRoute);
        }
        // if no proto is indicated, inject routes for UDP and TCP
        if route.proto.is_none() {
            let key = IngressKey::new(src_vpcd, Some(NextHeader::TCP));
            self.0.entry(key).or_default().insert_route(route.clone())?;
            let key = IngressKey::new(src_vpcd, Some(NextHeader::UDP));
            self.0.entry(key).or_default().insert_route(route.clone())?;
        }
        let key = IngressKey::new(src_vpcd, route.proto);
        self.0.entry(key).or_default().insert_route(route.clone())?;
        Ok(())
    }

    pub fn set_default(
        &mut self,
        src_vpcd: VpcDiscriminant,
        route: OvelayRoute,
    ) -> Result<(), VpcRoutingError> {
        debug!("Setting default route for VPC {src_vpcd} to {route}");
        let key = IngressKey::new(src_vpcd, None);
        self.0.entry(key).or_default().set_default(route)
    }

    #[must_use]
    pub fn lookup(
        &self,
        src_vpcd: VpcDiscriminant,
        proto: NextHeader,
        dst_addr: IpAddr,
        dst_port: Option<NonZero<u16>>,
    ) -> Option<&OvelayRoute> {
        debug!("Looking up routing table for for src_vpcd: {src_vpcd} proto: {proto}");
        let key = if proto == NextHeader::UDP || proto == NextHeader::TCP {
            IngressKey::new(src_vpcd, Some(proto))
        } else {
            IngressKey::new(src_vpcd, None)
        };
        let table = self.0.get(&key)?;
        debug!("Looking up route for {dst_addr} port:{dst_port:?} in table for {src_vpcd}");
        table.lookup(dst_addr, dst_port)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&IngressKey, &VpcRoutingTable)> {
        self.0.iter()
    }
}

/* Policy */

#[derive(Debug, Clone, Copy)]
pub struct PrefixPolicy {
    pub(crate) action: Action,
}
impl PrefixPolicy {
    #[must_use]
    pub fn new(action: Action) -> Self {
        Self { action }
    }
}

#[derive(Default, Debug, Clone)]
pub struct PeerMap(HashMap<VpcDiscriminant, PrefixPolicy, RandomState>);
impl PeerMap {
    pub fn insert(&mut self, dst_vpcd: VpcDiscriminant, action: Action) {
        self.0.insert(dst_vpcd, PrefixPolicy::new(action));
    }
    #[must_use]
    pub fn lookup_policy(&self, dst_vpcd: VpcDiscriminant) -> Option<&PrefixPolicy> {
        self.0.get(&dst_vpcd)
    }
    pub fn iter(&self) -> impl Iterator<Item = (VpcDiscriminant, &PrefixPolicy)> {
        self.0.iter().map(|(d, policy)| (*d, policy))
    }
}

/// The egress VPC policy for a VPC across all of its peerings
#[derive(Default, Debug, Clone)]
pub struct EgressVpcPolicy(pub(crate) IpPrefixTrie<PeerMap>);

impl EgressVpcPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn inherit(&mut self) {
        let original = self.clone();
        for (prefix, peermap) in self.0.iter_mut() {
            for (matched, matched_peermap) in original.0.matching_entries(prefix.network()) {
                if matched.length() < prefix.length() {
                    for (discr, policy) in matched_peermap.iter() {
                        peermap.insert(discr, policy.action);
                    }
                }
            }
        }
    }
    pub fn add(&mut self, prefix: Prefix, dst_vpcd: VpcDiscriminant, action: Action) {
        if let Some(peer_map) = self.0.get_mut(prefix) {
            peer_map.insert(dst_vpcd, action);
        } else {
            let mut peer_map = PeerMap::default();
            peer_map.insert(dst_vpcd, action);
            self.0.insert(prefix, peer_map);
        }
        self.inherit();
    }
    pub fn lookup(
        &self,
        address: IpAddr,
        dst_vpcd: VpcDiscriminant,
    ) -> Option<(Prefix, &PrefixPolicy)> {
        let (prefix, peer_map) = self.0.lookup(address)?;
        let policy = peer_map.lookup_policy(dst_vpcd)?;
        Some((prefix, policy))
    }
}

#[derive(Default)]
pub struct EgressVpcPolicyMap(HashMap<VpcDiscriminant, EgressVpcPolicy, RandomState>);
impl EgressVpcPolicyMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn iter(&self) -> impl Iterator<Item = (VpcDiscriminant, &EgressVpcPolicy)> {
        self.0.iter().map(|(vpcd, policy)| (*vpcd, policy))
    }
    pub fn insert(
        &mut self,
        src_vpcd: VpcDiscriminant,
        prefix: Prefix,
        dst_vpcd: VpcDiscriminant,
        action: Action,
    ) {
        self.0
            .entry(src_vpcd)
            .or_default()
            .add(prefix, dst_vpcd, action);
    }

    #[must_use]
    pub fn lookup(
        &self,
        src_vpcd: VpcDiscriminant,
        src_addr: IpAddr,
        dst_vpcd: VpcDiscriminant,
    ) -> Option<(Prefix, &PrefixPolicy)> {
        self.0
            .get(&src_vpcd)
            .and_then(|policy| policy.lookup(src_addr, dst_vpcd))
    }
}

#[derive(Default)]
pub struct OverlayRouting {
    #[allow(unused)]
    pub(crate) genid: GenId,
    pub(crate) imap: IngressMap, // routing map
    pub(crate) emap: EgressVpcPolicyMap,
}
impl OverlayRouting {
    #[must_use]
    pub fn new(genid: GenId, imap: IngressMap, emap: EgressVpcPolicyMap) -> Self {
        Self { genid, imap, emap }
    }

    pub fn lookup(&self, s: &PacketSummary) -> Option<(VpcDiscriminant, Action, Action)> {
        let Some(route) = self
            .imap
            .lookup(s.src_vpcd, s.proto, s.dst_addr, s.dst_port)
        else {
            debug!("Found no overlay route to process packet: {s}");
            return None;
        };
        let Some((prefix, policy)) = self.emap.lookup(s.src_vpcd, s.src_addr, route.dst_vpcd)
        else {
            debug!(
                "No peering of VPC {} allows packet: {s} to {}",
                s.src_vpcd, route.dst_vpcd
            );
            return None;
        };
        debug!(
            "Packet {s} comes from {prefix} of VPC {}. Should send to VPC {}",
            s.src_vpcd, route.dst_vpcd
        );
        Some((route.dst_vpcd, policy.action, route.action))
    }
}

pub struct PacketSummary {
    pub(crate) src_vpcd: VpcDiscriminant,
    pub(crate) src_addr: IpAddr,
    pub(crate) dst_addr: IpAddr,
    pub(crate) proto: NextHeader,
    pub(crate) src_port: Option<NonZero<u16>>,
    pub(crate) dst_port: Option<NonZero<u16>>,
}
