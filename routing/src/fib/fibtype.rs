// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fib implementation for IP packet lookups

#![allow(clippy::collapsible_if)]

use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use std::net::IpAddr;

use lpm::prefix::{Ipv4Prefix, Ipv6Prefix, Prefix};
use lpm::trie::{PrefixMapTrie, TrieMap, TrieMapFactory};
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use net::vxlan::Vni;

use crate::evpn::Vtep;
use crate::fib::fibgroupstore::{FibGroupStore, FibRoute};
use crate::fib::fibobjects::{FibEntry, FibGroup};
use crate::rib::nexthop::NhopKey;
use crate::rib::vrf::VrfId;

#[allow(unused)]
use tracing::{debug, error, info, warn};

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
/// An id we use to idenfify a FIB
pub enum FibId {
    Id(VrfId),
    Vni(Vni),
}
impl FibId {
    #[must_use]
    pub fn from_vrfid(vrfid: VrfId) -> Self {
        FibId::Id(vrfid)
    }
    #[must_use]
    pub fn from_vni(vni: Vni) -> Self {
        FibId::Vni(vni)
    }
    #[must_use]
    pub fn as_u32(&self) -> u32 {
        match self {
            FibId::Id(value) => *value,
            FibId::Vni(value) => value.as_u32(),
        }
    }
}

#[derive(Clone)]
pub struct Fib {
    id: FibId,
    routesv4: PrefixMapTrie<Ipv4Prefix, FibRoute>,
    routesv6: PrefixMapTrie<Ipv6Prefix, FibRoute>,
    groupstore: FibGroupStore,
    vtep: Vtep,
}

pub type FibRouteV4Filter = Box<dyn Fn(&(&Ipv4Prefix, &FibRoute)) -> bool>;
pub type FibRouteV6Filter = Box<dyn Fn(&(&Ipv6Prefix, &FibRoute)) -> bool>;

impl Fib {
    #[must_use]
    pub fn new(id: FibId) -> Self {
        let mut fib = Self {
            id,
            routesv4: PrefixMapTrie::create(),
            routesv6: PrefixMapTrie::create(),
            groupstore: FibGroupStore::new(),
            vtep: Vtep::new(),
        };
        // default route
        let route = FibRoute::with_fibgroup(fib.groupstore.get_drop_fibgroup_ref());
        fib.add_fibroute(Prefix::root_v4(), route.clone());
        fib.add_fibroute(Prefix::root_v6(), route);
        fib
    }

    #[must_use]
    /// Get the [`FibId`] for this [`Fib`]
    pub fn get_id(&self) -> FibId {
        self.id
    }

    /// Add a [`FibRoute`]
    fn add_fibroute(&mut self, prefix: Prefix, route: FibRoute) -> Option<FibRoute> {
        match prefix {
            Prefix::IPV4(p) => self.routesv4.insert(p, route),
            Prefix::IPV6(p) => self.routesv6.insert(p, route),
        }
    }

    /// Add a [`FibRoute`]
    fn build_add_fibroute(&mut self, prefix: Prefix, keys: &[NhopKey]) {
        let Ok(route) = FibRoute::from_nhopkeys(&self.groupstore, keys) else {
            error!("Failed to build fibroute for keys {keys:#?}");
            return;
        };
        self.add_fibroute(prefix, route);
    }

    /// Delete the [`FibRoute`] for a prefix
    fn del_fibroute(&mut self, prefix: Prefix) {
        match prefix {
            Prefix::IPV4(p4) => {
                if p4 == Ipv4Prefix::default() {
                    let route = FibRoute::with_fibgroup(self.groupstore.get_drop_fibgroup_ref());
                    if let Some(_prior) = self.add_fibroute(Prefix::root_v4(), route) {
                        // TODO: n.b. route increases refct of drop - that's ok
                    }
                } else {
                    self.routesv4.remove(&p4);
                }
            }
            Prefix::IPV6(p6) => {
                if p6 == Ipv6Prefix::default() {
                    let route = FibRoute::with_fibgroup(self.groupstore.get_drop_fibgroup_ref());
                    if let Some(_prior) = self.add_fibroute(Prefix::root_v6(), route) {}
                } else {
                    self.routesv6.remove(&p6);
                }
            }
        }
        self.groupstore.purge();
    }

    /// Set the [`Vtep`] for this [`Fib`]
    pub fn set_vtep(&mut self, vtep: &Vtep) {
        self.vtep = vtep.clone();
        let id = self.get_id();
        let ip = self
            .vtep
            .get_ip()
            .map(|a| a.to_string())
            .unwrap_or("none".to_owned());
        let mac = self
            .vtep
            .get_mac()
            .map(|a| a.to_string())
            .unwrap_or("none".to_owned());
        info!("VTEP for fib {id} set to ip:{ip} mac:{mac}");
    }

    /// Get the [`Vtep`] for this [`Fib`]
    pub fn get_vtep(&self) -> &Vtep {
        &self.vtep
    }

    /// Tell the number of IPv4 routes in this [`Fib`]
    #[must_use]
    pub fn len_v4(&self) -> usize {
        self.routesv4.len()
    }

    /// Tell the number of IPv6 routes in this [`Fib`]
    #[must_use]
    pub fn len_v6(&self) -> usize {
        self.routesv6.len()
    }

    /// Tell the number of [`FibGroup`] routes in this [`Fib`]
    #[must_use]
    pub fn len_groups(&self) -> usize {
        self.groupstore.len()
    }

    /// Iterate over IPv4 routes/entries
    pub fn iter_v4(&self) -> impl Iterator<Item = (&Ipv4Prefix, &FibRoute)> {
        self.routesv4.iter()
    }

    /// Iterate over IPv6 routes/entries
    pub fn iter_v6(&self) -> impl Iterator<Item = (&Ipv6Prefix, &FibRoute)> {
        self.routesv6.iter()
    }

    /// Iterate over [`FibGroup`]s
    pub fn group_iter(&self) -> impl Iterator<Item = &FibGroup> {
        self.groupstore.values()
    }

    #[must_use]
    /// Get a reference to the inner IPv4 trie
    pub fn get_v4_trie(&self) -> &PrefixMapTrie<Ipv4Prefix, FibRoute> {
        &self.routesv4
    }

    #[must_use]
    /// Get a reference to the inner IPv6 trie
    pub fn get_v6_trie(&self) -> &PrefixMapTrie<Ipv6Prefix, FibRoute> {
        &self.routesv6
    }

    /// Do lpm lookup for the given `IpAddr`
    #[must_use]
    pub fn lpm_with_prefix(&self, target: &IpAddr) -> (Prefix, &FibRoute) {
        match target {
            IpAddr::V4(a) => {
                let (prefix, route) = self.routesv4.lookup(*a).unwrap_or_else(|| unreachable!());
                (Prefix::IPV4(*prefix), route)
            }
            IpAddr::V6(a) => {
                let (prefix, route) = self.routesv6.lookup(*a).unwrap_or_else(|| unreachable!());
                (Prefix::IPV6(*prefix), route)
            }
        }
    }

    /// Identical to `lpm_with_prefix`, but without reporting the prefix hit
    #[must_use]
    pub fn lpm(&self, target: &IpAddr) -> &FibRoute {
        let (_, route) = self.lpm_with_prefix(target);
        route
    }

    /// Given a [`Packet`], uses [`Self::lpm()`] to retrieve the [`FibRoute`] to forward a packet.
    /// However, instead of returning the entire [`FibRoute`], returns a single [`FibEntry`] out of
    /// those in the `FibGroup`s that make up the [`FibRoute`]. The entry selected is chosen by
    /// computing a hash on the invariant header fields of the IP and L4 headers.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn lpm_entry<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<&FibEntry> {
        let (_, entry) = self.lpm_entry_prefix(packet);
        entry
    }

    /// Same as `lpm_entry` but reporting prefix
    #[allow(clippy::cast_possible_truncation)]
    pub fn lpm_entry_prefix<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> (Prefix, Option<&FibEntry>) {
        if let Some(destination) = packet.ip_destination() {
            let (prefix, route) = self.lpm_with_prefix(&destination);
            match route.len() {
                0 => {
                    warn!("Can't forward packet: no route to {prefix}. This is a bug.");
                    (prefix, None)
                }
                1 => (prefix, route.get_fibentry(0)),
                k => {
                    let entry_index = packet.packet_hash_ecmp(0, (k - 1) as u8);
                    debug!("Selected FibEntry {entry_index}/{k} to forward packet");
                    (prefix, route.get_fibentry(entry_index as usize))
                }
            }
        } else {
            error!("Failed to get destination IP address!");
            unreachable!()
        }
    }
}

#[derive(Debug)]
pub enum FibChange {
    RegisterFibGroup((NhopKey, FibGroup)),
    AddFibRoute((Prefix, Vec<NhopKey>)),
    DelFibRoute(Prefix),
    SetVtep(Vtep),
}

impl Absorb<FibChange> for Fib {
    fn absorb_first(&mut self, change: &mut FibChange, _: &Self) {
        match change {
            FibChange::RegisterFibGroup((key, fibgroup)) => {
                self.groupstore.add_mod_group(key, fibgroup.clone())
            }
            FibChange::AddFibRoute((prefix, keys)) => self.build_add_fibroute(*prefix, keys),
            FibChange::DelFibRoute(prefix) => self.del_fibroute(*prefix),
            FibChange::SetVtep(vtep) => self.set_vtep(vtep),
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

pub struct FibWriter(WriteHandle<Fib, FibChange>);
impl FibWriter {
    /// create a fib, providing a writer and a reader
    #[must_use]
    pub fn new(id: FibId) -> (FibWriter, FibReader) {
        let (w, r) = left_right::new_from_empty::<Fib, FibChange>(Fib::new(id));
        (FibWriter(w), FibReader(r))
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, Fib>> {
        self.0.enter()
    }
    #[must_use]
    pub fn get_id(&self) -> Option<FibId> {
        self.0.enter().map(|fib| fib.get_id())
    }
    pub fn register_fibgroup(&mut self, key: &NhopKey, fibgroup: &FibGroup, publish: bool) {
        self.0
            .append(FibChange::RegisterFibGroup((key.clone(), fibgroup.clone())));
        if publish {
            self.0.publish();
        }
    }
    pub fn add_fibroute(&mut self, prefix: Prefix, keys: Vec<NhopKey>, publish: bool) {
        self.0.append(FibChange::AddFibRoute((prefix, keys)));
        if publish {
            self.0.publish();
        }
    }
    pub fn del_fibroute(&mut self, prefix: Prefix) {
        self.0.append(FibChange::DelFibRoute(prefix));
        self.0.publish();
    }
    pub fn set_vtep(&mut self, vtep: Vtep) {
        self.0.append(FibChange::SetVtep(vtep));
        self.0.publish();
    }
    pub fn get_vtep(&self) -> Vtep {
        let fib = self.enter().unwrap_or_else(|| unreachable!());
        fib.vtep.clone()
    }
    pub fn publish(&mut self) {
        self.0.publish();
    }
    #[must_use]
    pub fn as_fibreader(&self) -> FibReader {
        FibReader::new(self.0.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FibReader(ReadHandle<Fib>);
impl FibReader {
    #[must_use]
    pub fn new(rhandle: ReadHandle<Fib>) -> Self {
        FibReader(rhandle)
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, Fib>> {
        self.0.enter()
    }
    pub fn get_id(&self) -> Option<FibId> {
        self.0.enter().map(|fib| fib.get_id())
    }
}
