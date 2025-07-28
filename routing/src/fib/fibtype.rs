// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fib implementation for IP packet lookups

#![allow(clippy::collapsible_if)]

use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::rc::Rc;

use lpm::prefix::{Ipv4Prefix, Ipv6Prefix, Prefix};
use lpm::trie::{PrefixMapTrie, TrieMap, TrieMapFactory};
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use net::vxlan::Vni;

use crate::evpn::Vtep;
use crate::fib::fibobjects::{FibEntry, FibGroup, PktInstruction};
use crate::rib::vrf::VrfId;

use tracing::{debug, info, warn};

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
    version: u64,
    routesv4: PrefixMapTrie<Ipv4Prefix, Rc<FibGroup>>,
    routesv6: PrefixMapTrie<Ipv6Prefix, Rc<FibGroup>>,
    groups: BTreeSet<Rc<FibGroup>>, /* shared fib groups */
    vtep: Vtep,
}

pub type FibGroupV4Filter = Box<dyn Fn(&(&Ipv4Prefix, &Rc<FibGroup>)) -> bool>;
pub type FibGroupV6Filter = Box<dyn Fn(&(&Ipv6Prefix, &Rc<FibGroup>)) -> bool>;

impl Fib {
    /// the default fibgroup for default routes
    #[must_use]
    pub fn drop_fibgroup() -> FibGroup {
        FibGroup::with_entry(FibEntry::with_inst(PktInstruction::Drop))
    }

    #[must_use]
    pub fn new(id: FibId) -> Self {
        let routesv4 = PrefixMapTrie::create();
        let routesv6 = PrefixMapTrie::create();
        let mut fib = Self {
            id,
            version: 0,
            routesv4,
            routesv6,
            groups: BTreeSet::new(),
            vtep: Vtep::new(),
        };

        // Adding groups to the fib makes the above unsafe calls safe
        let group = Self::drop_fibgroup();
        fib.add_fibgroup(Prefix::root_v4(), group.clone());
        fib.add_fibgroup(Prefix::root_v6(), group);
        fib
    }

    #[must_use]
    /// Get the [`FibId`] for this [`Fib`]
    pub fn get_id(&self) -> FibId {
        self.id
    }

    /// Add a [`FibGroup`] to a prefix
    pub fn add_fibgroup(&mut self, prefix: Prefix, group: FibGroup) -> Option<Rc<FibGroup>> {
        let rc_group = self.store_group(group);
        match prefix {
            Prefix::IPV4(p) => self.routesv4.insert(p, rc_group),
            Prefix::IPV6(p) => self.routesv6.insert(p, rc_group),
        }
    }

    /// Remove a [`FibGroup`] from a prefix
    pub fn del_fibgroup(&mut self, prefix: Prefix) {
        match prefix {
            Prefix::IPV4(p4) => {
                if p4 == Ipv4Prefix::default() {
                    if let Some(prior) = self.add_fibgroup(Prefix::root_v4(), Self::drop_fibgroup())
                    {
                        self.unstore_group(&prior);
                    }
                } else if let Some(group) = self.routesv4.remove(&p4) {
                    self.unstore_group(&group);
                }
            }
            Prefix::IPV6(p6) => {
                if p6 == Ipv6Prefix::default() {
                    if let Some(prior) = self.add_fibgroup(Prefix::root_v6(), Self::drop_fibgroup())
                    {
                        self.unstore_group(&prior);
                    }
                } else if let Some(group) = self.routesv6.remove(&p6) {
                    self.unstore_group(&group);
                }
            }
        }
    }

    /// Store a new [`FibGroup`], without creating it if an identical group exists.
    #[must_use]
    pub fn store_group(&mut self, group: FibGroup) -> Rc<FibGroup> {
        let rc_gr = Rc::new(group);
        if let Some(e) = self.groups.get(&rc_gr) {
            Rc::clone(e)
        } else {
            self.groups.insert(Rc::clone(&rc_gr));
            rc_gr
        }
    }

    /// Remove a [`FibGroup`] from the shared groups
    pub fn unstore_group(&mut self, group: &FibGroup) {
        self.groups.remove(group);
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
        self.groups.len()
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Iterate over IPv4 routes/entries
    pub fn iter_v4(&self) -> impl Iterator<Item = (&Ipv4Prefix, &Rc<FibGroup>)> {
        self.routesv4.iter()
    }

    /// Iterate over IPv6 routes/entries
    pub fn iter_v6(&self) -> impl Iterator<Item = (&Ipv6Prefix, &Rc<FibGroup>)> {
        self.routesv6.iter()
    }

    /// Iterate over [`FibGroup`]s
    pub fn group_iter(&self) -> impl Iterator<Item = &Rc<FibGroup>> {
        self.groups.iter()
    }

    #[must_use]
    /// Get a reference to the inner IPv4 trie
    pub fn get_v4_trie(&self) -> &PrefixMapTrie<Ipv4Prefix, Rc<FibGroup>> {
        &self.routesv4
    }

    #[must_use]
    /// Get a reference to the inner IPv6 trie
    pub fn get_v6_trie(&self) -> &PrefixMapTrie<Ipv6Prefix, Rc<FibGroup>> {
        &self.routesv6
    }

    /// Do lpm lookup with the given `IpAddr`
    #[must_use]
    pub fn lpm_with_prefix(&self, target: &IpAddr) -> (Prefix, &FibGroup) {
        match target {
            IpAddr::V4(a) => {
                let (prefix, group) = self.routesv4.lookup(*a).unwrap_or_else(|| unreachable!());
                (Prefix::IPV4(*prefix), group)
            }
            IpAddr::V6(a) => {
                let (prefix, group) = self.routesv6.lookup(*a).unwrap_or_else(|| unreachable!());
                (Prefix::IPV6(*prefix), group)
            }
        }
    }
    /// Identical to `lpm_with_prefix`, but without reporting the prefix hit
    #[must_use]
    pub fn lpm(&self, target: &IpAddr) -> &FibGroup {
        match target {
            IpAddr::V4(a) => {
                let (_, group) = self.routesv4.lookup(*a).unwrap_or_else(|| unreachable!());
                group
            }
            IpAddr::V6(a) => {
                let (_, group) = self.routesv6.lookup(*a).unwrap_or_else(|| unreachable!());
                group
            }
        }
    }

    /// Given a [`Packet`], uses [`Self::lpm()`] to retrieve the [`FibGroup`] to forward a packet.
    /// However, instead of returning the entire [`FibGroup`], returns a single [`FibEntry`] selected
    /// by computing a hash on the invariant header fields of the IP and L4 headers.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn lpm_entry<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> Option<&FibEntry> {
        if let Some(destination) = packet.ip_destination() {
            let group = self.lpm(&destination);
            match group.len() {
                0 => {
                    warn!("Cannot forward packet: no fibgroups for route. This is a bug");
                    None
                }
                1 => Some(&group.entries()[0_usize]),
                k => {
                    debug!("Hashing pkt to choose one FibEntry out of {k}");
                    let entry_index = packet.packet_hash_ecmp(0, (k - 1) as u8);
                    Some(&group.entries()[entry_index as usize])
                }
            }
        } else {
            unreachable!()
        }
    }

    /// Same as `lpm_entry` but reporting prefix and, in case packet is tagged with vxlan vni,
    /// consider only next-hops for that vni.
    #[allow(clippy::cast_possible_truncation)]
    pub fn lpm_entry_prefix<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> (Prefix, Option<&FibEntry>) {
        if let Some(destination) = packet.ip_destination() {
            let (prefix, group) = self.lpm_with_prefix(&destination);
            match group.len() {
                0 => {
                    warn!("Can't forward packet: no groups for route to {prefix}");
                    (prefix, None)
                }
                1 => (prefix, Some(&group.entries()[0_usize])),
                k => {
                    debug!("Hashing pkt to choose one FibEntry out of {k}");
                    let entry_index = packet.packet_hash_ecmp(0, (k - 1) as u8);
                    (prefix, Some(&group.entries()[entry_index as usize]))
                }
            }
        } else {
            unreachable!()
        }
    }
}

#[derive(Debug)]
pub enum FibChange {
    AddFibGroup((Prefix, FibGroup)),
    DelFibGroup(Prefix),
    SetVtep(Vtep),
}

impl Absorb<FibChange> for Fib {
    fn absorb_first(&mut self, change: &mut FibChange, _: &Self) {
        self.version += 1; // FIXME: only update if s/t changed
        match change {
            FibChange::AddFibGroup((prefix, group)) => {
                if let Some(group) = self.add_fibgroup(*prefix, group.clone()) {
                    self.unstore_group(&group);
                }
            }
            FibChange::DelFibGroup(prefix) => self.del_fibgroup(*prefix),
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
    pub fn add_fibgroup(&mut self, prefix: Prefix, group: FibGroup, publish: bool) {
        self.0.append(FibChange::AddFibGroup((prefix, group)));
        if publish {
            self.0.publish();
        }
    }
    pub fn publish(&mut self) {
        self.0.publish();
    }
    pub fn del_fibgroup(&mut self, prefix: Prefix) {
        self.0.append(FibChange::DelFibGroup(prefix));
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
