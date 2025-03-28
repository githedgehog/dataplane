// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fib implementation for IP packet lookups

use iptrie::map::RTrieMap;
use iptrie::{Ipv4Prefix, Ipv6Prefix};
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use net::buffer::PacketBufferMut;
use net::packet::Packet;
use net::vxlan::Vni;

use crate::prefix::Prefix;
use crate::route_processor::{FibEntry, FibGroup, PktInstruction};
use crate::vrf::VrfId;
use tracing::debug;

#[derive(Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
/// An id we use to idenfify a FIB
pub enum FibId {
    Id(VrfId),
    Vni(Vni),
}
impl FibId {
    pub fn from_vrfid(vrfid: VrfId) -> Self {
        FibId::Id(vrfid)
    }
    pub fn from_vni(vni: Vni) -> Self {
        FibId::Vni(vni)
    }
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
    routesv4: RTrieMap<Ipv4Prefix, Arc<FibGroup>>,
    routesv6: RTrieMap<Ipv6Prefix, Arc<FibGroup>>,
    groups: BTreeSet<Arc<FibGroup>>, /* shared fib groups */
}

pub type FibGroupV4Filter = Box<dyn Fn(&(&Ipv4Prefix, &Arc<FibGroup>)) -> bool>;
pub type FibGroupV6Filter = Box<dyn Fn(&(&Ipv6Prefix, &Arc<FibGroup>)) -> bool>;

impl Fib {
    /// the default fibgroup for default routes
    pub fn drop_fibgroup() -> FibGroup {
        FibGroup::with_entry(FibEntry::with_inst(PktInstruction::Drop))
    }
    pub fn new(id: FibId) -> Self {
        let mut fib = Self {
            id,
            version: 0,
            routesv4: RTrieMap::new(),
            routesv6: RTrieMap::new(),
            groups: BTreeSet::new(),
        };
        let group = Self::drop_fibgroup();
        fib.add_fibgroup(Prefix::root_v4(), group.clone());
        fib.add_fibgroup(Prefix::root_v6(), group);
        fib
    }
    pub fn get_id(&self) -> &FibId {
        &self.id
    }
    pub fn add_fibgroup(&mut self, prefix: Prefix, group: FibGroup) {
        let gr_arc = self.store_group(group);
        match prefix {
            Prefix::IPV4(p) => self.routesv4.insert(p, gr_arc.clone()),
            Prefix::IPV6(p) => self.routesv6.insert(p, gr_arc),
        };
    }
    pub fn del_fibgroup(&mut self, prefix: Prefix) {
        match prefix {
            Prefix::IPV4(p4) => {
                if p4 == Ipv4Prefix::default() {
                    self.add_fibgroup(Prefix::root_v4(), Self::drop_fibgroup());
                } else if let Some(group) = self.routesv4.remove(&p4) {
                    if Arc::strong_count(&group) == 1 {
                        self.unstore_group(&group);
                    }
                }
            }
            Prefix::IPV6(p6) => {
                if p6 == Ipv6Prefix::default() {
                    self.add_fibgroup(Prefix::root_v6(), Self::drop_fibgroup());
                } else if let Some(group) = self.routesv6.remove(&p6) {
                    if Arc::strong_count(&group) == 1 {
                        self.unstore_group(&group);
                    }
                }
            }
        };
    }

    /// Add a new group, without creating it if an identical group exists.
    /// This method returns a reference that must be used.
    #[must_use]
    pub fn store_group(&mut self, group: FibGroup) -> Arc<FibGroup> {
        let arc_gr = Arc::new(group.clone());
        if let Some(e) = self.groups.get(&arc_gr) {
            Arc::clone(e)
        } else {
            self.groups.insert(arc_gr.clone());
            arc_gr
        }
    }
    /// Remove a group from the shared groups
    pub fn unstore_group(&mut self, group: &FibGroup) {
        self.groups.remove(group);
    }

    /// FibGroups are refcounted, owned by the Fib and shared by prefixes.
    /// Since they don't have an explicit Id, when no prefix refers to them
    /// they will get a refcount of 1. This method allows removing those unused
    /// fibgroups. This method is not currently used and should NOT be needed.
    pub fn purge(&mut self) {
        self.groups.retain(|group| Arc::strong_count(group) > 1);
    }

    pub fn len_v4(&self) -> usize {
        self.routesv4.len().get()
    }
    pub fn len_v6(&self) -> usize {
        self.routesv6.len().get()
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn iter_v4(&self) -> impl Iterator<Item = (&Ipv4Prefix, &Arc<FibGroup>)> {
        self.routesv4.iter()
    }
    pub fn iter_v6(&self) -> impl Iterator<Item = (&Ipv6Prefix, &Arc<FibGroup>)> {
        self.routesv6.iter()
    }
    pub fn get_v4_trie(&self) -> &RTrieMap<Ipv4Prefix, Arc<FibGroup>> {
        &self.routesv4
    }
    pub fn get_v6_trie(&self) -> &RTrieMap<Ipv6Prefix, Arc<FibGroup>> {
        &self.routesv6
    }
    /// Do lpm lookup with the given IpAddr
    pub fn lpm_with_prefix(&self, target: &IpAddr) -> (Prefix, &FibGroup) {
        match target {
            IpAddr::V4(a) => {
                let (prefix, group) = self.routesv4.lookup(a);
                (Prefix::IPV4(*prefix), group)
            }
            IpAddr::V6(a) => {
                let (prefix, group) = self.routesv6.lookup(a);
                (Prefix::IPV6(*prefix), group)
            }
        }
    }
    /// Identical to lpm_with_prefix, but without reporting the prefix hit
    pub fn lpm(&self, target: &IpAddr) -> &FibGroup {
        match target {
            IpAddr::V4(a) => {
                let (_, group) = self.routesv4.lookup(a);
                group
            }
            IpAddr::V6(a) => {
                let (_, group) = self.routesv6.lookup(a);
                group
            }
        }
    }

    /// Given a [`Packet`], uses [`Self::lpm()`] to retrieve the [`FibGroup`] to forward a packet.
    /// However, instead of returning the entire [`FibGroup`], returns a single [`FibEntry`] selected
    /// by computing a hash on the invariant header fields of the IP and L4 headers.
    pub fn lpm_entry<Buf: PacketBufferMut>(&self, packet: &Packet<Buf>) -> &FibEntry {
        if let Some(destination) = packet.ip_destination() {
            let group = self.lpm(&destination);
            let entry_index = if group.len() == 1 {
                0
            } else {
                debug!(
                    "Hashing packet to determine one FibEntry out of {}",
                    group.len()
                );
                packet.packet_hash_ecmp(0, (group.len() - 1) as u8)
            };
            &group.entries()[entry_index as usize]
        } else {
            unreachable!()
        }
    }

    /// Same as lpm_entry but reporting prefix
    pub fn lpm_entry_prefix<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> (Prefix, &FibEntry) {
        if let Some(destination) = packet.ip_destination() {
            let (prefix, group) = self.lpm_with_prefix(&destination);
            let entry_index = if group.len() == 1 {
                0
            } else {
                debug!(
                    "Hashing packet to determine one FibEntry out of {}",
                    group.len()
                );
                packet.packet_hash_ecmp(0, (group.len() - 1) as u8)
            };
            (prefix, &group.entries()[entry_index as usize])
        } else {
            unreachable!()
        }
    }
}

#[derive(Debug)]
pub enum FibGroupChange {
    AddFibGroup((Prefix, FibGroup)),
    DelFibGroup(Prefix),
}

impl Absorb<FibGroupChange> for Fib {
    fn absorb_first(&mut self, change: &mut FibGroupChange, _: &Self) {
        self.version += 1; // FIXME: only update if s/t changed
        match change {
            FibGroupChange::AddFibGroup((prefix, group)) => {
                self.add_fibgroup(prefix.clone(), group.clone())
            }
            FibGroupChange::DelFibGroup(prefix) => self.del_fibgroup(prefix.clone()),
        };
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone()
    }
}

pub struct FibWriter(WriteHandle<Fib, FibGroupChange>);
impl FibWriter {
    /// create a fib, providing a writer and a reader
    pub fn new(id: FibId) -> (FibWriter, FibReader) {
        let (w, r) = left_right::new_from_empty::<Fib, FibGroupChange>(Fib::new(id.clone()));
        (FibWriter(w), FibReader(r))
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, Fib>> {
        self.0.enter()
    }
    pub fn get_id(&self) -> Option<FibId> {
        self.0.enter().map(|fib| fib.get_id().clone())
    }
    pub fn add_fibgroup(&mut self, prefix: Prefix, group: FibGroup) {
        self.0.append(FibGroupChange::AddFibGroup((prefix, group)));
        self.0.publish();
    }
    pub fn del_fibgroup(&mut self, prefix: Prefix) {
        self.0.append(FibGroupChange::DelFibGroup(prefix));
        self.0.publish();
    }
    pub fn as_fibreader(&self) -> FibReader {
        FibReader::new(self.0.clone())
    }
}

#[derive(Clone, Debug)]
pub struct FibReader(ReadHandle<Fib>);
impl FibReader {
    pub fn new(rhandle: ReadHandle<Fib>) -> Self {
        FibReader(rhandle)
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, Fib>> {
        self.0.enter()
    }
    pub fn get_id(&self) -> Option<FibId> {
        self.0.enter().map(|fib| fib.get_id().clone())
    }
}
