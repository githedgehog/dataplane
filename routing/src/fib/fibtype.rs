// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fib implementation for IP packet lookups

use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle};
use left_right_tlcache::Identity;
use std::hash::Hash;
use std::net::IpAddr;
use std::rc::Rc;

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
use tracing::{debug, error, info, trace, warn};

#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
// A type used to access a [`Fib`] or to identify it.
// As an identifier, only the variant `FibKey::Id` is allowed.
pub enum FibKey {
    Id(VrfId),
    Vni(Vni),
}
impl FibKey {
    #[must_use]
    pub fn from_vrfid(vrfid: VrfId) -> Self {
        FibKey::Id(vrfid)
    }
    #[must_use]
    pub fn from_vni(vni: Vni) -> Self {
        FibKey::Vni(vni)
    }
    #[must_use]
    pub fn as_u32(&self) -> u32 {
        match self {
            FibKey::Id(value) => *value,
            FibKey::Vni(value) => value.as_u32(),
        }
    }
}

pub struct Fib {
    /// `None` only between `Fib::default` and `FibWriter::new` setting it.
    ///
    /// A fib is always created for a vrf; a [`FibKey::Vni`] is an alias the fib *table* holds
    /// pointing at one, never a fib's own identity. Naming the narrower type here is what keeps
    /// that out of [`FibKey`], which every lookup has to match on.
    id: Option<VrfId>,
    routesv4: PrefixMapTrie<Ipv4Prefix, FibRoute>,
    routesv6: PrefixMapTrie<Ipv6Prefix, FibRoute>,
    groupstore: FibGroupStore,
    vtep: Vtep,
    valid: bool,
}
impl Hash for Fib {
    // We implement explicitly `std::hash::Hash` for `Fib` instead of deriving it because:
    //  - this avoids the need to implement/derive it for all internal components
    //  - it is actually not possible to do so since some types are defined externally (prefixes)
    //  - the Id suffices to identify them and the implementation is possibly faster.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
impl Identity<FibKey> for Fib {
    fn identity(&self) -> FibKey {
        self.get_id()
    }
}
impl Default for Fib {
    fn default() -> Self {
        let mut fib = Self {
            id: None,
            routesv4: PrefixMapTrie::create(),
            routesv6: PrefixMapTrie::create(),
            groupstore: FibGroupStore::new(),
            vtep: Vtep::new(),
            valid: true,
        };
        // default route
        let route = FibRoute::with_fibgroup(fib.groupstore.get_drop_fibgroup_ref());
        fib.add_fibroute(Prefix::root_v4(), route.clone());
        fib.add_fibroute(Prefix::root_v6(), route);
        fib
    }
}

pub type FibRouteV4Filter = Box<dyn Fn(&(Ipv4Prefix, &FibRoute)) -> bool>;
pub type FibRouteV6Filter = Box<dyn Fn(&(Ipv6Prefix, &FibRoute)) -> bool>;

impl Fib {
    /// Set the id for this [`Fib`]
    fn set_id(&mut self, vrfid: VrfId) {
        self.id = Some(vrfid);
    }

    #[must_use]
    /// Get the id for this [`Fib`]
    pub fn get_id(&self) -> FibKey {
        let Some(vrfid) = self.id else {
            error!("Hit fib whose id was never set");
            unreachable!()
        };
        FibKey::Id(vrfid)
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
        if keys.is_empty() {
            error!("Rejecting fibroute creation: no keys provided");
            return;
        }
        match FibRoute::from_nhopkeys(&self.groupstore, keys) {
            Ok(route) => {
                debug_assert!(route.len() > 0);
                self.add_fibroute(prefix, route);
            }
            Err(e) => error!("Failed to build fibroute for keys {keys:#?}: {e}"),
        }
    }

    /// Delete the [`FibRoute`] for a prefix
    fn del_fibroute(&mut self, prefix: Prefix) {
        let removed = match prefix {
            Prefix::IPV4(p4) => {
                if p4 == Ipv4Prefix::default() {
                    let route = FibRoute::with_fibgroup(self.groupstore.get_drop_fibgroup_ref());
                    self.add_fibroute(Prefix::root_v4(), route)
                } else {
                    self.routesv4.remove(p4)
                }
            }
            Prefix::IPV6(p6) => {
                if p6 == Ipv6Prefix::default() {
                    let route = FibRoute::with_fibgroup(self.groupstore.get_drop_fibgroup_ref());
                    self.add_fibroute(Prefix::root_v6(), route)
                } else {
                    self.routesv6.remove(p6)
                }
            }
        };
        if removed.is_some() {
            // here, we could iterate over the fibgroups of the removed route. However, in order to remove it
            // from the group store, we'd need the key which we don't have. We could lookup the elements in the
            // store matching each of the fibgroups (addresses) the route had, but it is simpler and probably
            // faster to just purge. Since we still keep a ref to the removed route, let's make sure we drop
            // it before we purge, so that it's references are gone before!
            drop(removed);
            self.groupstore.purge();
        }
    }

    /// Set the [`Vtep`] for this [`Fib`]
    fn set_vtep(&mut self, vtep: &Vtep) {
        self.vtep = vtep.clone();
        let id = self.get_id();
        let ip = self
            .vtep
            .get_ip()
            .map_or("none".to_owned(), |a| a.to_string());

        let mac = self
            .vtep
            .get_mac()
            .map_or("none".to_owned(), |a| a.to_string());
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
    pub fn iter_v4(&self) -> impl Iterator<Item = (Ipv4Prefix, &FibRoute)> {
        self.routesv4.iter()
    }

    /// Iterate over IPv6 routes/entries
    pub fn iter_v6(&self) -> impl Iterator<Item = (Ipv6Prefix, &FibRoute)> {
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
                (Prefix::IPV4(prefix), route)
            }
            IpAddr::V6(a) => {
                let (prefix, route) = self.routesv6.lookup(*a).unwrap_or_else(|| unreachable!());
                (Prefix::IPV6(prefix), route)
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
    /// # Panics
    ///
    /// This function panics if a route does not have any entries
    #[allow(clippy::cast_possible_truncation)]
    pub fn lpm_entry_prefix<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> (Prefix, &FibEntry) {
        if let Some(destination) = packet.ip_destination() {
            let (prefix, route) = self.lpm_with_prefix(&destination);
            let num_entries = route.len();
            if num_entries == 0 {
                let bad = "Warning, hit route without fibgroups/entries. This is a bug.";
                warn!("{bad}");
                panic!("{bad}");
            }
            let mut entry_index = 0;
            if num_entries > 1 {
                entry_index = packet.packet_hash_ecmp(0, (num_entries - 1) as u8);
            }
            (prefix, route.get_fibentry(entry_index as usize))
        } else {
            error!("Failed to get destination IP address!");
            unreachable!()
        }
    }
}

#[derive(Debug)]
enum FibChange {
    RegisterFibGroup((NhopKey, FibGroup)),
    UnregisterFibGroup(NhopKey),
    AddFibRoute((Prefix, Vec<NhopKey>)),
    DelFibRoute(Prefix),
    SetVtep(Vtep),
    Invalidate,
}

impl Absorb<FibChange> for Fib {
    fn absorb_first(&mut self, change: &mut FibChange, _: &Self) {
        match change {
            FibChange::RegisterFibGroup((key, fibgroup)) => {
                self.groupstore.add_mod_group(key, fibgroup.clone());
            }
            FibChange::UnregisterFibGroup(key) => {
                self.groupstore.del(key);
            }
            FibChange::AddFibRoute((prefix, keys)) => self.build_add_fibroute(*prefix, keys),
            FibChange::DelFibRoute(prefix) => self.del_fibroute(*prefix),
            FibChange::SetVtep(vtep) => self.set_vtep(vtep),
            FibChange::Invalidate => self.valid = false,
        }
    }
    fn sync_with(&mut self, first: &Self) {
        assert!(self.id.is_some());
        assert_eq!(self.id, first.id);
        debug!("Internal LR state for fib {} is now synced", self.get_id());
    }
}

pub struct FibWriter(WriteHandle<Fib, FibChange>);
impl FibWriter {
    /// create a fib, providing a writer and a reader
    #[must_use]
    pub fn new(vrfid: VrfId) -> (FibWriter, FibReader) {
        let (mut w, r) = left_right::new::<Fib, FibChange>();
        // `left_right::new` builds both copies from `Fib::default`, which cannot know the id;
        // `new_from_empty` would take a built one but wants `Clone`, which a `Fib` must not have
        // (its `FibGroupStore` holds `Rc`s the two copies may not share). So set it on both.
        unsafe {
            // It is safe to call raw_handle() and raw_write_handle() here
            let fib_rcopy = r.raw_handle().unwrap_or_else(|| unreachable!()).as_mut();
            let fib_wcopy = w.raw_write_handle().as_mut();
            fib_rcopy.set_id(vrfid);
            fib_wcopy.set_id(vrfid);
            // this is needed to avoid needing to clone the fib
            w.publish();
        }
        info!("Created Fib with id {vrfid}");
        (FibWriter(w), FibReader(r))
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, Fib>> {
        self.0.enter()
    }
    pub fn register_fibgroup(&mut self, key: &NhopKey, fibgroup: &FibGroup, publish: bool) {
        self.0
            .append(FibChange::RegisterFibGroup((key.clone(), fibgroup.clone())));
        if publish {
            self.0.publish();
        }
    }
    pub fn unregister_fibgroup(&mut self, key: &NhopKey, publish: bool) {
        self.0.append(FibChange::UnregisterFibGroup(key.clone()));
        if publish {
            self.0.publish();
        }
    }
    pub fn add_fibroute(&mut self, prefix: Prefix, keys: Vec<NhopKey>, publish: bool) {
        if keys.is_empty() {
            error!("Rejected route to prefix {prefix}: no next-hop keys provided");
            return;
        }
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
    pub fn get_vtep(&self) -> Option<Vtep> {
        self.enter().map(|fib| fib.vtep.clone())
    }
    pub fn publish(&mut self) {
        self.0.publish();
    }
    #[must_use]
    pub fn as_fibreader(&self) -> FibReader {
        FibReader::new(self.0.clone())
    }
    /// Invalidate this fib and take it back from the readers.
    ///
    /// # Panics
    ///
    /// Panics if the taken fib is not the invalidated one, which would mean the change published
    /// above was not the change absorbed.
    pub fn destroy(mut self) {
        self.0.append(FibChange::Invalidate);
        self.0.publish();
        let taken_fib = self.0.take();
        assert!(!taken_fib.valid);
    }
}

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct FibReader(ReadHandle<Fib>);
impl FibReader {
    #[must_use]
    pub fn new(rhandle: ReadHandle<Fib>) -> Self {
        FibReader(rhandle)
    }
    #[must_use]
    #[inline]
    pub fn is_valid(&self) -> bool {
        match self.0.enter() {
            Some(fib) => fib.valid,
            None => false,
        }
    }
    pub fn enter(&self) -> Option<ReadGuard<'_, Fib>> {
        self.0
            .enter()
            .map(|fib| if fib.valid { Some(fib) } else { None })?
    }

    /// Convert `Rc<ReadHandle<Fib>>` -> `FibReader`
    /// We need this conversion because the cache of read-handles stores `ReadHandle<T>`'s
    /// but the `FibTable` provides `FibReader`s.
    pub(crate) fn rc_from_rc_rhandle(rc: Rc<ReadHandle<Fib>>) -> Rc<Self> {
        unsafe {
            // the conversion is safe because FibReader is a transparent wrapper of ReadHandle<Fib>
            let ptr = Rc::into_raw(rc).cast::<Self>();
            Rc::from_raw(ptr)
        }
    }
    pub fn get_id(&self) -> Option<FibKey> {
        self.enter().map(|fib| fib.get_id())
    }
    #[must_use]
    pub fn factory(&self) -> FibReaderFactory {
        FibReaderFactory(self.0.factory())
    }

    /// Get a reference to the `FibRoute` best matching address `destination`
    /// Return value: this method may only return None if the `FibReader` cannot
    /// be entered, which should only occur if the `FibWriter` has been dropped.
    ///
    /// Safety: the `FibRoute` reference returned will remain valid and immutable
    /// as long as the returned `ReadGuard` is alive.
    pub fn lpm_route(&self, destination: IpAddr) -> Option<ReadGuard<'_, FibRoute>> {
        self.enter()
            .map(|guard| ReadGuard::map(guard, |fib| fib.lpm(&destination)))
    }

    /// Same as `FibReader::lpm_route`, but reporting the longest `Prefix` matched.
    /// Notes: no prefix will be returned if we fail to "enter" in the fib.
    pub fn lpm_route_with_prefix(
        &self,
        destination: IpAddr,
    ) -> Option<(Prefix, ReadGuard<'_, FibRoute>)> {
        let mut prefix = Prefix::root_v4();
        let guarded_route = self.enter().map(|guard| {
            ReadGuard::map(guard, |fib| {
                let (hit, route) = fib.lpm_with_prefix(&destination);
                prefix = hit;
                route
            })
        });
        guarded_route.map(|guarded_route| (prefix, guarded_route))
    }

    /// Similar to `FibReader::lpm_route_with_prefix()`, but receing a `Packet` and selecting
    /// a `FibEntry` based on a hash of the packet if more than one `FibEntries` could be used to
    /// forward the packet
    pub fn lpm_entry_prefix<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> Option<(Prefix, ReadGuard<'_, FibEntry>)> {
        let mut prefix = Prefix::root_v4();
        let guarded_entry = self.enter().map(|guard| {
            ReadGuard::map(guard, |fib| {
                let (hit, entry) = fib.lpm_entry_prefix(packet);
                prefix = hit;
                entry
            })
        });
        guarded_entry.map(|guarded_entry| (prefix, guarded_entry))
    }
}

// make FibReader a zero-cost wrap of ReadHandle<Fib>
impl AsRef<FibReader> for ReadHandle<Fib> {
    #[inline]
    fn as_ref(&self) -> &FibReader {
        // safe because FibReader is repr(transparent) wrapper of ReadHandle<Fib>
        unsafe { &*(std::ptr::from_ref::<ReadHandle<Fib>>(self).cast::<FibReader>()) }
    }
}
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct FibReaderFactory(pub(crate) ReadHandleFactory<Fib>);

// make FibReaderFactory a zero-cost wrap of ReadHandleFactory<Fib>
impl AsRef<ReadHandleFactory<Fib>> for FibReaderFactory {
    #[inline]
    fn as_ref(&self) -> &ReadHandleFactory<Fib> {
        &self.0
    }
}

impl FibReaderFactory {
    #[must_use]
    pub fn handle(&self) -> FibReader {
        FibReader(self.0.handle())
    }
}

/// Model-based properties over a [`Fib`] driven through its writer.
///
/// The generator here is the one the pipeline harness will want: it produces a *populated* fib,
/// reached the way production reaches one -- a sequence of `FibChange`s through a `FibWriter` --
/// rather than by reaching into the tries. Everything the fib is asked afterwards is checked
/// against a model kept alongside it.
#[cfg(test)]
mod fib_properties {
    use super::*;
    use crate::fib::fibgroupstore::tests::{build_fib_entry_egress, build_fibgroup};
    use bolero::{Driver, ValueGenerator};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const NUM_NHOPS: u8 = 4;
    const NUM_PREFIXES: u8 = 8;
    const NUM_ENTRIES: u8 = 4;
    const MAX_CHANGES: u8 = 12;
    const MAX_KEYS_PER_ROUTE: u8 = 3;
    const MAX_ENTRIES_PER_GROUP: u8 = 3;

    /// The drop next-hop, first in [`nhop_keys`]. The store creates its group at construction and
    /// refuses to delete it.
    const DROP_KEY: usize = 0;
    /// `0.0.0.0/0` and `::/0`, at these indices in [`prefixes`]. A fib always carries a route for
    /// both: `Fib::lpm` has no answer for an address nothing covers, and says so with an
    /// `unreachable!()` on the forwarding path.
    const ROOT_V4: usize = 0;
    const ROOT_V6: usize = 5;

    /// The next-hop keys a generated fib may mention.
    ///
    /// A small pool on purpose. What is worth exercising is the collisions -- a route pinning a
    /// group against deletion, a registration mutating a group two routes share -- and collisions
    /// need a small pool to happen often. The drop key is in it because the rib does register
    /// groups under it, and because the store treats it as permanent.
    fn nhop_keys() -> Vec<NhopKey> {
        vec![
            NhopKey::with_drop(),
            NhopKey::with_addr_ifindex("10.0.0.1", 1),
            NhopKey::with_addr_ifindex("10.0.0.2", 2),
            NhopKey::with_ifindex(3),
        ]
    }

    /// The prefixes a generated fib may carry routes for. Nested on purpose, so a longest match
    /// has something to be longer than, and both roots so that deleting one is reachable.
    fn prefixes() -> Vec<Prefix> {
        [
            "0.0.0.0/0",
            "10.0.0.0/8",
            "10.1.0.0/16",
            "10.1.2.0/24",
            "10.1.2.3/32",
            "::/0",
            "2001:db8::/32",
            "2001:db8:1::/48",
        ]
        .iter()
        .map(|p| Prefix::from_str(p).unwrap_or_else(|_| unreachable!()))
        .collect()
    }

    /// Addresses to look up: one inside each level of the nesting, and one outside all of them in
    /// each family, so a lookup that falls through to the root is exercised too.
    fn probes() -> Vec<IpAddr> {
        [
            "9.9.9.9",
            "10.9.9.9",
            "10.1.9.9",
            "10.1.2.9",
            "10.1.2.3",
            "2000::1",
            "2001:db8::1",
            "2001:db8:1::1",
        ]
        .iter()
        .map(|a| IpAddr::from_str(a).unwrap_or_else(|_| unreachable!()))
        .collect()
    }

    /// The entries a generated group may be built from.
    fn entry_pool() -> Vec<FibEntry> {
        (1..=u32::from(NUM_ENTRIES))
            .map(|i| build_fib_entry_egress(i, &format!("10.0.9.{i}")))
            .collect()
    }

    /// One change, as the writer API exposes them, over indices into the pools above.
    #[derive(Debug, Clone)]
    enum Change {
        RegisterGroup { key: usize, entries: Vec<usize> },
        UnregisterGroup { key: usize },
        AddRoute { prefix: usize, keys: Vec<usize> },
        DelRoute { prefix: usize },
    }

    /// Draws sequences of [`Change`]s.
    #[derive(Debug, Clone, Copy, Default)]
    struct ChangeSequences;

    fn index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        driver
            .gen_u8(Included(&0), Included(&(count - 1)))
            .map(usize::from)
    }

    fn indices<D: Driver>(driver: &mut D, count: u8, most: u8) -> Option<Vec<usize>> {
        // Deliberately able to draw none: an empty group and a route with no next-hops are both
        // things the fib is supposed to refuse, and refusing is behaviour worth checking.
        let len = driver.gen_u8(Included(&0), Included(&most))?;
        let mut out = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            out.push(index(driver, count)?);
        }
        Some(out)
    }

    impl ValueGenerator for ChangeSequences {
        type Output = Vec<Change>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<Change>> {
            let len = driver.gen_u8(Included(&0), Included(&MAX_CHANGES))?;
            let mut out = Vec::with_capacity(usize::from(len));
            for _ in 0..len {
                let change = match driver.gen_u8(Included(&0), Included(&3))? {
                    0 => Change::RegisterGroup {
                        key: index(driver, NUM_NHOPS)?,
                        entries: indices(driver, NUM_ENTRIES, MAX_ENTRIES_PER_GROUP)?,
                    },
                    1 => Change::UnregisterGroup {
                        key: index(driver, NUM_NHOPS)?,
                    },
                    2 => Change::AddRoute {
                        prefix: index(driver, NUM_PREFIXES)?,
                        keys: indices(driver, NUM_NHOPS, MAX_KEYS_PER_ROUTE)?,
                    },
                    _ => Change::DelRoute {
                        prefix: index(driver, NUM_PREFIXES)?,
                    },
                };
                out.push(change);
            }
            Some(out)
        }
    }

    /// What the fib should hold, tracked beside it.
    ///
    /// Not a reimplementation: two maps, which is the fib with the tries, the group store's
    /// reference counting and its `UnsafeCell` sharing all taken away. What the model does have to
    /// get right is which changes the fib *refuses*, and that is the part worth writing down --
    /// three guards in three files decide it, and none of them says so where the next one can see.
    #[derive(Debug, Clone)]
    struct Model {
        /// next-hop key index -> the entries of its group.
        groups: BTreeMap<usize, Vec<FibEntry>>,
        /// prefix index -> the next-hop keys of its route, in order.
        routes: BTreeMap<usize, Vec<usize>>,
    }

    impl Model {
        /// A fresh fib: a drop group, and a route to it for each root.
        fn new() -> Self {
            Self {
                groups: BTreeMap::from([(DROP_KEY, vec![FibEntry::drop_fibentry()])]),
                routes: BTreeMap::from([(ROOT_V4, vec![DROP_KEY]), (ROOT_V6, vec![DROP_KEY])]),
            }
        }

        fn referenced(&self, key: usize) -> bool {
            self.routes.values().any(|keys| keys.contains(&key))
        }

        /// Drop every group no route points at. The store does this by reference count; here the
        /// routes are the reference count.
        fn purge(&mut self) {
            let referenced: BTreeSet<usize> = self
                .routes
                .values()
                .flatten()
                .copied()
                .collect::<BTreeSet<_>>();
            self.groups
                .retain(|key, _| *key == DROP_KEY || referenced.contains(key));
        }

        fn apply(&mut self, change: &Change, pool: &[FibEntry]) {
            match change {
                Change::RegisterGroup { key, entries } => {
                    // a group with no entries is refused: a route reaching one would leave the
                    // forwarder with nothing to execute
                    if entries.is_empty() {
                        return;
                    }
                    let entries = entries.iter().map(|i| pool[*i].clone()).collect();
                    self.groups.insert(*key, entries);
                }
                Change::UnregisterGroup { key } => {
                    // the drop group is permanent, and a group a route still names is pinned
                    if *key == DROP_KEY || self.referenced(*key) {
                        return;
                    }
                    self.groups.remove(key);
                }
                Change::AddRoute { prefix, keys } => {
                    // a route with no next-hops is refused, and so is one naming a group that was
                    // never registered -- whole, not in part
                    if keys.is_empty() || keys.iter().any(|k| !self.groups.contains_key(k)) {
                        return;
                    }
                    // note: no purge here. Replacing a route releases the old route's hold on its
                    // groups, but the fib leaves them in the store until something purges.
                    self.routes.insert(*prefix, keys.clone());
                }
                Change::DelRoute { prefix } => {
                    // a root route is not deleted but reset to drop, so that a lookup always has
                    // an answer
                    let removed = if *prefix == ROOT_V4 || *prefix == ROOT_V6 {
                        self.routes.insert(*prefix, vec![DROP_KEY])
                    } else {
                        self.routes.remove(prefix)
                    };
                    if removed.is_some() {
                        self.purge();
                    }
                }
            }
        }

        /// The longest prefix carrying a route that covers `addr`.
        fn lpm(&self, addr: &IpAddr, prefixes: &[Prefix]) -> Option<usize> {
            self.routes
                .keys()
                .copied()
                .filter(|i| prefixes[*i].covers_addr(addr))
                .max_by_key(|i| prefixes[*i].length())
        }

        /// The entries a route offers: its groups' entries, concatenated in next-hop key order.
        fn entries_for(&self, prefix: usize) -> Vec<FibEntry> {
            self.routes[&prefix]
                .iter()
                .flat_map(|key| self.groups[key].iter().cloned())
                .collect()
        }
    }

    fn apply_to_fib(writer: &mut FibWriter, change: &Change, pool: &[FibEntry], keys: &[NhopKey]) {
        let prefixes = prefixes();
        match change {
            Change::RegisterGroup { key, entries } => {
                let entries: Vec<FibEntry> = entries.iter().map(|i| pool[*i].clone()).collect();
                writer.register_fibgroup(&keys[*key], &build_fibgroup(&entries), true);
            }
            Change::UnregisterGroup { key } => writer.unregister_fibgroup(&keys[*key], true),
            Change::AddRoute {
                prefix,
                keys: route,
            } => {
                let route = route.iter().map(|k| keys[*k].clone()).collect();
                writer.add_fibroute(prefixes[*prefix], route, true);
            }
            Change::DelRoute { prefix } => writer.del_fibroute(prefixes[*prefix]),
        }
    }

    /// The pools and the constants that index them agree.
    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(nhop_keys().len(), usize::from(NUM_NHOPS));
        assert_eq!(prefixes().len(), usize::from(NUM_PREFIXES));
        assert_eq!(entry_pool().len(), usize::from(NUM_ENTRIES));
        assert_eq!(nhop_keys()[DROP_KEY], NhopKey::with_drop());
        assert_eq!(prefixes()[ROOT_V4], Prefix::root_v4());
        assert_eq!(prefixes()[ROOT_V6], Prefix::root_v6());
        for probe in probes() {
            assert!(
                prefixes().iter().any(|p| p.covers_addr(&probe)),
                "probe {probe} is covered by no prefix, not even a root"
            );
        }
    }

    /// After any sequence of changes, a fib answers every lookup the way the model says.
    ///
    /// This is the whole of the fib's read path against an independent account of its contents:
    /// which prefix the lookup lands on, and which entries the route there offers. It covers the
    /// group store's sharing too, since registering a group under a key two routes name has to
    /// change what both of them offer.
    #[test]
    fn a_fib_answers_lookups_the_way_the_model_says() {
        let keys = nhop_keys();
        let prefixes = prefixes();
        let probes = probes();
        let pool = entry_pool();

        bolero::check!()
            .with_generator(ChangeSequences)
            .cloned()
            .for_each(|changes: Vec<Change>| {
                let (mut writer, _reader) = FibWriter::new(1);
                let mut model = Model::new();

                for (step, change) in changes.iter().enumerate() {
                    apply_to_fib(&mut writer, change, &pool, &keys);
                    model.apply(change, &pool);

                    let fib = writer.enter().unwrap_or_else(|| unreachable!());
                    let at = || format!("at step {step} of {changes:?}");

                    assert_eq!(fib.len_groups(), model.groups.len(), "{}", at());

                    for probe in &probes {
                        let want = model
                            .lpm(probe, &prefixes)
                            .unwrap_or_else(|| panic!("model has no route for {probe} {}", at()));

                        let (hit, route) = fib.lpm_with_prefix(probe);
                        assert_eq!(hit, prefixes[want], "for {probe} {}", at());

                        let got: Vec<FibEntry> = route
                            .iter()
                            .flat_map(|group| group.entries().iter().cloned())
                            .collect();
                        assert_eq!(got, model.entries_for(want), "for {probe} {}", at());
                    }
                }
            });
    }

    /// A lookup always lands on a route with at least one entry to execute.
    ///
    /// `Fib::lpm_entry_prefix` panics outright on a route with none -- "hit route without
    /// fibgroups/entries. This is a bug." -- on the forwarding path, for every packet that reaches
    /// it. The invariant that saves it is held jointly by three guards in three files: the store
    /// refuses an empty group, the writer refuses a route with no next-hop keys, and
    /// `FibRoute::from_nhopkeys` refuses a route naming a group that is not registered. Nothing
    /// states the invariant they add up to, so state it here.
    #[test]
    fn every_route_a_lookup_reaches_has_an_entry_to_execute() {
        let keys = nhop_keys();
        let probes = probes();
        let pool = entry_pool();

        bolero::check!()
            .with_generator(ChangeSequences)
            .cloned()
            .for_each(|changes: Vec<Change>| {
                let (mut writer, _reader) = FibWriter::new(1);
                for change in &changes {
                    apply_to_fib(&mut writer, change, &pool, &keys);
                }

                let fib = writer.enter().unwrap_or_else(|| unreachable!());
                for probe in &probes {
                    let (_, route) = fib.lpm_with_prefix(probe);
                    assert!(route.len() > 0, "no entry for {probe} after {changes:?}");
                    // and the index arithmetic that picks among them is total over that range
                    for index in 0..route.len() {
                        let _ = route.get_fibentry(index);
                    }
                }
            });
    }

    /// A reader sees what the writer sees, once every change has been published.
    #[test]
    fn a_reader_and_a_writer_agree_after_publishing() {
        let keys = nhop_keys();
        let probes = probes();
        let pool = entry_pool();

        bolero::check!()
            .with_generator(ChangeSequences)
            .cloned()
            .for_each(|changes: Vec<Change>| {
                let (mut writer, reader) = FibWriter::new(1);
                for change in &changes {
                    apply_to_fib(&mut writer, change, &pool, &keys);
                }

                for probe in &probes {
                    let (want_prefix, want_entries) = {
                        let fib = writer.enter().unwrap_or_else(|| unreachable!());
                        let (prefix, route) = fib.lpm_with_prefix(probe);
                        let entries: Vec<FibEntry> = route
                            .iter()
                            .flat_map(|group| group.entries().iter().cloned())
                            .collect();
                        (prefix, entries)
                    };

                    let (got_prefix, route) = reader
                        .lpm_route_with_prefix(*probe)
                        .unwrap_or_else(|| unreachable!());
                    let got_entries: Vec<FibEntry> = route
                        .iter()
                        .flat_map(|group| group.entries().iter().cloned())
                        .collect();

                    assert_eq!(got_prefix, want_prefix, "for {probe} after {changes:?}");
                    assert_eq!(got_entries, want_entries, "for {probe} after {changes:?}");
                }
            });
    }
}
