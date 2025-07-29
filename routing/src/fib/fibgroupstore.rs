// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that contains a reference counted store for Fibgroups. Every FibGroup is
//! a vector of FibEntries. Forwarding a packet happens by finding and selecting one FibEntry.
//!
//! This module defines a new data structure called FibRoute, that consists of a vector
//! of shared references of FibGroups. The data structures in this module allows mutating
//! Fibgroups when routing changes occur for all the affected routes without needing to explicitly
//! change any of the routes. This allows, upon routing changes, updating the FIB in O(Nh) instead
//! of O(Routes), potentially reducing the number of updates by several orders of magnitude.
//! This is achieved by means of an `UnsafeCell`, which allows us to mutate fibgroups.
//! This data structure is, therefore, NOT thread-safe. Thread-safety is achieved by wrapping
//! this structure in left-right. The use of `UnsafeCell` over RefCell is meant to avoid any
//! penalty due to run-time borrow-checking. The expectation is that this new structure incurs
//! no penalty in packet forwarding performance while allowing for massive fib updates at a very low
//! algorithmic complexity.

#![allow(unused)]

use crate::fib::fibobjects::{FibEntry, FibGroup};
use crate::rib::nexthop::NhopKey;
use ahash::RandomState;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::rc::Rc;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum FibError {
    #[error("Failed to find fibgroup for nh {0}")]
    NoFibGroup(NhopKey),
}

#[derive(Clone, Default, Debug)]
pub(crate) struct FibGroupStore(HashMap<NhopKey, Rc<UnsafeCell<FibGroup>>, RandomState>);

impl FibGroupStore {
    #[must_use]
    pub(crate) fn new() -> Self {
        let mut store = Self(HashMap::with_hasher(RandomState::with_seed(0)));
        store.add_mod_group(&NhopKey::with_drop(), Self::drop_fibgroup());
        store
    }
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
    #[must_use]
    fn drop_fibgroup() -> FibGroup {
        FibGroup::with_entry(FibEntry::drop_fibentry())
    }
    #[must_use]
    /// get an Rc for the drop `Fibgroup`. The drop fibgroup is unique.
    pub fn get_drop_fibgroup_ref(&self) -> Rc<UnsafeCell<FibGroup>> {
        self.get_ref(&NhopKey::with_drop())
            .unwrap_or_else(|| unreachable!())
    }

    ////////////////////////////////////////////////////////////////////////////////
    /// Add a `FibGroup` for a given `NhopKey` or replace it if it exists.
    ////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn add_mod_group(&mut self, key: &NhopKey, fibgroup: FibGroup) {
        if let Some(group) = &mut self.0.get(key) {
            unsafe {
                *group.get() = fibgroup;
            }
        } else {
            let fg = Rc::new(UnsafeCell::new(fibgroup));
            self.0.insert(key.clone(), fg);
        }
    }
    ////////////////////////////////////////////////////////////////////////////////
    /// Get a refcounted reference to the `Fibgroup` for a given `NhopKey`. This is
    /// used by `FibRoutes` to point to the current `FibGroups`.
    ////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn get_ref(&self, key: &NhopKey) -> Option<Rc<UnsafeCell<FibGroup>>> {
        self.0.get(key).map(|group| Rc::clone(group))
    }
    #[must_use]
    pub(crate) fn get(&self, key: &NhopKey) -> Option<&FibGroup> {
        self.0.get(key).map(|group| unsafe { &*group.get() })
    }
    pub(crate) fn del(&mut self, key: &NhopKey) {
        if key == &NhopKey::with_drop() {
            return;
        }
        if let Some(group) = self.0.get(key) {
            if Rc::strong_count(group) == 1 {
                self.0.remove(key);
            }
        }
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Remove unused `FibGroup`s. This should not be needed, but we may use it to expedite N deletions
    /// in batch, as it avoids lookups (at the expense of traversal).
    /// Returns the number of groups removed.
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn purge(&mut self) -> usize {
        let len = self.len();
        self.0
            .retain(|key, group|  { let keep = Rc::strong_count(group) > 1 || key == &NhopKey::with_drop();
                if !keep {
                    debug!("Will purge fibgroup for nhop '{key}'");
                }
                keep
        });
        len - self.len()
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Iterate over the `FibGroups` in the store
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn values(&self) -> impl Iterator<Item = &FibGroup> {
        unsafe { self.0.values().map(|group| &*group.get()) }
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Iterate over the `FibGroups` in the store
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&NhopKey, &FibGroup)> {
        unsafe { self.0.iter().map(|(key, group)| (key, &*group.get())) }
    }
}

#[derive(Debug, Clone)]
pub struct FibRoute(Vec<Rc<UnsafeCell<FibGroup>>>);
impl FibRoute {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(vec![])
    }
    #[must_use]
    pub fn with_fibgroup(fg_ref: Rc<UnsafeCell<FibGroup>>) -> Self {
        Self(vec![fg_ref])
    }
    /// Add a reference to a `FibGroup` to a `FibRoute`
    pub(crate) fn add_fibgroup_ref(&mut self, fg_ref: Rc<UnsafeCell<FibGroup>>) {
        self.0.push(fg_ref);
    }
    #[must_use]
    #[cfg(test)]
    /// Get a reference to the `FibGroup` at the group-level index. This is only for testing.
    pub(crate) fn get_fibgroup(&self, index: usize) -> Option<&FibGroup> {
        if index < self.len() {
            unsafe { Some(&*self.0[index].get()) }
        } else {
            None
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    /// Tells the total number of `FibEntry`s in a `FibRoute`, as the sum of the lengths of its `FibGroup`s
    /////////////////////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.0
            .iter()
            .fold(0, |val, g| unsafe { val + (&*g.get()).len() })
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////
    /// Tells the number of `FibGroup`s that a `FibRoute` has
    /////////////////////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn num_groups(&self) -> usize {
        self.0.len()
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// A Fibroute is a vector of fibgroups, and each fibgroup is itself a vector of FibEntries.
    /// We cannot "merge" all of the FibEntries into a single vector since that would defeat the purpose
    /// of automatically mutating them at once for multiple prefixes. This creates a problem in the datapath.
    /// To forward a packet we have to hash it in order to select one out of the total set of FibEntries.
    /// One possibility would be that we first select a fibgroup and then one of its FibEntries.
    /// However, this could bias the selection if fibgroups have distinct number of entries: take 2 groups,
    /// one with 5 entries and one with 2. Assuming uniformity, each group would be selected
    /// 1/2 of the time. However, entries in the first would be selected 1/10th of the time each, while,
    /// those in the second, 1/4th. To avoid this skew, we map the hash value onto the total number of entries,
    /// as we would normally do, but then need to find the right entry within each vector (fibgroup).
    /// This is what this method is for. As input, we expect some virtual index, which would be the index
    /// the entries would have had they been stored in a single vector. We then translate that virtual index
    /// to a real one, in the corresponding fibgroup, as shown in the next example for 4 groups.
    /// 0 1 2 3 4 | 5 6 7 | 8 9 | 10 11 12 | virtual entry indices
    /// 0 1 2 3 4 | 0 1 2 | 0 1 | 0  1  2  | real    entry indices within each group.
    ////////////////////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn get_fibentry(&self, index: usize) -> Option<&FibEntry> {
        let mut index = index;
        for g in self.0.iter() {
            let group = unsafe { &*g.get() };
            if index < group.len() {
                return Some(&group.entries[index]);
            }
            index -= group.len();
        }
        None
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Provide iterator over the `FibGroups` that a `Fibroute` refers to
    ////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn iter(&self) -> impl Iterator<Item = &FibGroup> {
        unsafe { self.0.iter().map(|group| &*group.get()) }
    }
}

impl FibRoute {
    #[must_use]
    ///////////////////////////////////////////////////////////////////////////////////
    /// Creates a `FibRoute` with the `FibGroups` corresponding to a set of `NhopKey`s.
    /// Fails if it can't find a FibGroup for any of the `NhopKey`s.
    ///////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn from_nhopkeys(store: &FibGroupStore, keys: &[NhopKey]) -> Result<Self, FibError> {
        let mut route = FibRoute::new();
        for key in keys {
            let fg_ref = store
                .get_ref(key)
                .ok_or_else(|| FibError::NoFibGroup(key.clone()))?;
            route.0.push(fg_ref);
        }
        Ok(route)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::fib::fibgroupstore::{FibError, FibGroupStore, FibRoute};
    use crate::fib::fibobjects::EgressObject;
    use crate::fib::fibobjects::FibEntry;
    use crate::fib::fibobjects::FibGroup;
    use crate::fib::fibobjects::PktInstruction;
    use crate::rib::nexthop::NhopKey;

    use std::net::IpAddr;
    use std::str::FromStr;

    // builds fib entry with single egress instruction
    fn build_fib_entry_egress(ifindex: u32, address: &str, ifname: &str) -> FibEntry {
        let addr = Some(IpAddr::from_str(address).unwrap());
        let ifname = Some(ifname.to_string());
        let ifindex = Some(ifindex);
        let inst = PktInstruction::Egress(EgressObject::new(ifindex, addr, ifname));
        FibEntry::with_inst(inst)
    }
    // builds fibgroup with a single entry
    fn build_fibgroup(entries: &[FibEntry]) -> FibGroup {
        let mut fibgroup = FibGroup::new();
        fibgroup.entries.extend_from_slice(entries);
        fibgroup
    }

    #[test]
    fn test_fibgroupstore_minimal() {
        // create fibgroup store
        let mut store = FibGroupStore::new();

        // build fibgroup with one fib entry
        let entry = build_fib_entry_egress(99, "10.0.1.1", "eth0");
        let fibgroup = FibGroup::with_entry(entry.clone());

        // nhop key to store the fibgroup at
        let nhkey = NhopKey::with_address(&IpAddr::from_str("7.0.0.1").unwrap());

        // store the fibgroup
        store.add_mod_group(&nhkey, fibgroup);

        // retrieve the fibgrop from the store from its key
        let stored = store.get(&nhkey).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored.entries[0].len(), 1);
        assert_eq!(stored.entries[0], entry);
        println!("{stored:#?}");

        // create fibroute to have a shared ref to that fibgroup
        let mut fibroute = FibRoute::new();
        fibroute.add_fibgroup_ref(store.get_ref(&nhkey).unwrap());
        assert_eq!(fibroute.0.len(), 1);
        assert_eq!(fibroute.len(), 1);

        // pretend to perform a lookup that hits that fibroute and get its single fib entry
        let found = fibroute.get_fibentry(0).unwrap();
        assert_eq!(found, &entry);
        println!("hit:\n{found}");

        // mutate/replace fibgroup, without modifying fibroute
        let entry2 = build_fib_entry_egress(100, "10.0.2.2", "eth1");
        let fibgroup = FibGroup::with_entry(entry2.clone());
        store.add_mod_group(&nhkey, fibgroup);

        // check that the fibroute has been internally modified
        let found = fibroute.get_fibentry(0).unwrap();
        assert_eq!(found, &entry2);
        println!("hit:\n{found}");
    }

    #[test]
    fn test_multi_fibgroup_route_entry_selection() {
        // create multiple fib entries
        let e1 = build_fib_entry_egress(1, "10.0.1.1", "eth1");
        let e2 = build_fib_entry_egress(2, "10.0.2.1", "eth2");
        let e3 = build_fib_entry_egress(3, "10.0.3.1", "eth3");
        let e4 = build_fib_entry_egress(4, "10.0.3.4", "eth4");
        let e5 = build_fib_entry_egress(5, "10.0.3.5", "eth5");
        let e6 = build_fib_entry_egress(6, "10.0.3.6", "eth6");
        let e7 = build_fib_entry_egress(7, "10.0.3.7", "eth7");
        let e8 = build_fib_entry_egress(8, "10.0.3.8", "eth8");

        // create several fibgroups of distinct sizes
        let g1 = build_fibgroup(&[e1.clone(), e2.clone()]);
        let g2 = build_fibgroup(&[e3.clone(), e4.clone(), e5.clone(), e6.clone()]);
        let g3 = build_fibgroup(&[e7.clone()]);
        let g4 = build_fibgroup(&[e8.clone()]);

        // create a dummy nhop key whose contents do not matter other than for storing each fibgroup
        let key1 = NhopKey::with_address(&IpAddr::from_str("8.0.0.1").unwrap());
        let key2 = NhopKey::with_address(&IpAddr::from_str("8.0.0.2").unwrap());
        let key3 = NhopKey::with_address(&IpAddr::from_str("8.0.0.3").unwrap());
        let key4 = NhopKey::with_address(&IpAddr::from_str("8.0.0.4").unwrap());

        // create a fibgroup store and store the fibgroups with the respective nhop keys
        let mut store = FibGroupStore::new();
        store.add_mod_group(&key1, g1.clone());
        store.add_mod_group(&key2, g2.clone());
        store.add_mod_group(&key3, g3.clone());
        store.add_mod_group(&key4, g4.clone());
        assert_eq!(store.len(), 4 + 1); // +1 is for drop group
        println!("{store:#?}");

        // Iterator
        for (key, group) in store.iter() {
            println!("{key} -> {group}");
        }

        // Build a route that references the four fibgroups
        let mut fibroute = FibRoute::new();
        fibroute.add_fibgroup_ref(store.get_ref(&key1).unwrap());
        fibroute.add_fibgroup_ref(store.get_ref(&key2).unwrap());
        fibroute.add_fibgroup_ref(store.get_ref(&key3).unwrap());
        fibroute.add_fibgroup_ref(store.get_ref(&key4).unwrap());
        assert_eq!(fibroute.0.len(), 4); // 4 fibgroups
        assert_eq!(fibroute.len(), g1.len() + g2.len() + g3.len() + g4.len());

        // select one entry in the fibroute by index and check that it is correct
        assert_eq!(fibroute.get_fibentry(0), Some(e1).as_ref());
        assert_eq!(fibroute.get_fibentry(1), Some(e2).as_ref());
        assert_eq!(fibroute.get_fibentry(2), Some(e3).as_ref());
        assert_eq!(fibroute.get_fibentry(3), Some(e4).as_ref());
        assert_eq!(fibroute.get_fibentry(4), Some(e5).as_ref());
        assert_eq!(fibroute.get_fibentry(5), Some(e6).as_ref());
        assert_eq!(fibroute.get_fibentry(6), Some(e7).as_ref());
        assert_eq!(fibroute.get_fibentry(7), Some(e8).as_ref());
        assert_eq!(fibroute.get_fibentry(8), None.as_ref());

        // attempt to remove fibgroups: none should be removed from the store
        store.del(&key1);
        store.del(&key2);
        store.del(&key3);
        store.del(&key4);
        assert_eq!(store.len(), 4 + 1); // +1 is for drop group
        assert_eq!(store.purge(), 0);

        // remove last fibgroup from route and remove it: should be removed
        fibroute.0.pop();
        store.del(&key4);
        assert_eq!(store.len(), (4 + 1) - 1);

        // remove another one
        fibroute.0.pop();
        assert_eq!(store.purge(), 1); // one should be purged

        // drop the route
        drop(fibroute);

        // remove the remaining
        store.del(&key1);
        store.del(&key2);
        store.del(&key3);
        assert_eq!(store.len(), 1); // drop group always remains
    }

    #[test]
    fn test_fibroute_from_nhopkeys() {
        // create multiple fib entries
        let e1 = build_fib_entry_egress(1, "10.0.1.1", "eth1");
        let e2 = build_fib_entry_egress(2, "10.0.2.1", "eth2");
        let e3 = build_fib_entry_egress(3, "10.0.3.1", "eth3");
        let e4 = build_fib_entry_egress(4, "10.0.3.4", "eth4");
        let e5 = build_fib_entry_egress(5, "10.0.3.5", "eth5");
        let e6 = build_fib_entry_egress(6, "10.0.3.6", "eth6");
        let e7 = build_fib_entry_egress(7, "10.0.3.7", "eth7");
        let e8 = build_fib_entry_egress(8, "10.0.3.8", "eth8");

        // create several fibgroups of distinct sizes
        let g1 = build_fibgroup(&[e1.clone(), e2.clone()]);
        let g2 = build_fibgroup(&[e3.clone(), e4.clone(), e5.clone(), e6.clone()]);
        let g3 = build_fibgroup(&[e7.clone()]);
        let g4 = build_fibgroup(&[e8.clone()]);

        // create a dummy nhop key whose contents do not matter other than for storing each fibgroup
        let key1 = NhopKey::with_address(&IpAddr::from_str("8.0.0.1").unwrap());
        let key2 = NhopKey::with_address(&IpAddr::from_str("8.0.0.2").unwrap());
        let key3 = NhopKey::with_address(&IpAddr::from_str("8.0.0.3").unwrap());
        let key4 = NhopKey::with_address(&IpAddr::from_str("8.0.0.4").unwrap());

        // create a fibgroup store and store the fibgroups with the respective nhop keys
        let mut store = FibGroupStore::new();
        store.add_mod_group(&key1, g1.clone());
        store.add_mod_group(&key2, g2.clone());
        store.add_mod_group(&key3, g3.clone());
        store.add_mod_group(&key4, g4.clone());
        assert_eq!(store.len(), 4 + 1); // +1 is for drop group

        // create a FibRoute from the keys
        let fibroute = FibRoute::from_nhopkeys(
            &store,
            &[key1.clone(), key2.clone(), key3.clone(), key4.clone()],
        )
        .unwrap();

        assert_eq!(fibroute.0.len(), 4);
        assert_eq!(unsafe { &*fibroute.0[0].get() }, store.get(&key1).unwrap());
        assert_eq!(unsafe { &*fibroute.0[1].get() }, store.get(&key2).unwrap());
        assert_eq!(unsafe { &*fibroute.0[2].get() }, store.get(&key3).unwrap());
        assert_eq!(unsafe { &*fibroute.0[3].get() }, store.get(&key4).unwrap());
        println!("{fibroute:#?}");

        // Attempt to create a Fibroute with a key for which no fibgroup exists: should fail
        let key = NhopKey::with_address(&IpAddr::from_str("9.0.0.1").unwrap());
        let fibroute = FibRoute::from_nhopkeys(&store, &[key1, key2, key]);
        assert!(matches!(fibroute, Err(FibError::NoFibGroup(ref key))));
        println!("{fibroute:#?}");
    }
}
