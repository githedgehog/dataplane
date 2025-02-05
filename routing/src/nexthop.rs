// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Object definitions for (shared) routing next-hops. These
//! refer to other objects like Encapsulation.

use crate::encapsulation::Encapsulation;
use std::cell::RefCell;
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
pub use std::collections::BTreeSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::net::IpAddr;
use std::option::Option;
pub use std::rc::Rc;
#[cfg(test)]
use std::str::FromStr;

#[derive(Debug)]
/// A collection of unique next-hops. Next-hops are identified by a next-hop key
/// that can contain an address, ifindex and encapsulation.
pub(crate) struct NhopStore(pub(crate) BTreeSet<Rc<Nhop>>);

#[derive(Debug, Eq)]
/// A next-hop object that can be shared by multiple routes and that can have
/// references to other next-hops in this (or other?) table.
pub(crate) struct Nhop {
    pub(crate) key: NhopKey,
    pub(crate) resolvers: RefCell<Vec<Rc<Nhop>>>,
}

#[derive(Debug, Default, Copy, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub enum FwAction {
    #[default]
    Forward = 0,
    Drop = 1,
}

/// A struct acting as a key to next-hop objects. This should include the properties that
/// make a shared next-hop unique and distinguishable from the rest. This type is also used
/// as return value in next-hop resolution routines.
#[derive(Debug, Default, Copy, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct NhopKey {
    pub(crate) address: Option<IpAddr>,
    pub(crate) ifindex: Option<u32>,
    pub(crate) encap: Option<Encapsulation>,
    pub(crate) fwaction: FwAction,
}

#[allow(dead_code)]
impl NhopKey {
    //////////////////////////////////////////////////////////////////
    /// Build a next-hop key
    //////////////////////////////////////////////////////////////////
    pub fn new(
        address: Option<IpAddr>,
        ifindex: Option<u32>,
        encap: Option<Encapsulation>,
        fwaction: FwAction,
    ) -> Self {
        Self {
            address,
            ifindex,
            encap,
            fwaction,
        }
    }
    pub fn with_drop() -> Self {
        Self {
            address: None,
            ifindex: None,
            encap: None,
            fwaction: FwAction::Drop,
        }
    }
    #[cfg(test)]
    pub fn from_str(address: &str) -> Self {
        Self {
            address: Some(IpAddr::from_str(address).expect("Bad address")),
            ..Default::default()
        }
    }
    pub fn with_addr_ifindex(address: &IpAddr, ifindex: u32) -> Self {
        Self {
            address: Some(*address),
            ifindex: Some(ifindex),
            ..Default::default()
        }
    }
    pub fn with_address(address: &IpAddr) -> Self {
        Self {
            address: Some(*address),
            ..Default::default()
        }
    }
    pub fn with_ifindex(ifindex: u32) -> Self {
        Self {
            ifindex: Some(ifindex),
            ..Default::default()
        }
    }
}

/* Implement some traits needed to use Nhop as set element of BtreeSet. Since a Nhop can
   be internally mutated, we have to implement these manually to leave the resolvers out.
   The implementations leverage the derived trait implementations for the `NhopKey`
   (contained in the Nhop).
*/
impl PartialEq for Nhop {
    fn eq(&self, other: &Self) -> bool {
        self.key.eq(&other.key)
    }
}
impl Ord for Nhop {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key.cmp(&other.key)
    }
}
impl PartialOrd for Nhop {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/* Hash is only needed if we use HashSet instead of BtreeSet for the NhopMap */
impl Hash for Nhop {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

#[allow(dead_code)]
#[allow(clippy::mutable_key_type)]
impl Nhop {
    //////////////////////////////////////////////////////////////////
    /// Create a new Nhop object from a key object
    //////////////////////////////////////////////////////////////////
    fn new_from_key(key: &NhopKey) -> Self {
        Self {
            key: *key,
            resolvers: RefCell::new(Vec::new()),
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    /// Store a reference to some Nhop 'resolver' in the current next-hop Self.
    /// Note well:
    ///   * this increments/keeps the Rc count of the "resolver" since we're storing an Rc as parameter
    ///   * this should be called when we find out that Self resolves to 'resolver' according to some
    ///     routing table. Other than that, the reference has no semantics in this module, except that
    ///     the 'routing resolution' semantic is implicitly assumed in the functions that allow resolving
    ///     nexthops from such references. In other words, the "resolution" in this module will be as (in)
    ///     correct as those with explicit recursion, as long as the references are kept up to date.
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn add_resolver(&self, resolver: Rc<Nhop>) -> &Self {
        self.resolvers.borrow_mut().push(resolver);
        self
    }

    /// Auxiliary recursive method used by Nhop::quick_resolve().
    fn quick_resolve_rec(&self, result: &mut BTreeSet<NhopKey>) {
        let resolvers_of_this = self.resolvers.borrow();

        if resolvers_of_this.len() == 0 {
            /* next-hop has no resolvers */
            if self.key.ifindex.is_some() || self.key.fwaction == FwAction::Drop {
                result.insert(self.key);
            } else {
                // This should not happen. The vrf will be such that there's always
                // a default route (with legitimate next-hops or a default one with action drop).
                // So all next-hops should resolve, at the very least, to the default route.
                // If we get here, we probably failed to update the resolution dependencies.
                panic!("Unable to resolve next-hop {:#?}", &self.key);
            }
        } else {
            /* check resolvers */
            for r in resolvers_of_this.iter() {
                if let Some(i) = r.key.ifindex {
                    /* Take into account that some nhops may already be partially resolved, meaning
                    they include an address AND an ifindex */
                    let address = r.key.address.map_or(self.key.address, |_| r.key.address);
                    result.insert(NhopKey::new(
                        address,
                        Some(i),
                        self.key.encap,
                        self.key.fwaction,
                    ));
                } else {
                    r.quick_resolve_rec(result);
                }
            }
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////////
    /// This method is just a proof of concept. The idea is that if the next-hop dependencies are up-to-date,
    /// a next-hop can be resolved by those. This allows us to replace an expensive LPM recursion (multiple LPMs)
    /// by a small recursion in the next-hop store, which is stateful and persists the results (to be done).
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    pub fn quick_resolve(&self) -> BTreeSet<NhopKey> {
        let mut out: BTreeSet<NhopKey> = BTreeSet::new();
        self.quick_resolve_rec(&mut out);
        out
    }
}

#[allow(dead_code)]
impl NhopStore {
    //////////////////////////////////////////////////////////////////
    /// Create a next-hop map object.
    //////////////////////////////////////////////////////////////////
    pub(crate) fn new() -> Self {
        Self(BTreeSet::new())
    }

    //////////////////////////////////////////////////////////////////
    /// Get the number of next-hops in the store
    //////////////////////////////////////////////////////////////////
    pub fn len(&self) -> usize {
        self.0.len()
    }

    //////////////////////////////////////////////////////////////////
    /// Add a next hop with a given key (if it does not exist already)
    /// and return a shared reference to it.
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn add_nhop(&mut self, key: &NhopKey) -> Rc<Nhop> {
        let nh = Rc::new(Nhop::new_from_key(key));
        if let Some(e) = self.0.get(&nh) {
            Rc::clone(e)
        } else {
            let out = Rc::clone(&nh);
            self.0.insert(nh);
            out
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Tell if there exists a next-hop with a given key.
    //////////////////////////////////////////////////////////////////
    pub(crate) fn contains(&self, key: &NhopKey) -> bool {
        let nh = Nhop::new_from_key(key);
        self.0.contains(&nh)
    }

    //////////////////////////////////////////////////////////////////
    /// Get a reference to the next-hop with a given key, if it exists.
    /// Unlike add_nhop(), this returns a `&Rc<Nhop>` and not `Rc<Nhop>`,
    /// thereby not increasing the reference count of the next-hop.
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn get_nhop(&self, key: &NhopKey) -> Option<&Rc<Nhop>> {
        let nh = Nhop::new_from_key(key);
        self.0.get(&nh)
    }

    //////////////////////////////////////////////////////////////////
    /// Get the Rc count of the next-hop with the given key.
    /// This method may only used for testing.
    //////////////////////////////////////////////////////////////////
    #[cfg(test)]
    pub fn get_nhop_rc_count(&self, key: &NhopKey) -> usize {
        self.get_nhop(key).map_or(0, Rc::strong_count)
    }

    //////////////////////////////////////////////////////////////////
    /// Declare that a next-hop is no longer of our interest. The nhop may be removed or
    /// not, depending on whether there are other references to it. This function could
    /// just be self.map.remove(). However, that would just remove an Rc<Nhop> from the
    /// collection while other elements might have living references to it. We want the
    /// store to be and exhaustive, in that it should contain only living nexthops and
    /// all of them. I.e., no next-hop object should be alive outside of this collection.
    /// So, we'll remove elements from this collection iff no one refers to them.
    /// This should guarantee the uniqueness of next-hops and their referrals.
    pub(crate) fn del_nhop(&mut self, key: &NhopKey) {
        let target = Nhop::new_from_key(key);
        let mut remove: bool = false;
        if let Some(existing) = self.0.get(&target) {
            if Rc::strong_count(existing) == 1 {
                remove = true;
            }
        }
        if remove {
            /* Nobody refers to this next-hop, so we're good to remove it. We could happily call
               self.map.remove(): all the references to its resolvers will be gone too.
               But those resolvers may get one less reference and may need to be purged too, and
               by doing so, the next-hops used to resolve them ... So, we recourse. Nothing terribly
               bad would happen if we didn't. In principle all next-hops should stay alive as long
               as a route refers to them. This is just a sanity to protect against the race where a
               route is removed but its next-hop remains alive due to a referral and then that referral
               is gone, causing the next-hop to remain in the store.
            */
            if let Some(existing) = self.0.take(&target) {
                /* N.B. this mutable borrow should be "safe" in spite of the recursion because
                the only case where it wouldn't would be if borrow_xx() was called for the same
                nhop, but that should happen if its refcount is 1 and we don't keep other refs around */
                let mut resolvers = existing.resolvers.borrow_mut();
                while let Some(r) = resolvers.pop() {
                    let key = r.key; /* copy the key since we'll */
                    drop(r); /* ....drop the Rc */
                    self.del_nhop(&key);
                }
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Resolve a next-hop by address. If no next-hop exists for that
    /// address, returns None. Otherwise, it returns the result of
    /// quick_resolve() on the next-hop found.
    /// This function is probably only useful for testing.
    //////////////////////////////////////////////////////////////////
    #[cfg(test)]
    pub(crate) fn resolve_by_addr(&self, address: &IpAddr) -> Option<BTreeSet<NhopKey>> {
        let key = NhopKey::with_address(address);
        self.get_nhop(&key).map(|nh| nh.quick_resolve())
    }

    /// Dump the contents of the next-hop map
    #[cfg(test)]
    pub(crate) fn dump(&self) {
        print!("{self:#?}");
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use crate::nexthop::*;
    use std::rc::Rc;

    #[test]
    fn test_nhop_store_minimal() {
        let mut store = NhopStore::new();
        let nh_key = NhopKey::from_str("10.0.1.1");

        /* add a nhop. We're not keeping the returned reference. Therefore, its refcount will remain at 1 */
        let _ = store.add_nhop(&nh_key);

        /* check it's there */
        assert_eq!(store.contains(&nh_key), true);

        /* get it */
        let nh = store.get_nhop(&nh_key).unwrap();
        assert_eq!(Rc::strong_count(nh), 1);

        /* check refcount */
        let num_refs = store.get_nhop_rc_count(&nh_key);
        assert_eq!(num_refs, 1);

        store.dump();
    }

    #[test]
    fn test_nhop_store_basic() {
        let mut store = NhopStore::new();

        /* Create KEYS for some next-hop */
        let n1_k = NhopKey::from_str("10.0.1.1");
        let n2_k = NhopKey::from_str("10.0.2.1");
        let n3_k = NhopKey::from_str("10.0.3.1");

        let i1_k = NhopKey::with_ifindex(1);
        let i2_k = NhopKey::with_ifindex(2);
        let i3_k = NhopKey::with_ifindex(3);

        /* Add some next-hops and references */
        {
            /* Use separate scope so that all refs the APIs returns
            get dropped at the end of it. This is just for testing. */
            let n1 = store.add_nhop(&n1_k);
            let n2 = store.add_nhop(&n2_k);
            let n3 = store.add_nhop(&n3_k);

            let i1 = store.add_nhop(&i1_k);
            let i2 = store.add_nhop(&i2_k);
            let i3 = store.add_nhop(&i3_k);
            n1.add_resolver(i1);
            n2.add_resolver(i2);
            n3.add_resolver(i3);
        }

        /* check that were added */
        assert_eq!(store.len(), 6);
        assert_eq!(store.contains(&n1_k), true);
        assert_eq!(store.contains(&n2_k), true);
        assert_eq!(store.contains(&n3_k), true);
        assert_eq!(store.contains(&i1_k), true);
        assert_eq!(store.contains(&i2_k), true);
        assert_eq!(store.contains(&i3_k), true);

        /* check rc counts */
        assert_eq!(store.get_nhop_rc_count(&n1_k), 1);
        assert_eq!(store.get_nhop_rc_count(&n2_k), 1);
        assert_eq!(store.get_nhop_rc_count(&n3_k), 1);
        assert_eq!(store.get_nhop_rc_count(&i1_k), 2);
        assert_eq!(store.get_nhop_rc_count(&i2_k), 2);
        assert_eq!(store.get_nhop_rc_count(&i3_k), 2);

        store.dump();
    }

    #[test]
    fn test_nhop_store_shared_resolvers() {
        let mut store = NhopStore::new();

        let i1_k = NhopKey::with_ifindex(1);

        let n1_k = NhopKey::from_str("11.0.0.1");
        let n2_k = NhopKey::from_str("11.0.0.2");
        let n3_k = NhopKey::from_str("11.0.0.3");

        /* create 3 next-hops all resolving to the same one */
        let i1 = store.add_nhop(&i1_k);
        store.add_nhop(&n1_k).add_resolver(i1.clone());
        store.add_nhop(&n2_k).add_resolver(i1.clone());
        store.add_nhop(&n3_k).add_resolver(i1);
        store.dump();

        assert_eq!(store.len(), 4);
        assert_eq!(store.get_nhop_rc_count(&i1_k), 4);
    }

    /// Create a nhop store with next-hops and dependencies.
    fn build_test_nhop_store() -> NhopStore {
        // create store
        let mut store = NhopStore::new();

        // add "interface" next-hops
        let i1 = store.add_nhop(&NhopKey::with_ifindex(1));
        let i2 = store.add_nhop(&NhopKey::with_ifindex(2));
        let i3 = store.add_nhop(&NhopKey::with_ifindex(3));

        // add "adjacent" nexthops
        let a1 = store.add_nhop(&NhopKey::from_str("10.0.0.1"));
        let a2 = store.add_nhop(&NhopKey::from_str("10.0.0.5"));
        let a3 = store.add_nhop(&NhopKey::from_str("10.0.0.9"));

        // add "non-adjacent" nexthops
        let b1 = store.add_nhop(&NhopKey::from_str("172.16.0.1"));
        let b2 = store.add_nhop(&NhopKey::from_str("172.16.0.2"));

        // add even further next-hop
        let n = store.add_nhop(&NhopKey::from_str("7.0.0.1"));

        /* Add resolvers */
        a1.add_resolver(i1);
        a2.add_resolver(i2);
        a3.add_resolver(i3);

        b1.add_resolver(a1);
        b1.add_resolver(a2.clone());

        b2.add_resolver(a2);
        b2.add_resolver(a3);

        n.add_resolver(b1);
        n.add_resolver(b2);

        store
    }

    /// Create a populated nhop store with inter-nexthop dependencies where some next-hops are partially resolved already
    fn build_test_nhop_store_partially_resolved() -> NhopStore {
        // create store
        let mut store = NhopStore::new();

        // add "adjacent" nexthops with interface resolved
        let a1 = store.add_nhop(&NhopKey::with_addr_ifindex(
            &("10.0.0.1".parse().unwrap()),
            1,
        ));
        let a2 = store.add_nhop(&NhopKey::with_addr_ifindex(
            &("10.0.0.5".parse().unwrap()),
            2,
        ));
        let a3 = store.add_nhop(&NhopKey::with_addr_ifindex(
            &("10.0.0.9".parse().unwrap()),
            3,
        ));

        // add "non-adjacent" nexthops
        let b1 = store.add_nhop(&NhopKey::from_str("172.16.0.1"));
        let b2 = store.add_nhop(&NhopKey::from_str("172.16.0.2"));

        // add even further next-hop
        let n = store.add_nhop(&NhopKey::from_str("7.0.0.1"));

        /* Add resolutions */
        b1.add_resolver(a1);
        b1.add_resolver(a2.clone());

        b2.add_resolver(a2);
        b2.add_resolver(a3);

        n.add_resolver(b1);
        n.add_resolver(b2);

        store
    }

    /// Create a populated nhop store with inter-nexthop dependencies to a drop next-hop
    fn build_test_nhop_store_with_drop_nexthop() -> NhopStore {
        let mut store = NhopStore::new();

        /* drop next-hop */
        let nh_drop = store.add_nhop(&NhopKey::with_drop());

        /* direct resolution to drop */
        store
            .add_nhop(&NhopKey::from_str("172.16.0.1"))
            .add_resolver(nh_drop.clone());

        /* indirect resolution to drop */
        let intermediate = store.add_nhop(&NhopKey::from_str("10.0.0.1"));
        intermediate.add_resolver(nh_drop);

        /* nh that resolves to intermediate */
        store
            .add_nhop(&NhopKey::from_str("7.0.0.1"))
            .add_resolver(intermediate);

        /* add next-hop that does not resolve to anything */
        let _ = store.add_nhop(&NhopKey::from_str("8.0.0.1"));

        store
    }

    #[test]
    fn test_nhop_store_consistency() {
        /* create store */
        let mut store = build_test_nhop_store();
        store.dump();

        /* get the next-hop 7.0.0.1 */
        let key = NhopKey::from_str("7.0.0.1");

        /* It has no extra reference */
        assert_eq!(store.get_nhop_rc_count(&key), 1);

        /* Delete nexthop. Since it has no extra reference it should be gone */
        store.del_nhop(&key);
        assert_eq!(store.contains(&key), false);

        /* ... and since it refers to all other next-hops (indirectly) and no
        other next-hop does, all should be gone too */
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_nhop_store_vanilla_resolution() {
        // create store
        let store = build_test_nhop_store();
        store.dump();

        /* get next-hop 7.0.0.1 */
        let key = NhopKey::from_str("7.0.0.1");
        let n = store.get_nhop(&key).expect("Should be there");

        let res = n.quick_resolve();
        assert_eq!(res.len(), 3, "Should resolve over 3 interfaces");
        for k in res.iter() {
            assert!(k.ifindex.is_some());
        }
        println!("{:#?}", &res);
    }

    #[test]
    /// The same as above, but with adjacent next-hops resolved (i.e. having already ifindex)
    fn test_nhop_store_vanilla_with_partially_resolved() {
        // create store
        let store = build_test_nhop_store_partially_resolved();
        store.dump();

        /* get next-hop 7.0.0.1 */
        let key = NhopKey::from_str("7.0.0.1");
        let n = store.get_nhop(&key).unwrap();

        let res = n.quick_resolve();
        assert_eq!(res.len(), 3, "Should resolve over 3 interfaces");
        for k in res.iter() {
            assert!(k.ifindex.is_some());
        }
        println!("{:#?}", &res);
    }

    #[test]
    fn test_nhopmap_resolution_with_drop() {
        let store = build_test_nhop_store_with_drop_nexthop();
        store.dump();

        {
            let key = NhopKey::from_str("172.16.0.1");
            let n = store.get_nhop(&key).expect("Next-hop should be there");
            let mut res = n.quick_resolve();
            assert_eq!(res.len(), 1, "Should get just one nhop key");
            assert_eq!(
                res.pop_first().expect("Should be there").fwaction,
                FwAction::Drop,
                "It should be drop"
            );
        }
        {
            let key = NhopKey::from_str("7.0.0.1");
            let n = store.get_nhop(&key).expect("Next-hop should be there");
            let mut res = n.quick_resolve();
            assert_eq!(res.len(), 1, "Should get just one nhop key");
            assert_eq!(
                res.pop_first().expect("Should be there").fwaction,
                FwAction::Drop,
                "It should be drop"
            );
        }

        // similar using next-hop store method that looks up the next-hop first
        let res = store.resolve_by_addr(&("7.0.0.1".parse().unwrap()));
        assert!(res.is_some());
        println!("{:#?}", &res);
    }
}
