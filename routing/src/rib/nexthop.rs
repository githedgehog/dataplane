// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Object definitions for (shared) routing next-hops. These
//! refer to other objects like Encapsulation.

use super::encapsulation::Encapsulation;
use super::vrf::{RouteOrigin, Vrf};
use crate::IfTable;
use crate::evpn::RmacStore;
use crate::fib::fibobjects::{FibGroup, PktInstruction};
use ordermap::OrderSet;

use std::fmt::Debug;
use std::hash::Hash;
use std::net::IpAddr;
use std::option::Option;

use net::interface::InterfaceIndex;
use std::cell::Cell;
use std::cell::Ref;
use std::cell::RefCell;
use std::rc::{Rc, Weak};
#[cfg(test)]
use std::str::FromStr;
use tracing::{debug, error, warn};

use tracectl::trace_target;
trace_target!("next-hops", LevelFilter::WARN, &["routing-full"]);

#[derive(Debug)]
/// A next-hop object that can be shared by multiple routes and that can have
/// references to other next-hops in this (or other) table.
pub struct Nhop {
    pub(crate) key: NhopKey,
    pub(crate) ifname: RefCell<Option<String>>,
    resolvers: RefCell<Vec<Weak<Nhop>>>,
    pub(crate) instructions: RefCell<Vec<PktInstruction>>,
    pub(crate) fibgroup: RefCell<FibGroup>,
    pub(crate) invalid: Cell<bool>,
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
#[derive(Debug, Default, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct NhopKey {
    pub origin: RouteOrigin,
    pub address: Option<IpAddr>,
    pub ifindex: Option<InterfaceIndex>,
    pub encap: Option<Encapsulation>,
    pub fwaction: FwAction,
}

impl NhopKey {
    //////////////////////////////////////////////////////////////////
    /// Build a next-hop key
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(
        origin: RouteOrigin,
        address: Option<IpAddr>,
        ifindex: Option<InterfaceIndex>,
        encap: Option<Encapsulation>,
        fwaction: FwAction,
    ) -> Self {
        Self {
            origin,
            address,
            ifindex,
            encap,
            fwaction,
        }
    }
    #[must_use]
    pub fn with_drop() -> Self {
        Self {
            origin: RouteOrigin::default(),
            address: None,
            ifindex: None,
            encap: None,
            fwaction: FwAction::Drop,
        }
    }
    #[cfg(test)]
    pub fn from_address(address: &str) -> Self {
        Self {
            address: Some(IpAddr::from_str(address).expect("Bad address")),
            ..Default::default()
        }
    }
    #[cfg(test)]
    #[must_use]
    pub fn with_addr_ifindex(address: &str, ifindex: u32) -> Self {
        Self {
            address: Some(IpAddr::from_str(address).expect("Bad address")),
            ifindex: Some(InterfaceIndex::try_new(ifindex).expect("Bad ifindex")),
            ..Default::default()
        }
    }
    #[cfg(test)]
    #[must_use]
    pub fn with_address(address: &IpAddr) -> Self {
        Self {
            address: Some(*address),
            ..Default::default()
        }
    }
    #[cfg(test)]
    #[must_use]
    pub fn with_ifindex(ifindex: u32) -> Self {
        Self {
            ifindex: Some(InterfaceIndex::try_new(ifindex).unwrap()),
            ..Default::default()
        }
    }
}

impl Eq for Nhop {}

impl PartialEq for Nhop {
    fn eq(&self, other: &Self) -> bool {
        self.key.eq(&other.key)
    }
}
impl Hash for Nhop {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

type NhopId = *const Nhop;
type Visited = Vec<NhopId>;

impl Nhop {
    /// Create a new Nhop object from a key object
    fn from_key(key: &NhopKey) -> Self {
        Self {
            key: key.clone(),
            resolvers: RefCell::new(Vec::new()),
            instructions: RefCell::new(Vec::with_capacity(2)),
            fibgroup: RefCell::new(FibGroup::new()),
            invalid: Cell::new(false),
            ifname: RefCell::new(None),
        }
    }

    /// Set (overwrite) the ifname for a next-hop. We have to account for the fact that,
    /// temporarily, we may not know the name corresponding to an ifindex.
    pub(crate) fn set_ifname(&self, ifname: &Option<String>) {
        self.ifname.replace(ifname.clone());
    }

    /// Store a weak reference to some Nhop 'resolver' in the current next-hop.
    ///
    /// N.B. like [`Nhop::resolve`], this must leave the resolver graph free of resolution
    /// loops, since the walks over the resolvers of a next-hop rely on that (see
    /// `Nhop::build_nhop_fibgroup`). So, adding a resolver that resolves back to this
    /// next-hop is a bug and panics.
    #[cfg(test)]
    pub fn add_resolver(&self, resolver: &Rc<Nhop>) -> &Self {
        assert!(
            !resolver.resolves_with(self),
            "Resolver {resolver} of next-hop {self} would create a resolution loop"
        );
        let Ok(mut resolvers) = self.resolvers.try_borrow_mut() else {
            error!("Failed to add resolver: try-borrow-mut failed!. Nhop={self:#?}");
            return self;
        };
        resolvers.push(Rc::downgrade(resolver));
        self
    }

    fn id(&self) -> NhopId {
        std::ptr::from_ref(self)
    }

    /// The resolvers of a next-hop, or `None` if they cannot be borrowed. N.B. this is
    /// the only access to the resolvers from outside of this module: [`Nhop::resolve`] is
    /// their sole writer, which keeps the resolution graph free of loops.
    pub(crate) fn get_resolvers(&self) -> Option<Ref<'_, [Weak<Nhop>]>> {
        let Ok(resolvers) = self.resolvers.try_borrow() else {
            error!("Try-borrow on next-hop resolvers failed!");
            return None;
        };
        Some(Ref::map(resolvers, Vec::as_slice))
    }

    #[cfg(test)]
    fn resolves_with(&self, checked: &Nhop) -> bool {
        self.resolves_with_rec(checked, &mut Visited::new())
    }

    #[cfg(test)]
    fn resolves_with_rec(&self, checked: &Nhop, visited: &mut Visited) -> bool {
        if self.id() == checked.id() {
            error!("Loop detected for next-hop {}!", self.key);
            return true;
        }
        if visited.contains(&self.id()) {
            return false;
        }
        visited.push(self.id());

        // resolvers should not refer back to the checked next-hop
        let resolvers = self.resolvers.borrow();
        resolvers
            .iter()
            .filter_map(Weak::upgrade)
            .any(|res| res.resolves_with_rec(checked, visited))
    }

    /// Tell if a next-hop requires resolution
    pub(super) fn must_be_resolved(&self) -> bool {
        self.key.ifindex.is_none() && self.key.fwaction != FwAction::Drop
    }

    /// Tell if a next-hop requires resolution but could not be resolved. This is the
    /// authoritative statement about the usability of a next-hop.
    #[must_use]
    pub(crate) fn is_unresolved(&self) -> bool {
        self.must_be_resolved()
            && self
                .resolvers
                .try_borrow()
                .is_ok_and(|resolvers| resolvers.is_empty())
    }

    /// Tell if a next hop requires resolution and if that's possible. If so,
    /// return the address to resolve
    fn get_resolution_target(&self) -> Option<IpAddr> {
        if !self.must_be_resolved() {
            return None;
        }
        let Some(a) = self.key.address else {
            error!("Found nexthop with neither address nor ifindex!: {self}");
            return None;
        };
        Some(a)
    }

    /// Resolve a next-hop with a VRF, recursively. On return, this next-hop and every
    /// next-hop it recursively resolves to have up-to-date resolvers, and this next-hop
    /// is usable (resolved) iff it needs no resolution or has a usable resolver.
    ///
    /// N.B. this resolves a single next-hop completely, without requiring every next-hop
    /// in the [`NhopStore`] to be resolved (see [`NhopStore::resolve_all`]), which allows
    /// resolving only the next-hops of, say, a single route.
    pub fn resolve(&self, vrf: &Vrf) {
        self.resolve_rec(vrf, &mut Visited::new());
    }

    /// Recursive helper for [`Nhop::resolve`]. `path` is the chain of next-hops that we
    /// are resolving, excluding `Self`. Returns true if the next-hop is usable.
    fn resolve_rec(&self, vrf: &Vrf, path: &mut Visited) -> bool {
        if path.contains(&self.id()) {
            debug!("Skipping next-hop {self}: it would cause a resolution loop");
            return false;
        }
        if !self.must_be_resolved() {
            debug!("Nhop {self} requires no resolution");
            return true; // always usable
        }
        let Some(target) = self.get_resolution_target() else {
            return false;
        };

        let name = &vrf.name;
        let (prefix, route) = vrf.lpm(target);
        debug!("Address {target} resolves with route to {prefix} in vrf {name}");

        // resolve the next-hops of the resolving route and collect the usable ones
        path.push(self.id());
        let mut resolvers = Vec::with_capacity(route.s_nhops.len());
        for nhop in &route.s_nhops {
            let resolver = &nhop.rc;
            if resolver.resolve_rec(vrf, path) {
                debug!(" {target} -> {resolver}");
                resolvers.push(Rc::downgrade(resolver));
            }
        }
        path.pop();

        // a single usable resolver suffices to make this next-hop usable
        if resolvers.is_empty() {
            warn!(
                "Cannot resolve address {target} with vrf {name}: {} route to {prefix} has no usable next-hop",
                route.origin
            );
            // Finding no usable resolver may be down to the path we came from, since we
            // had to skip every next-hop in it. So, keep the resolvers that the next-hops
            // in the path already had: they will be resolved on their own. Only the
            // next-hop that we were asked to resolve (the one with an empty path) gets its
            // resolvers cleared.
            if !path.is_empty() {
                return false; // unusable
            }
        }

        // update resolvers (N.B: resolvers may be empty)
        let usable = !resolvers.is_empty();
        self.resolvers.replace(resolvers);
        usable
    }
}

#[derive(Debug)]
/// A collection of unique next-hops. Next-hops are identified by a next-hop key
/// that can contain an address, ifindex and encapsulation.
pub(crate) struct NhopStore(OrderSet<Rc<Nhop>>);

impl NhopStore {
    /// Create a next-hop map object.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(OrderSet::new())
    }

    /// Get the number of next-hops in the store
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Tell if the next-hop store is empty
    #[must_use]
    #[allow(unused)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Add a next hop with a given key (if it does not exist already)
    /// and return an owning reference to it.
    #[must_use]
    pub(crate) fn add_nhop(&mut self, key: &NhopKey) -> Rc<Nhop> {
        let nh = Rc::new(Nhop::from_key(key));
        if let Some(e) = self.0.get(&nh) {
            Rc::clone(e)
        } else {
            self.0.insert(Rc::clone(&nh));
            debug!("Registered new next-hop {nh}");
            nh
        }
    }

    /// Get the Rc strong count of the next-hop with some key.
    #[must_use]
    #[allow(unused)]
    pub(crate) fn nhop_strong_count(&self, key: &NhopKey) -> usize {
        self.get_nhop(key).map_or(0, Rc::strong_count)
    }

    /// Get the Rc weak count of the next-hop with some key.
    #[must_use]
    #[allow(unused)]
    pub(crate) fn nhop_weak_count(&self, key: &NhopKey) -> usize {
        self.get_nhop(key).map_or(0, Rc::weak_count)
    }

    /// Get a reference to the next-hop with a given key, if it exists.
    /// Unlike `add_nhop()`, this returns a `&Rc<Nhop>` and not `Rc<Nhop>`
    /// thereby not increasing the refcount of the next-hop.
    #[must_use]
    #[allow(unused)]
    pub(crate) fn get_nhop(&self, key: &NhopKey) -> Option<&Rc<Nhop>> {
        let nh = Nhop::from_key(key);
        self.0.get(&nh)
    }

    /// Declare that a next-hop is no longer of interest. The nhop may be removed or
    /// not, depending on whether there are other references to it. This method returns
    /// true if the next-hop was removed and false otherwise.
    pub(crate) fn del_nhop(&mut self, key: &NhopKey) -> bool {
        let target = Nhop::from_key(key);
        if let Some(existing) = self.0.get(&target) {
            if Rc::strong_count(existing) == 1 {
                let r = self.0.remove(&target);
                debug_assert!(r);
                if r {
                    debug!("Removed next-hop {key}");
                }
                return r;
            }
        }
        false
    }

    /// Iterate over all next-hops in the next-hop store
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Rc<Nhop>> {
        self.0.iter()
    }

    /// Rebuild the instructions for all next-hops
    pub fn rebuild_nhop_instructions(&self, rstore: &RmacStore) {
        for nhop in self.iter() {
            nhop.build_nhop_instructions(rstore);
        }
    }

    /// Flush all resolution state of all next-hops
    fn flush_resolvers(&self) {
        for nhop in self.iter() {
            nhop.resolvers.borrow_mut().clear();
        }
    }

    /// Flush all resolution state and re-resolve all next-hops.
    pub fn resolve_all(&self, vrf: &Vrf) {
        self.flush_resolvers();
        self.iter().for_each(|nhop| nhop.resolve(vrf));
    }

    /// Rebuild the fibgroup for every next-hop. This method visits every next-hop and
    /// rebuilds its fibgroup. It returns a vector with only those next-hops whose
    /// fibgroup changed. We return a Vector and not an iterator to force the rebuild
    /// of the fibgroups. N.B. we hand out weak references and not owning ones so as to
    /// not alter the strong count of the next-hops, which tells how many routes use them
    /// and determines if a next-hop can be removed (see `NhopStore::del_nhop()`).
    pub fn rebuild_fibgroups(&self) -> Vec<Weak<Nhop>> {
        self.iter()
            .filter(|nhop| nhop.set_fibgroup())
            .map(Rc::downgrade)
            .collect()
    }

    /// Set the ifname for all nhops that have an ifindex, according to the interface table
    /// This method is for future use
    #[allow(unused)]
    pub fn refresh_nhop_ifnames_all(&self, iftable: &IfTable) {
        self.iter().for_each(|nhop| {
            if let Some(ifindex) = &nhop.key.ifindex {
                let ifname = iftable
                    .get_interface(*ifindex)
                    .map(|iface| iface.name.clone());

                let current = nhop.ifname.borrow();
                let update = *current != ifname;
                drop(current);
                if update {
                    nhop.set_ifname(&ifname);
                }
            }
        });
    }

    /// Update the ifname of all next-hops with a given ifindex.
    /// This method is for future use
    #[allow(unused)]
    pub fn refresh_nhop_ifname(&self, ifindex: InterfaceIndex, ifname: &String) {
        self.iter()
            .filter(|nhop| nhop.key.ifindex == Some(ifindex))
            .for_each(|nhop| nhop.set_ifname(&Some(ifname.clone())));
    }
}

#[cfg(test)]
impl NhopStore {
    /// Tell if there exists a next-hop with a given key.
    #[must_use]
    pub(crate) fn contains(&self, key: &NhopKey) -> bool {
        let nh = Nhop::from_key(key);
        self.0.contains(&nh)
    }

    /// Dump the contents of the next-hop map
    pub(crate) fn dump(&self) {
        print!("{self}");
    }
}

#[cfg(test)]
mod tests {
    use crate::evpn::RmacStore;
    use crate::fib::fibobjects::{EgressObject, FibEntry, FibGroup, PktInstruction};
    use crate::rib::nexthop::*;
    use crate::rib::vrf::tests::{build_test_nhop, build_test_route, mk_addr};
    use crate::rib::vrf::{RouteNhop, RouterVrfConfig};
    use lpm::prefix::Prefix;
    use std::rc::Rc;
    use tracing_test::traced_test;

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    /// Tests the correct behavior of the next-hop store
    fn test_nhop_store_minimal() {
        let mut store = NhopStore::new();
        let nh_key = NhopKey::from_address("10.0.1.1");

        // add a nhop
        let nhref = store.add_nhop(&nh_key);
        assert_eq!(store.nhop_strong_count(&nh_key), 2);
        drop(nhref);
        assert_eq!(store.nhop_strong_count(&nh_key), 1);

        // check presence
        assert!(store.contains(&nh_key));

        // check get() does not increment the refcount
        let nh = store.get_nhop(&nh_key).expect("Should find it");
        assert_eq!(Rc::strong_count(nh), 1, "Must be 1");

        // check refcount
        let num_refs = store.nhop_strong_count(&nh_key);
        assert_eq!(num_refs, 1);
        store.dump();
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    /// Tests the correct deletion of next-hops
    fn test_nhop_reuse_and_deletion() {
        let mut store = NhopStore::new();
        let nh_key = NhopKey::from_address("10.0.1.1");

        // add a nhop and keep a reference to it
        let r1 = store.add_nhop(&nh_key);
        assert_eq!(Rc::strong_count(&r1), 2);

        // check it's there
        assert!(store.contains(&nh_key));

        // add again: no new next-hop should be added
        let r2 = store.add_nhop(&nh_key);
        assert_eq!(store.len(), 1);

        // get it: since add_nhop returns a reference and we keep it, refcount should be 3
        let nh = store.get_nhop(&nh_key).unwrap();
        assert_eq!(Rc::strong_count(nh), 3);

        // check refcount
        let num_refs = store.nhop_strong_count(&nh_key);
        assert_eq!(num_refs, 3);

        // drop references
        let _ = nh;
        drop(r1);
        assert!(!store.del_nhop(&nh_key));
        assert_eq!(store.nhop_strong_count(&nh_key), 2);
        drop(r2);
        assert_eq!(store.nhop_strong_count(&nh_key), 1);
        assert!(store.del_nhop(&nh_key));
        assert_eq!(store.len(), 0);
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    /// Tests the correctness of next-hops reference counts
    fn test_nhop_ref_counts() {
        let mut store = NhopStore::new();

        // Create KEYS for some next-hops
        let n1_k = NhopKey::from_address("10.0.1.1");
        let n2_k = NhopKey::from_address("10.0.2.1");
        let n3_k = NhopKey::from_address("10.0.3.1");

        let i1_k = NhopKey::with_ifindex(1);
        let i2_k = NhopKey::with_ifindex(2);
        let i3_k = NhopKey::with_ifindex(3);

        // Add some next-hops and references
        {
            /* Use separate scope so that all refs the APIs returns
            get dropped at the end of it. This is just for testing. */
            let n1 = store.add_nhop(&n1_k);
            let n2 = store.add_nhop(&n2_k);
            let n3 = store.add_nhop(&n3_k);

            let i1 = store.add_nhop(&i1_k);
            let i2 = store.add_nhop(&i2_k);
            let i3 = store.add_nhop(&i3_k);
            n1.add_resolver(&i1);
            n2.add_resolver(&i2);
            n3.add_resolver(&i3);
        }

        // check they were added
        assert_eq!(store.len(), 6);
        assert!(store.contains(&n1_k));
        assert!(store.contains(&n2_k));
        assert!(store.contains(&n3_k));
        assert!(store.contains(&i1_k));
        assert!(store.contains(&i2_k));
        assert!(store.contains(&i3_k));

        // counts
        assert_eq!(store.nhop_strong_count(&n1_k), 1);
        assert_eq!(store.nhop_strong_count(&n2_k), 1);
        assert_eq!(store.nhop_strong_count(&n3_k), 1);
        assert_eq!(store.nhop_weak_count(&i1_k), 1);
        assert_eq!(store.nhop_weak_count(&i2_k), 1);
        assert_eq!(store.nhop_weak_count(&i3_k), 1);

        store.dump();
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_nhop_store_shared_resolvers() {
        let mut store = NhopStore::new();

        let i1_k = NhopKey::with_ifindex(1);
        let n1_k = NhopKey::from_address("11.0.0.1");
        let n2_k = NhopKey::from_address("11.0.0.2");
        let n3_k = NhopKey::from_address("11.0.0.3");
        let n4_k = NhopKey::from_address("11.0.0.4");
        let n5_k = NhopKey::from_address("11.0.0.5");

        /* create 5 next-hops all resolving to the same one */
        let i1 = store.add_nhop(&i1_k);
        store.add_nhop(&n1_k).add_resolver(&i1);
        store.add_nhop(&n2_k).add_resolver(&i1);
        store.add_nhop(&n3_k).add_resolver(&i1);
        store.add_nhop(&n4_k).add_resolver(&i1);
        store.add_nhop(&n5_k).add_resolver(&i1);
        store.dump();

        assert_eq!(store.len(), 6);
        assert_eq!(store.nhop_strong_count(&i1_k), 2);

        /* remove one next-hop */
        store.del_nhop(&n5_k);
        assert_eq!(store.len(), 5);
        assert_eq!(store.nhop_strong_count(&i1_k), 2);
        store.dump();

        /* remove rest of next-hops */
        store.del_nhop(&n4_k);
        store.del_nhop(&n3_k);
        store.del_nhop(&n2_k);
        store.del_nhop(&n1_k);
        assert_eq!(store.len(), 1);

        /* remove common resolver */
        drop(i1);
        store.del_nhop(&i1_k);
        assert!(store.is_empty());
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    /// Tests flushing of next-hop resolution data
    fn test_nhop_store_flush_resolvers() {
        let mut store = NhopStore::new();

        let i1_k = NhopKey::with_ifindex(1);

        let n1_k = NhopKey::from_address("11.0.0.1");
        let n2_k = NhopKey::from_address("11.0.0.2");
        let n3_k = NhopKey::from_address("11.0.0.3");
        let n4_k = NhopKey::from_address("11.0.0.4");
        let n5_k = NhopKey::from_address("11.0.0.5");

        /* create 5 next-hops all resolving to the same one */
        let i1 = store.add_nhop(&i1_k);
        store.add_nhop(&n1_k).add_resolver(&i1);
        store.add_nhop(&n2_k).add_resolver(&i1);
        store.add_nhop(&n3_k).add_resolver(&i1);
        store.add_nhop(&n4_k).add_resolver(&i1);
        store.add_nhop(&n5_k).add_resolver(&i1);
        drop(i1);
        assert_eq!(store.nhop_weak_count(&i1_k), 5); // used to resolve 5 nexthops
        store.dump();
        store.flush_resolvers();
        assert_eq!(store.nhop_weak_count(&i1_k), 0); // used to resolve 0 nexthops
        store.dump();
    }

    /// Create a nhop store with next-hops and dependencies.
    fn build_test_nhop_store() -> NhopStore {
        /* create store */
        let mut store = NhopStore::new();

        /* add "interface" next-hops */
        let i1 = store.add_nhop(&NhopKey::with_ifindex(1));
        let i2 = store.add_nhop(&NhopKey::with_ifindex(2));
        let i3 = store.add_nhop(&NhopKey::with_ifindex(3));

        /* add "adjacent" nexthops */
        let a1 = store.add_nhop(&NhopKey::from_address("10.0.0.1"));
        let a2 = store.add_nhop(&NhopKey::from_address("10.0.0.5"));
        let a3 = store.add_nhop(&NhopKey::from_address("10.0.0.9"));

        /* add "non-adjacent" nexthops */
        let b1 = store.add_nhop(&NhopKey::from_address("172.16.0.1"));
        let b2 = store.add_nhop(&NhopKey::from_address("172.16.0.2"));

        /* add even farther next-hop */
        let n = store.add_nhop(&NhopKey::from_address("7.0.0.1"));

        /* Add resolvers */
        a1.add_resolver(&i1);
        a2.add_resolver(&i2);
        a3.add_resolver(&i3);

        b1.add_resolver(&a1);
        b1.add_resolver(&a2);

        b2.add_resolver(&a2);
        b2.add_resolver(&a3);

        n.add_resolver(&b1);
        n.add_resolver(&b2);

        store
    }

    /// Create a populated nhop store with inter-nexthop dependencies where some next-hops are partially resolved already
    fn build_test_nhop_store_partially_resolved() -> NhopStore {
        /* create store */
        let mut store = NhopStore::new();

        /* add "adjacent" nexthops with interface resolved */
        let a1 = store.add_nhop(&NhopKey::with_addr_ifindex("10.0.0.1", 1));
        let a2 = store.add_nhop(&NhopKey::with_addr_ifindex("10.0.0.5", 2));
        let a3 = store.add_nhop(&NhopKey::with_addr_ifindex("10.0.0.9", 3));

        // add "non-adjacent" nexthops
        let b1 = store.add_nhop(&NhopKey::from_address("172.16.0.1"));
        let b2 = store.add_nhop(&NhopKey::from_address("172.16.0.2"));

        // add even further next-hop
        let n = store.add_nhop(&NhopKey::from_address("7.0.0.1"));

        /* Add resolutions */
        b1.add_resolver(&a1);
        b1.add_resolver(&a2);

        b2.add_resolver(&a2);
        b2.add_resolver(&a3);

        n.add_resolver(&b1);
        n.add_resolver(&b2);

        store
    }

    /// Create a populated nhop store with inter-nexthop dependencies to a drop next-hop
    fn build_test_nhop_store_with_drop_nexthop() -> NhopStore {
        let mut store = NhopStore::new();

        /* drop next-hop */
        let nh_drop = store.add_nhop(&NhopKey::with_drop());

        /* direct resolution to drop */
        store
            .add_nhop(&NhopKey::from_address("172.16.0.1"))
            .add_resolver(&nh_drop);

        /* indirect resolution to drop */
        let intermediate = store.add_nhop(&NhopKey::from_address("10.0.0.1"));
        intermediate.add_resolver(&nh_drop);

        /* nh that resolves to intermediate */
        store
            .add_nhop(&NhopKey::from_address("7.0.0.1"))
            .add_resolver(&intermediate);

        /* add next-hop that does not resolve to anything */
        let _ = store.add_nhop(&NhopKey::from_address("8.0.0.1"));

        store
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_nhop_store_consistency() {
        /* create store */
        let mut store = build_test_nhop_store();
        store.dump();

        /* get the next-hop 7.0.0.1 */
        let key = NhopKey::from_address("7.0.0.1");

        /* It has no extra reference */
        assert_eq!(store.nhop_strong_count(&key), 1);
        store.dump();

        /* check resolvers refcount */
        assert_eq!(
            store.nhop_weak_count(&NhopKey::from_address("172.16.0.1")),
            1
        );
        assert_eq!(
            store.nhop_weak_count(&NhopKey::from_address("172.16.0.2")),
            1
        );

        /* Delete nexthop. Since it has no extra reference it should be gone */
        store.del_nhop(&key);
        assert!(!store.contains(&key));

        /* resolvers refcount is decreased */
        assert_eq!(
            store.nhop_weak_count(&NhopKey::from_address("172.16.0.1")),
            0
        );
        assert_eq!(
            store.nhop_weak_count(&NhopKey::from_address("172.16.0.2")),
            0
        );
    }

    /// The distinct egress objects that the entries of a fibgroup send traffic out with,
    /// sorted. This is what the resolution of a next-hop amounts to, as the fib sees it.
    fn egress_objects(fibgroup: &FibGroup) -> Vec<EgressObject> {
        let mut egress: Vec<EgressObject> = fibgroup
            .iter()
            .flat_map(FibEntry::iter)
            .filter_map(|instruction| {
                if let PktInstruction::Egress(egress) = instruction {
                    Some(egress.clone())
                } else {
                    None
                }
            })
            .collect();
        egress.sort();
        egress.dedup();
        egress
    }

    fn egress(ifindex: u32, address: &str) -> EgressObject {
        EgressObject::new(
            InterfaceIndex::try_new(ifindex).ok(),
            Some(mk_addr(address)),
            None,
        )
    }

    /// The fibgroup of a next-hop that resolves to nothing usable
    fn drops(fibgroup: &FibGroup) -> bool {
        fibgroup.entries() == &vec![FibEntry::drop_fibentry()]
    }

    #[test]
    fn test_nhop_store_vanilla_resolution() {
        // create store
        let store = build_test_nhop_store();
        store.rebuild_nhop_instructions(&RmacStore::new());
        store.dump();

        /* get next-hop 7.0.0.1 */
        let key = NhopKey::from_address("7.0.0.1");
        let n = store.get_nhop(&key).expect("Should be there");

        let fibgroup = n.build_nhop_fibgroup();
        println!("{fibgroup}");
        assert_eq!(fibgroup.len(), 4, "Should resolve over 4 paths");
        assert_eq!(
            egress_objects(&fibgroup),
            vec![
                egress(1, "10.0.0.1"),
                egress(2, "10.0.0.5"),
                egress(3, "10.0.0.9"),
            ],
            "Should resolve over 3 interfaces"
        );
    }

    #[test]
    /// The same as above, but with adjacent next-hops resolved (i.e. having already ifindex)
    fn test_nhop_store_vanilla_with_partially_resolved() {
        // create store
        let store = build_test_nhop_store_partially_resolved();
        store.rebuild_nhop_instructions(&RmacStore::new());
        store.dump();

        /* get next-hop 7.0.0.1 */
        let key = NhopKey::from_address("7.0.0.1");
        let n = store.get_nhop(&key).unwrap();

        let fibgroup = n.build_nhop_fibgroup();
        println!("{fibgroup}");
        assert_eq!(fibgroup.len(), 4, "Should resolve over 4 paths");
        assert_eq!(
            egress_objects(&fibgroup),
            vec![
                egress(1, "10.0.0.1"),
                egress(2, "10.0.0.5"),
                egress(3, "10.0.0.9"),
            ],
            "Should resolve over 3 interfaces"
        );
    }

    #[test]
    fn test_nhopmap_resolution_with_drop() {
        let store = build_test_nhop_store_with_drop_nexthop();
        store.rebuild_nhop_instructions(&RmacStore::new());
        store.dump();

        // 172.16.0.1 resolves to the drop next-hop directly
        {
            let key = NhopKey::from_address("172.16.0.1");
            let n = store.get_nhop(&key).expect("Next-hop should be there");
            assert!(drops(&n.build_nhop_fibgroup()), "Traffic must be dropped");
        }
        // 7.0.0.1 resolves to it over 10.0.0.1
        {
            let key = NhopKey::from_address("7.0.0.1");
            let n = store.get_nhop(&key).expect("Next-hop should be there");
            assert!(drops(&n.build_nhop_fibgroup()), "Traffic must be dropped");
        }
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_must_be_resolved() {
        // a drop next-hop requires no resolution
        let nhop = Nhop::from_key(&NhopKey::with_drop());
        assert!(!nhop.must_be_resolved());

        // a next-hop with only address requires resolution
        let nhop = Nhop::from_key(&NhopKey::from_address("7.0.0.1"));
        assert!(nhop.must_be_resolved());

        // a next-hop with address and ifindex does not require resolution
        let nhop = Nhop::from_key(&NhopKey::with_addr_ifindex("7.0.0.1", 13));
        assert!(!nhop.must_be_resolved());
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    /// An unresolved next-hop (requiring resolution) produces a drop `FibGroup`
    fn test_unresolved_nhop_drops_traffic() {
        let store = build_test_nhop_store_with_drop_nexthop();

        // 8.0.0.1 resolves to nothing */
        let key = NhopKey::from_address("8.0.0.1");
        let nhop = store.get_nhop(&key).expect("Next-hop should be there");
        assert!(nhop.must_be_resolved());
        assert!(nhop.is_unresolved());

        let fibgroup = nhop.build_nhop_fibgroup();
        assert_eq!(fibgroup.len(), 1, "Should get a single fib entry");
        assert_eq!(
            fibgroup.entries()[0],
            FibEntry::drop_fibentry(),
            "Traffic to an unresolved next-hop must be dropped"
        );
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_unresolved_nhop_is_fib_ignored() {
        let mut store = NhopStore::new();

        // 7.0.0.1 resolves over interface 1 and 9.9.9.9 (unresolved) */
        let i1 = store.add_nhop(&NhopKey::with_ifindex(1));
        let unresolved = store.add_nhop(&NhopKey::from_address("9.9.9.9"));
        let key = NhopKey::from_address("7.0.0.1");
        let nhop = store.add_nhop(&key);
        nhop.add_resolver(&i1).add_resolver(&unresolved);
        store.rebuild_nhop_instructions(&RmacStore::new());
        store.dump();

        // Fibgroup gets only one entry over interface
        let fibgroup = nhop.build_nhop_fibgroup();
        assert_eq!(fibgroup.len(), 1, "Only the usable path should be there");
        let entry = &fibgroup.entries()[0];
        assert!(matches!(
            entry.iter().next().expect("Should have an instruction"),
            PktInstruction::Egress(_)
        ));
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_nhop_instruction_build_and_fibgroup() {
        let rmac_store = RmacStore::new();
        let mut store = NhopStore::new();

        let nh1 = store.add_nhop(&NhopKey::from_address("7.0.0.1"));
        let nh2 = store.add_nhop(&NhopKey::from_address("8.0.0.2"));
        let nh3 = store.add_nhop(&NhopKey::from_address("10.0.0.1"));
        let nh4 = store.add_nhop(&NhopKey::with_ifindex(1));

        let nh3_1 = store.add_nhop(&NhopKey::from_address("10.0.1.1"));
        let nh5 = store.add_nhop(&NhopKey::with_ifindex(2));

        nh1.add_resolver(&nh2);
        nh2.add_resolver(&nh3);
        nh2.add_resolver(&nh3_1);
        nh3.add_resolver(&nh4);
        nh3_1.add_resolver(&nh5);

        // build the instructions of all next-hops
        store.rebuild_nhop_instructions(&rmac_store);

        // check: next-hop nh1 has a single instruction with its address
        let instructions = nh1.instructions.borrow();
        assert_eq!(instructions.len(), 1);
        let inst = &instructions[0];
        assert!(
            matches!(inst, PktInstruction::Egress(e) if e.address().unwrap() == IpAddr::from_str("7.0.0.1").unwrap())
        );

        // check: the fibgroup for nh1 contains 2 fibentries, each with a single instruction egress
        // with the right addresses and interface indices
        let fibgroup = nh1.build_nhop_fibgroup();
        assert_eq!(fibgroup.len(), 2);
        let e1 = &fibgroup.entries()[0];
        let e2 = &fibgroup.entries()[1];
        assert_eq!(e1.len(), 1);
        assert_eq!(e2.len(), 1);
        assert_ne!(e1, e2);

        assert!(matches!(&e1.instructions[0], PktInstruction::Egress(e)
                if e.ifindex().unwrap().to_u32() == 1 && e.address().unwrap() == IpAddr::from_str("10.0.0.1").unwrap()
                || e.ifindex().unwrap().to_u32() == 2 && e.address().unwrap() == IpAddr::from_str("10.0.1.1").unwrap()));

        assert!(matches!(&e2.instructions[0], PktInstruction::Egress(e)
                if e.ifindex().unwrap().to_u32() == 1 && e.address().unwrap() == IpAddr::from_str("10.0.0.1").unwrap()
                || e.ifindex().unwrap().to_u32() == 2 && e.address().unwrap() == IpAddr::from_str("10.0.1.1").unwrap()));
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_sanity_drop_fibentry() {
        let rmac_store = RmacStore::new();
        let mut store = NhopStore::new();

        let nh1 = store.add_nhop(&NhopKey::from_address("7.0.0.1"));
        let nh2 = store.add_nhop(&NhopKey::from_address("8.0.0.2"));
        let nh3 = store.add_nhop(&NhopKey::from_address("10.0.0.1"));
        nh1.add_resolver(&nh2);
        nh2.add_resolver(&nh3);

        // build the instructions of all next-hops
        store.rebuild_nhop_instructions(&rmac_store);

        // check: next-hop nh1 has a single instruction with its address
        let instructions = nh1.instructions.borrow();
        assert_eq!(instructions.len(), 1);
        let inst = &instructions[0];
        assert!(
            matches!(inst, PktInstruction::Egress(e) if e.address().unwrap() == IpAddr::from_str("7.0.0.1").unwrap())
        );

        // check: the fibgroup for nh1 contains 1 fib entry drop, in spite of the egress instruction, since
        // the resulting fibentry would not be valid.
        let fibgroup = nh1.build_nhop_fibgroup();
        assert_eq!(fibgroup.len(), 1);
        let e1 = &fibgroup.entries()[0];
        assert_eq!(e1.len(), 1);
        assert!(matches!(&e1.instructions[0], PktInstruction::Drop));
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_loop_prevention() {
        let mut store = NhopStore::new();

        let i1_k = NhopKey::with_ifindex(1);
        let i2_k = NhopKey::with_ifindex(2);
        let a = NhopKey::from_address("10.0.1.1");
        let b = NhopKey::from_address("10.0.2.1");
        let x = NhopKey::from_address("192.168.1.1");
        let y = NhopKey::from_address("192.168.2.1");
        let checked = NhopKey::from_address("7.0.0.1");

        let i1 = store.add_nhop(&i1_k);
        let i2 = store.add_nhop(&i2_k);
        let a = store.add_nhop(&a);
        let b = store.add_nhop(&b);
        let x = store.add_nhop(&x);
        let y = store.add_nhop(&y);
        let checked = store.add_nhop(&checked);

        a.add_resolver(&i1);
        b.add_resolver(&i2);
        x.add_resolver(&a);
        y.add_resolver(&b);
        checked.add_resolver(&x);
        checked.add_resolver(&y);

        store.dump();

        assert!(!i1.resolves_with(checked.as_ref()));
        assert!(!i1.resolves_with(a.as_ref()));
        assert!(!i1.resolves_with(x.as_ref()));
        assert!(!a.resolves_with(x.as_ref()));

        assert!(i1.resolves_with(i1.as_ref()));
        assert!(a.resolves_with(i1.as_ref()));
        assert!(x.resolves_with(i1.as_ref()));

        assert!(!y.resolves_with(checked.as_ref()));
        assert!(!a.resolves_with(checked.as_ref()));
        assert!(!x.resolves_with(checked.as_ref()));

        // a resolver added later is accounted for, transitively
        x.add_resolver(&b);
        assert!(x.resolves_with(b.as_ref()));
        assert!(x.resolves_with(i2.as_ref()));
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    #[should_panic(expected = "would create a resolution loop")]
    /// A resolver that resolves back to the next-hop being resolved must never be stored:
    /// the walks over the resolvers of a next-hop rely on there being no loop in them
    fn test_add_resolver_refuses_a_resolution_loop() {
        let mut store = NhopStore::new();
        let a = store.add_nhop(&NhopKey::from_address("7.0.0.1"));
        let b = store.add_nhop(&NhopKey::from_address("8.0.0.2"));
        a.add_resolver(&b);
        b.add_resolver(&a);
    }

    /// Build a VRF with two connected routes, over interfaces 1 and 2, and no other route
    fn build_test_vrf_connected_only() -> Vrf {
        let mut vrf = Vrf::new(&RouterVrfConfig::new(0, "default"));
        add_connected_route(&mut vrf, ("10.0.0.0", 30), 1);
        add_connected_route(&mut vrf, ("10.0.1.0", 30), 2);
        vrf
    }

    /// Add a route to a test VRF over the given next-hop addresses, resolving its
    /// next-hops as production code does
    fn add_test_route(vrf: &mut Vrf, prefix: (&str, u8), vias: &[&str]) {
        let nhops: Vec<RouteNhop> = vias
            .iter()
            .map(|via| build_test_nhop(Some(via), None, 0, None))
            .collect();
        add_test_route_nhops(vrf, prefix, &nhops);
    }

    /// Add a connected route to a test VRF over the given interface
    fn add_connected_route(vrf: &mut Vrf, prefix: (&str, u8), ifindex: u32) {
        add_test_route_nhops(
            vrf,
            prefix,
            &[build_test_nhop(None, Some(ifindex), 0, None)],
        );
    }

    fn add_test_route_nhops(vrf: &mut Vrf, prefix: (&str, u8), nhops: &[RouteNhop]) {
        let route = build_test_route(RouteOrigin::Bgp, 0, 1);
        let prefix = Prefix::expect_from(prefix);
        vrf.add_route_complete(&prefix, route, nhops, None, &RmacStore::new());
    }

    /// Get the next-hop with the given address from the store of a VRF. N.B. we hand out
    /// a reference so as to not alter the strong count of the next-hop
    fn get_test_nhop<'a>(vrf: &'a Vrf, address: &str) -> &'a Rc<Nhop> {
        vrf.nhstore
            .get_nhop(&NhopKey::from_address(address))
            .expect("Next-hop should be there")
    }

    /// The addresses of the resolvers of a next-hop, sorted
    fn resolver_addresses(nhop: &Nhop) -> Vec<Option<IpAddr>> {
        let mut addresses: Vec<Option<IpAddr>> = nhop
            .resolvers
            .borrow()
            .iter()
            .filter_map(Weak::upgrade)
            .map(|r| r.key.address)
            .collect();
        addresses.sort();
        addresses
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    /// Resolving a single next-hop resolves the next-hops it depends on, recursively:
    /// resolving every next-hop in the store is not needed for the result to be complete
    fn test_nhop_resolve_is_recursive() {
        let mut vrf = build_test_vrf_connected_only();

        // 8.0.0.1 is reachable over 10.0.0.1, itself reachable over interface 1
        add_test_route(&mut vrf, ("8.0.0.1", 32), &["10.0.0.1"]);
        add_test_route(&mut vrf, ("7.0.0.1", 32), &["8.0.0.1"]);
        vrf.nhstore.flush_resolvers();

        // resolving the next-hop of the route to 7.0.0.1 resolves the whole chain
        let nhop = get_test_nhop(&vrf, "8.0.0.1");
        nhop.resolve(&vrf);
        vrf.dump(Some("After resolving next-hop 8.0.0.1"));

        assert!(!nhop.is_unresolved());
        assert_eq!(resolver_addresses(nhop), vec![Some(mk_addr("10.0.0.1"))]);

        let resolver = get_test_nhop(&vrf, "10.0.0.1");
        assert!(
            !resolver.is_unresolved(),
            "The resolvers of a next-hop must be resolved too"
        );
        assert_eq!(
            resolver_addresses(resolver),
            vec![None],
            "Should resolve to an interface"
        );

        // with the chain complete, the next-hop gets a fibgroup that forwards traffic
        nhop.set_fibgroup();
        let fibgroup = nhop.fibgroup.borrow();
        assert_eq!(fibgroup.len(), 1);
        assert_ne!(fibgroup.entries()[0], FibEntry::drop_fibentry());
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    /// A next-hop whose resolution leads only to itself is unusable, and so is every
    /// next-hop in the loop
    fn test_nhop_resolve_detects_loops() {
        let mut vrf = build_test_vrf_connected_only();

        // 60.0.0.1 and 61.0.0.1 resolve with each other and nothing else
        add_test_route(&mut vrf, ("60.0.0.0", 24), &["61.0.0.1"]);
        add_test_route(&mut vrf, ("61.0.0.0", 24), &["60.0.0.1"]);
        vrf.nhstore.flush_resolvers();

        let a = get_test_nhop(&vrf, "60.0.0.1");
        let b = get_test_nhop(&vrf, "61.0.0.1");
        a.resolve(&vrf);
        b.resolve(&vrf);
        vrf.dump(Some("After resolving next-hops 60.0.0.1 and 61.0.0.1"));

        assert!(
            a.is_unresolved(),
            "A next-hop in a resolution loop is unusable"
        );
        assert!(
            b.is_unresolved(),
            "A next-hop in a resolution loop is unusable"
        );

        // traffic to an unusable next-hop must be dropped
        a.set_fibgroup();
        assert_eq!(a.fibgroup.borrow().entries(), &[FibEntry::drop_fibentry()]);
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    /// Resolving a next-hop must not leave the next-hops it walked over worse-off: a
    /// next-hop skipped as a loop is only skipped for the resolution at hand, and the
    /// next-hop that had to skip it keeps its own, complete, resolution.
    fn test_nhop_resolve_keeps_others_resolvable() {
        let mut vrf = build_test_vrf_connected_only();

        // 42.0.0.1 resolves over 43.0.0.1, which resolves over 42.0.0.1 (loop) and 10.0.0.1
        add_test_route(&mut vrf, ("42.0.0.0", 24), &["43.0.0.1"]);
        add_test_route(&mut vrf, ("43.0.0.0", 24), &["42.0.0.1", "10.0.0.1"]);
        vrf.nhstore.flush_resolvers();

        let a = get_test_nhop(&vrf, "42.0.0.1");
        let b = get_test_nhop(&vrf, "43.0.0.1");

        // resolving 42.0.0.1 forces 43.0.0.1 to skip it, but 43.0.0.1 remains usable
        a.resolve(&vrf);
        vrf.dump(Some("After resolving next-hop 42.0.0.1"));
        assert!(!a.is_unresolved());
        assert_eq!(resolver_addresses(a), vec![Some(mk_addr("43.0.0.1"))]);
        assert!(
            !b.is_unresolved(),
            "43.0.0.1 resolves over 10.0.0.1 and must not be left unresolved"
        );

        assert_eq!(resolver_addresses(b), vec![Some(mk_addr("10.0.0.1"))]);

        // resolving 43.0.0.1 on its own gives the same result, since 42.0.0.1 is only
        // reachable over 43.0.0.1 itself and is therefore not a resolver it can use
        b.resolve(&vrf);
        vrf.dump(Some("After resolving next-hop 43.0.0.1"));
        assert_eq!(resolver_addresses(b), vec![Some(mk_addr("10.0.0.1"))]);
        assert!(
            !a.is_unresolved(),
            "Resolving 43.0.0.1 must not undo the resolution of 42.0.0.1"
        );

        // the loop is cut when building the fibgroup, which keeps the usable path only
        a.set_fibgroup();
        let fibgroup = a.fibgroup.borrow();
        assert_eq!(fibgroup.len(), 1);
        assert_ne!(fibgroup.entries()[0], FibEntry::drop_fibentry());
    }
}

#[cfg(test)]
mod resolution_properties {
    use super::*;
    use crate::evpn::RmacStore;
    use crate::rib::vrf::tests::{build_test_nhop, build_test_route};
    use crate::rib::vrf::{RouteNhop, RouteOrigin, RouterVrfConfig};
    use lpm::prefix::Prefix;
    use std::rc::Rc;

    use super::fibgroup_properties::{Graph, Graphs};

    /// The address that a node of a graph is reached with
    fn node_address(node: usize) -> String {
        format!("10.0.0.{}", node.saturating_add(1))
    }

    fn add_route(vrf: &mut Vrf, prefix: (&str, u8), nhops: &[RouteNhop]) {
        let route = build_test_route(RouteOrigin::Bgp, 0, 1);
        vrf.add_route_complete(
            &Prefix::expect_from(prefix),
            route,
            nhops,
            None,
            &RmacStore::new(),
        );
    }

    /// Realize a graph as a VRF, so that the only way its next-hops get resolvers is
    /// [`Nhop::resolve`]: every node is an address, reached with a route over the
    /// addresses of the nodes it has edges to, or over an interface if it is grounded. A
    /// node with neither resolves with the default (drop) route. Every node is also the
    /// next-hop of a route of its own, so that it exists as a next-hop even if no other
    /// node resolves over it.
    fn realize_as_vrf(graph: &Graph) -> Vrf {
        let mut vrf = Vrf::new(&RouterVrfConfig::new(0, "default"));
        for (node, edges) in graph.edges.iter().enumerate() {
            let address = node_address(node);
            let user = format!("30.0.0.{}", node.saturating_add(1));
            add_route(
                &mut vrf,
                (user.as_str(), 32),
                &[build_test_nhop(Some(&address), None, 0, None)],
            );
            if graph.grounded[node] {
                let ifindex = u32::try_from(node.saturating_add(1)).unwrap_or(1);
                add_route(
                    &mut vrf,
                    (address.as_str(), 32),
                    &[build_test_nhop(None, Some(ifindex), 0, None)],
                );
            } else if !edges.is_empty() {
                let nhops: Vec<RouteNhop> = edges
                    .iter()
                    .map(|to| build_test_nhop(Some(&node_address(*to)), None, 0, None))
                    .collect();
                add_route(&mut vrf, (address.as_str(), 32), &nhops);
            }
        }
        vrf
    }

    /// Tell if the resolvers of a next-hop lead back to it
    fn has_resolution_loop(nhop: &Rc<Nhop>, path: &mut Visited) -> bool {
        if path.contains(&nhop.id()) {
            return true;
        }
        path.push(nhop.id());
        let looped = nhop
            .resolvers
            .borrow()
            .iter()
            .filter_map(Weak::upgrade)
            .any(|resolver| has_resolution_loop(&resolver, path));
        path.pop();
        looped
    }

    #[test]
    /// However the routes of a VRF resolve with each other, resolution never stores a
    /// resolver that leads back to the next-hop being resolved. This is what allows the
    /// resolvers to be walked without keeping track of the path followed.
    fn resolve_all_yields_an_acyclic_resolver_graph() {
        bolero::check!()
            .with_generator(Graphs)
            .cloned()
            .for_each(|graph: Graph| {
                let vrf = realize_as_vrf(&graph);
                vrf.nhstore.resolve_all(&vrf);
                for nhop in vrf.nhstore.iter() {
                    assert!(
                        !has_resolution_loop(nhop, &mut Visited::new()),
                        "resolution loop at next-hop {nhop} for {graph:?}"
                    );
                }
            });
    }

    #[test]
    /// Resolution only ever stores usable resolvers, which is what lets a fibgroup be
    /// built from the resolvers of a next-hop without checking them again
    fn resolve_all_only_stores_usable_resolvers() {
        bolero::check!()
            .with_generator(Graphs)
            .cloned()
            .for_each(|graph: Graph| {
                let vrf = realize_as_vrf(&graph);
                vrf.nhstore.resolve_all(&vrf);
                for nhop in vrf.nhstore.iter() {
                    for resolver in nhop.resolvers.borrow().iter().filter_map(Weak::upgrade) {
                        assert!(
                            !resolver.is_unresolved(),
                            "unusable resolver {resolver} of next-hop {nhop} for {graph:?}"
                        );
                    }
                }
            });
    }
}

#[cfg(test)]
mod fibgroup_properties {
    use super::*;
    use crate::fib::fibobjects::FibEntry;
    use bolero::{Driver, ValueGenerator};
    use std::ops::Bound::Included;

    const MAX_NODES: u8 = 6;
    const MAX_RESOLVERS: u8 = 2;

    #[derive(Debug, Clone)]
    pub(super) struct Graph {
        pub(super) edges: Vec<Vec<usize>>,
        pub(super) grounded: Vec<bool>,
    }

    impl Graph {
        fn reachable_from(&self, start: usize) -> Vec<bool> {
            let mut seen = vec![false; self.edges.len()];
            let mut stack = vec![start];
            while let Some(node) = stack.pop() {
                if std::mem::replace(&mut seen[node], true) {
                    continue;
                }
                stack.extend_from_slice(&self.edges[node]);
            }
            seen
        }
    }

    #[derive(Debug, Clone, Copy, Default)]
    pub(super) struct Graphs;

    impl ValueGenerator for Graphs {
        type Output = Graph;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Graph> {
            let nodes = usize::from(driver.gen_u8(Included(&1), Included(&MAX_NODES))?);
            let last = u8::try_from(nodes - 1).ok()?;
            let mut edges = Vec::with_capacity(nodes);
            let mut grounded = Vec::with_capacity(nodes);
            for node in 0..nodes {
                let count = driver.gen_u8(Included(&0), Included(&MAX_RESOLVERS))?;
                let mut resolvers = Vec::with_capacity(usize::from(count));
                // only resolve over later nodes: that keeps the graph acyclic, as
                // resolution does, and every acyclic graph has such an ordering
                if let Some(first) = u8::try_from(node.saturating_add(1))
                    .ok()
                    .filter(|f| *f <= last)
                {
                    for _ in 0..count {
                        resolvers.push(usize::from(
                            driver.gen_u8(Included(&first), Included(&last))?,
                        ));
                    }
                }
                edges.push(resolvers);
                grounded.push(driver.produce::<bool>()?);
            }
            Some(Graph { edges, grounded })
        }
    }

    fn realize(graph: &Graph) -> (NhopStore, Vec<Rc<Nhop>>) {
        let mut store = NhopStore::new();
        let nodes: Vec<Rc<Nhop>> = (0..graph.edges.len())
            .map(|index| {
                let raw = u8::try_from(index).unwrap_or_else(|_| unreachable!());
                let mut key = NhopKey::from_address(&format!("10.0.0.{}", raw + 1));
                if graph.grounded[index] {
                    key.ifindex = Some(
                        InterfaceIndex::try_new(u32::from(raw) + 1)
                            .unwrap_or_else(|_| unreachable!()),
                    );
                }
                store.add_nhop(&key)
            })
            .collect();

        for (from, resolvers) in graph.edges.iter().enumerate() {
            for to in resolvers {
                nodes[from].add_resolver(&nodes[*to]);
            }
        }
        (store, nodes)
    }

    fn expected(
        graph: &Graph,
        nodes: &[Rc<Nhop>],
        from: usize,
        path: &mut Vec<usize>,
        prefix: &FibEntry,
        out: &mut Vec<FibEntry>,
    ) {
        if path.contains(&from) {
            return;
        }
        path.push(from);

        let mut entry = prefix.clone();
        entry.extend_from_slice(&nodes[from].instructions.borrow());

        if graph.edges[from].is_empty() {
            if !nodes[from].must_be_resolved() {
                entry.squash();
                if entry.is_valid() {
                    out.push(entry);
                }
            }
        } else {
            for to in &graph.edges[from] {
                expected(graph, nodes, *to, path, &entry, out);
            }
        }

        path.pop();
    }

    #[test]
    fn a_fibgroup_is_the_usable_paths_through_the_graph() {
        let rstore = RmacStore::new();
        bolero::check!()
            .with_generator(Graphs)
            .cloned()
            .for_each(|graph: Graph| {
                let (_store, nodes) = realize(&graph);
                for node in &nodes {
                    node.build_nhop_instructions(&rstore);
                }

                let mut want = Vec::new();
                expected(
                    &graph,
                    &nodes,
                    0,
                    &mut Vec::new(),
                    &FibEntry::new(),
                    &mut want,
                );
                if want.is_empty() {
                    want.push(FibEntry::drop_fibentry());
                }

                let got = nodes[0].build_nhop_fibgroup();
                assert_eq!(got.entries(), &want, "for {graph:?}");
            });
    }

    #[test]
    fn every_entry_in_a_fibgroup_is_usable() {
        let rstore = RmacStore::new();
        bolero::check!()
            .with_generator(Graphs)
            .cloned()
            .for_each(|graph: Graph| {
                let (_store, nodes) = realize(&graph);
                for node in &nodes {
                    node.build_nhop_instructions(&rstore);
                }
                let group = nodes[0].build_nhop_fibgroup();
                assert!(!group.is_empty(), "for {graph:?}");
                for entry in group.iter() {
                    assert!(entry.is_valid(), "unusable entry {entry:?} for {graph:?}");
                }
            });
    }

    #[test]
    fn resolves_with_answers_reachability() {
        bolero::check!()
            .with_generator(Graphs)
            .cloned()
            .for_each(|graph: Graph| {
                let (_store, nodes) = realize(&graph);
                for (from, node) in nodes.iter().enumerate() {
                    let reachable = graph.reachable_from(from);
                    for (to, other) in nodes.iter().enumerate() {
                        assert_eq!(
                            node.resolves_with(other),
                            reachable[to],
                            "{from} -> {to}, for {graph:?}"
                        );
                    }
                }
            });
    }

    #[test]
    fn a_next_hop_resolves_via_itself() {
        bolero::check!()
            .with_generator(Graphs)
            .cloned()
            .for_each(|graph: Graph| {
                let (_store, nodes) = realize(&graph);
                for node in &nodes {
                    assert!(node.resolves_with(node));
                }
            });
    }

    #[test]
    fn no_next_hop_resolves_via_another_store() {
        bolero::check!()
            .with_generator(Graphs)
            .cloned()
            .for_each(|graph: Graph| {
                let (_here, here) = realize(&graph);
                let (_there, there) = realize(&graph);
                for (from, node) in here.iter().enumerate() {
                    for (to, other) in there.iter().enumerate() {
                        assert!(
                            !node.resolves_with(other),
                            "{from} resolves via {to} in another store, for {graph:?}"
                        );
                    }
                }
            });
    }
}
