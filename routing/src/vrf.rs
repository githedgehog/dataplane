// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VRF module to store Ipv4 and Ipv6 routing tables

use std::hash::Hash;
use std::iter::Filter;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

use crate::nexthop::{Nhop, NhopKey, NhopStore};
use crate::prefix::Prefix;
use crate::pretty_utils::Frame;
use crate::softfib::fib::FibId;
use crate::softfib::fib::FibWriter;
use iptrie::map::RTrieMap;
use iptrie::{Ipv4Prefix, Ipv6Prefix};
use net::vxlan::Vni;

/// Every VRF is univocally identified with a numerical VRF id
pub type VrfId = u32;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
/// A next-hop in the VRF
pub struct RouteNhop {
    pub vrfid: VrfId,
    pub key: NhopKey,
}
impl Default for RouteNhop {
    fn default() -> Self {
        Self {
            vrfid: 0,
            key: NhopKey::with_drop(),
        }
    }
}

#[allow(unused)]
#[derive(Debug, Default, Clone, PartialEq)]
pub enum RouteOrigin {
    Local,
    Connected,
    Static,
    Ospf,
    Isis,
    Bgp,
    #[default]
    Other,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub origin: RouteOrigin,
    pub distance: u8,
    pub metric: u32,
    pub s_nhops: Vec<ShimNhop>,
}
impl Default for Route {
    fn default() -> Self {
        Self {
            origin: RouteOrigin::default(),
            distance: 0,
            metric: 0,
            s_nhops: Vec::with_capacity(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShimNhop {
    pub ext_vrf: Option<VrfId>,
    pub rc: Arc<Nhop>,
}
impl ShimNhop {
    fn new(ext_vrf: Option<VrfId>, rc: Arc<Nhop>) -> Self {
        Self { ext_vrf, rc }
    }
}

#[allow(unused)]
pub struct Vrf {
    #[allow(unused)]
    pub name: String,
    pub vrfid: VrfId,
    pub(crate) routesv4: RTrieMap<Ipv4Prefix, Route>,
    pub(crate) routesv6: RTrieMap<Ipv6Prefix, Route>,
    pub(crate) nhstore: NhopStore,
    pub(crate) vni: Option<Vni>,
    pub(crate) fibid: Option<FibId>,
    pub(crate) fibw: Option<FibWriter>,
}

// pub type RouteV4FilterTuple<'a> = (&'a Ipv4Prefix, &'a Route);
// pub type RouteV6FilterTuple<'a> = (&'a Ipv6Prefix, &'a Route);

pub type RouteV4Filter = Box<dyn Fn(&(&Ipv4Prefix, &Route)) -> bool>;
pub type RouteV6Filter = Box<dyn Fn(&(&Ipv6Prefix, &Route)) -> bool>;

#[allow(dead_code)]
impl Vrf {
    /////////////////////////////////////////////////////////////////////////
    /// Create a new VRF with the given name and vrfId
    /// Initial capacities are 0. We may want to have some default sizes.
    /// Else, we can always call Self::with_capacities().
    /////////////////////////////////////////////////////////////////////////
    pub fn new(name: &str, vrfid: VrfId, fibw: Option<FibWriter>) -> Self {
        Self::with_capacities(name, vrfid, 0, 0, fibw)
    }

    /////////////////////////////////////////////////////////////////////////
    /// Calculate the FibId corresponding to a VRF. We need FibIds to identify the fib
    /// object corresponding to a VRF, so that we can do certain lookups from the vni.
    /// If a VRF does not have a vni, we don't need it to be in the fibtable, but
    /// we add it for convenience. Note that the Fib object exists anyway. We're
    /// just registering a fibreader so that the Fib is readily readable.
    /////////////////////////////////////////////////////////////////////////
    pub fn fib_id(&self) -> FibId {
        if let Some(vni) = self.vni {
            FibId::from_vni(vni)
        } else {
            FibId::from_vrfid(self.vrfid)
        }
    }
    /////////////////////////////////////////////////////////////////////////
    /// Set the fib id for the fib corresponding to this VRF.
    /////////////////////////////////////////////////////////////////////////
    pub fn set_fib_id(&mut self) {
        self.fibid = Some(self.fib_id());
    }

    /////////////////////////////////////////////////////////////////////////
    /// Get the current fib id for a VRF, if any
    /////////////////////////////////////////////////////////////////////////
    pub fn get_fib_id(&self) -> &Option<FibId> {
        &self.fibid
    }

    /////////////////////////////////////////////////////////////////////////
    /// Set the fibw for a given VRF
    /////////////////////////////////////////////////////////////////////////
    pub fn set_fibw(&mut self, fibw: FibWriter) {
        self.fibw = Some(fibw);
    }

    /////////////////////////////////////////////////////////////////////////
    /// Dump the contents of a Vrf, preceded by some optional heading
    /////////////////////////////////////////////////////////////////////////
    pub fn dump(&self, heading: Option<&str>) {
        if let Some(heading) = heading {
            print!("{}", Frame(heading.to_owned()));
        }
        print!("{self}");
    }

    /////////////////////////////////////////////////////////////////////////
    /// Create VRF with some initial capacities
    /////////////////////////////////////////////////////////////////////////
    pub fn with_capacities(
        name: &str,
        vrfid: VrfId,
        capa_v4: usize,
        capa_v6: usize,
        fibw: Option<FibWriter>,
    ) -> Self {
        let mut vrf = Self {
            name: name.to_owned(),
            vrfid,
            routesv4: RTrieMap::with_capacity(capa_v4),
            routesv6: RTrieMap::with_capacity(capa_v6),
            nhstore: NhopStore::new(),
            vni: None,   /* not set yet */
            fibid: None, /* not set yet */
            fibw,
        };

        /* add default routes with default next-hop with action DROP */
        vrf.add_route(
            &Prefix::root_v4(),
            Route::default(),
            &[RouteNhop::default()],
            None,
        );
        vrf.add_route(
            &Prefix::root_v6(),
            Route::default(),
            &[RouteNhop::default()],
            None,
        );
        vrf
    }

    /////////////////////////////////////////////////////////////////////////
    /// Set the VNI for a Vrf
    /////////////////////////////////////////////////////////////////////////
    pub fn set_vni(&mut self, vni: Vni) {
        self.vni = Some(vni);
        debug!(
            "Vrf '{}'(Id {}) is now associated to vni {}",
            self.name,
            self.vrfid,
            vni.as_u32()
        );
    }

    #[inline(always)]
    #[must_use]
    fn register_shared_nhop(&mut self, nhop: &RouteNhop) -> Arc<Nhop> {
        self.nhstore.add_nhop(&nhop.key)
    }

    /////////////////////////////////////////////////////////////////////////
    /// Register a shared next-hop for the route if not there
    /////////////////////////////////////////////////////////////////////////
    fn register_shared_nhops(&mut self, route: &mut Route, nhops: &[RouteNhop]) {
        for nhop in nhops {
            let shared = self.register_shared_nhop(nhop);
            let ext_vrf = if nhop.vrfid != self.vrfid {
                Some(nhop.vrfid)
            } else {
                None
            };
            /* create shim next-hop */
            let shim = ShimNhop::new(ext_vrf, shared.clone());

            /* add to route */
            route.s_nhops.push(shim);
        }
    }

    #[inline(always)]
    fn deregister_shared_nhop(&mut self, shim: ShimNhop) {
        let key = shim.rc.key;
        drop(shim);
        self.nhstore.del_nhop(&key);
    }
    /////////////////////////////////////////////////////////////////////////
    /// De-register a shared next-hop for the route
    /////////////////////////////////////////////////////////////////////////
    fn deregister_shared_nexthops(&mut self, route: &mut Route) {
        while let Some(shim) = route.s_nhops.pop() {
            self.deregister_shared_nhop(shim);
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Route Insertion
    /////////////////////////////////////////////////////////////////////////
    pub fn add_route(
        &mut self,
        prefix: &Prefix,
        mut route: Route,
        nhops: &[RouteNhop],
        vrf0: Option<&Vrf>,
    ) {
        self.register_shared_nhops(&mut route, nhops);

        match prefix {
            Prefix::IPV4(p) => self.routesv4.insert(*p, route.clone()),
            Prefix::IPV6(p) => self.routesv6.insert(*p, route.clone()),
        };
        // NB. above, we inserted a clone of the route, which points to the same next-hops
        // as the route we still own at this point. This clone is cheap and convenient
        // so that here we have access to the next-hops and can modify them.
        for shim in &route.s_nhops {
            if Arc::strong_count(&shim.rc) <= 2 {
                if let Some(vrf0) = vrf0 {
                    shim.rc.lazy_resolve(vrf0);
                } else {
                    shim.rc.lazy_resolve(self);
                }
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Route removal
    /////////////////////////////////////////////////////////////////////////

    #[inline(always)]
    fn del_route_v4(&mut self, prefix: &Ipv4Prefix) {
        // iptrie forbids removing the default route (at root).
        // So, we have to replace it with a dummy route with action Drop, to actually represent a lack of route.
        if prefix == &Ipv4Prefix::default() {
            // This is a bit of a hack
            if let Some(mut prior) = self.routesv4.insert(*prefix, Route::default()) {
                self.deregister_shared_nexthops(&mut prior);
            }
            self.add_route(
                &Prefix::from(*prefix),
                Route::default(),
                &[RouteNhop::default()],
                None,
            );
        } else if let Some(found) = &mut self.routesv4.remove(prefix) {
            self.deregister_shared_nexthops(found);
        }
    }
    #[inline(always)]
    fn del_route_v6(&mut self, prefix: &Ipv6Prefix) {
        // iptrie forbids removing the default route (at root).
        // So, we have to replace it with a dummy route with action Drop, to actually represent a lack of route.
        if prefix == &Ipv6Prefix::default() {
            // This is a bit of a hack
            if let Some(mut prior) = self.routesv6.insert(*prefix, Route::default()) {
                self.deregister_shared_nexthops(&mut prior);
            }
            self.add_route(
                &Prefix::from(*prefix),
                Route::default(),
                &[RouteNhop::default()],
                None,
            );
        } else if let Some(found) = &mut self.routesv6.remove(prefix) {
            self.deregister_shared_nexthops(found);
        }
    }
    pub fn del_route(&mut self, prefix: &Prefix) {
        match prefix {
            Prefix::IPV4(p) => self.del_route_v4(p),
            Prefix::IPV6(p) => self.del_route_v6(p),
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Route retrieval
    /////////////////////////////////////////////////////////////////////////

    #[inline(always)]
    fn get_route_v4(&self, prefix: &Ipv4Prefix) -> Option<&Route> {
        self.routesv4.get(prefix)
    }
    #[inline(always)]
    fn get_route_v6(&self, prefix: &Ipv6Prefix) -> Option<&Route> {
        self.routesv6.get(prefix)
    }
    pub fn get_route(&self, prefix: &Prefix) -> Option<&Route> {
        match prefix {
            Prefix::IPV4(p) => self.get_route_v4(p),
            Prefix::IPV6(p) => self.get_route_v6(p),
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Route retrieval (mutable): we may not need this and if we do, extra
    // care should be taken modifying route internals
    /////////////////////////////////////////////////////////////////////////

    #[inline(always)]
    fn get_route_v4_mut(&mut self, prefix: &Ipv4Prefix) -> Option<&mut Route> {
        self.routesv4.get_mut(prefix)
    }
    #[inline(always)]
    fn get_route_v6_mut(&mut self, prefix: &Ipv6Prefix) -> Option<&mut Route> {
        self.routesv6.get_mut(prefix)
    }
    pub fn get_route_mut(&mut self, prefix: &Prefix) -> Option<&mut Route> {
        match prefix {
            Prefix::IPV4(p) => self.get_route_v4_mut(p),
            Prefix::IPV6(p) => self.get_route_v6_mut(p),
        }
    }

    // ///////////////////////////////////////////////////////////////////////
    // iterators, filters and counts
    // ///////////////////////////////////////////////////////////////////////

    pub fn iter_v4(&self) -> impl Iterator<Item = (&Ipv4Prefix, &Route)> {
        self.routesv4.iter()
    }
    pub fn iter_v6(&self) -> impl Iterator<Item = (&Ipv6Prefix, &Route)> {
        self.routesv6.iter()
    }
    pub fn filter_v4<'a>(
        &'a self,
        filter: &'a RouteV4Filter,
    ) -> Filter<impl Iterator<Item = (&'a Ipv4Prefix, &'a Route)>, &'a RouteV4Filter> {
        self.iter_v4().filter(filter)
    }
    pub fn filter_v6<'a>(
        &'a self,
        filter: &'a RouteV6Filter,
    ) -> Filter<impl Iterator<Item = (&'a Ipv6Prefix, &'a Route)>, &'a RouteV6Filter> {
        self.iter_v6().filter(filter)
    }
    pub fn len_v4(&self) -> usize {
        self.routesv4.len().get()
    }
    pub fn len_v6(&self) -> usize {
        self.routesv6.len().get()
    }
    /////////////////////////////////////////////////////////////////////////
    // LPM, single call
    /////////////////////////////////////////////////////////////////////////

    #[inline(always)]
    fn lpm_v4(&self, target: &Ipv4Prefix) -> (&Ipv4Prefix, &Route) {
        self.routesv4.lookup(target)
    }
    #[inline(always)]
    fn lpm_v6(&self, target: &Ipv6Prefix) -> (&Ipv6Prefix, &Route) {
        self.routesv6.lookup(target)
    }
    pub fn lpm(&self, target: &IpAddr) -> (Prefix, &Route) {
        match *target {
            IpAddr::V4(a) => {
                let (p, r) = self.lpm_v4(&a.into());
                (Prefix::IPV4(*p), r)
            }
            IpAddr::V6(a) => {
                let (p, r) = self.lpm_v6(&a.into());
                (Prefix::IPV6(*p), r)
            }
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
#[rustfmt::skip]
pub mod tests {
    use super::*;
    use std::str::FromStr;
    use crate::interface::IfIndex;
    use crate::vrf::VrfId;
    use crate::nexthop::{FwAction, NhopKey};
    use crate::encapsulation::{Encapsulation, VxlanEncapsulation};

    #[test]
    fn test_vrf_build() {
        let vrf = Vrf::new("Default", 0, None);
        assert_eq!(vrf.len_v4(), 1, "An Ipv4 default route must exist.");
        assert_eq!(vrf.len_v6(), 1, "An Ipv6 default route must exist.");
        assert_eq!(vrf.nhstore.len(), 1, "A single 'drop' nexthop must be there.");
        vrf.dump(Some("Brand new VRF"));
    }

    fn check_default_drop_v4(vrf: &Vrf) {
        let prefix: Prefix = Prefix::root_v4();
        let recovered = vrf.get_route_v4(prefix.get_v4()).expect("There must be a default route");
        assert_eq!(recovered.s_nhops.len(), 1);
        assert_eq!(recovered.s_nhops[0].rc.key.fwaction, FwAction::Drop);
    }
    fn check_default_drop_v6(vrf: &Vrf) {
        let prefix: Prefix = Prefix::root_v6();
        let recovered = vrf.get_route_v6(prefix.get_v6()).expect("There must be a default route");
        assert_eq!(recovered.s_nhops.len(), 1);
        assert_eq!(recovered.s_nhops[0].rc.key.fwaction, FwAction::Drop);
    }
    fn check_vrf_is_empty(vrf: &Vrf) {
        assert_eq!(vrf.len_v4(), 1,"Only default(root) route for Ipv4");
        assert_eq!(vrf.len_v6(), 1,"Only default(root) route for Ipv6");
        assert_eq!(vrf.nhstore.len(), 1, "Only next-hop for default route w/ Fwaction::Drop");
        check_default_drop_v4(vrf);
        check_default_drop_v6(vrf);
    }

    #[test]
    fn test_default_idempotence() {
        let mut vrf = Vrf::new("Default", 0, None);

        let pref_v4: Prefix = Prefix::root_v4();
        let pref_v6: Prefix = Prefix::root_v6();

        /* default-Drop routes must be there */
        check_default_drop_v4(&vrf);
        check_default_drop_v6(&vrf);

        /* default-Drop routes cannot be deleted */
        vrf.del_route(&pref_v4);
        vrf.del_route(&pref_v6);
        check_default_drop_v4(&vrf);
        check_default_drop_v6(&vrf);

        /* Overwrite is safe */
        vrf.add_route(&pref_v4, Route::default(), &[RouteNhop::default()], None);
        vrf.add_route(&pref_v6, Route::default(), &[RouteNhop::default()], None);
        check_default_drop_v4(&vrf);
        check_default_drop_v6(&vrf);
        vrf.dump(None);
    }

    pub fn mk_addr(a: &str) -> IpAddr {
        IpAddr::from_str(a).expect("Bad address")
    }

    pub fn build_test_nhop(
        address: Option<&str>,
        ifindex: Option<IfIndex>,
        vrfid: VrfId,
        encap: Option<Encapsulation>,
    ) -> RouteNhop {
        let key = NhopKey::new(
            address.map(mk_addr),
            ifindex, encap,FwAction::Forward);

        RouteNhop {
            vrfid,
            key,
        }
    }
    pub fn build_test_route(origin: RouteOrigin, distance: u8, metric: u32) -> Route {
        Route {
            origin,
            distance,
            metric,
            s_nhops: vec![],
        }
    }

    #[test]
    fn test_default_replace_v4() {
        let mut vrf = Vrf::new("Default", 0, None);
        vrf.dump(Some("Initial (clean)"));

        /* Add static default via 10.0.0.1 */
        let prefix: Prefix = Prefix::root_v4();
        let route = build_test_route(RouteOrigin::Static, 1, 0);
        let nhop = build_test_nhop(Some("10.0.0.1"), None, 0, None);
        vrf.add_route(&prefix, route, &[nhop], None);

        assert_eq!(vrf.len_v4(), 1, "Should have replaced the default");
        vrf.dump(Some("With static IPv4 default non-drop route"));

        /* delete the static default. This should put back again a default route with action DROP */
        vrf.del_route(&prefix);
        check_default_drop_v4(&vrf);

        vrf.dump(Some("After removing the IPv4 static default"));
    }

    #[test]
    fn test_default_replace_v6() {
        let mut vrf = Vrf::new("Default", 0, None);
        vrf.dump(Some("Initial (clean)"));

        /* Add static default via 2001::1 */
        let prefix: Prefix = Prefix::root_v4();
        let route = build_test_route(RouteOrigin::Static, 1, 0);
        let nhop = build_test_nhop(Some("2001::1"), None, 0, None);
        vrf.add_route(&prefix, route, &[nhop], None);

        assert_eq!(vrf.len_v6(), 1, "Should have replaced the default");
        vrf.dump(Some("With static IPv6 default non-drop route"));

        /* delete the static default. This should put back again a default route with action DROP */
        vrf.del_route(&prefix);
        check_default_drop_v6(&vrf);

        vrf.dump(Some("After removing the IPv6 static default"));
    }

    #[test]
    fn test_vrf_basic() {
        let num_routes = 10;
        let mut vrf = Vrf::new("Default", 0, None);

        /* Add 'num_routes' routes */
        for i in 1..=num_routes {
            /* add a v4 route */
            let nh1 = build_test_nhop(Some("10.0.0.1"), Some(1), 0, None);
            let nh2 = build_test_nhop(Some("10.0.0.2"), Some(2), 0, None);
            let route = build_test_route(RouteOrigin::Ospf, 110, 20);
            let prefix = Prefix::expect_from((format!("7.0.0.{i}").as_str(), 32));
            vrf.add_route(&prefix, route.clone() /* only test */, &[nh1, nh2], None);

            /* since route is /32, it should resolve to itself */
            let target = prefix.as_address();
            let (longest, best) = vrf.lpm(&target);
            assert_eq!(longest, prefix);
            assert_eq!(best.distance, route.distance);
            assert_eq!(best.metric, route.metric);
            assert_eq!(best.origin, route.origin);
            assert_eq!(best.s_nhops.len(), 2);
            assert!(best.s_nhops.iter().any(|s| s.rc.key.address == Some(mk_addr("10.0.0.1")) && s.rc.key.ifindex == Some(1)));
            assert!(best.s_nhops.iter().any(|s| s.rc.key.address == Some(mk_addr("10.0.0.2")) && s.rc.key.ifindex == Some(2)));
        }
        assert_eq!(vrf.len_v4(),  (1 + num_routes) as usize, "There must be default + the ones added");
        assert_eq!(vrf.nhstore.len(), 3usize,"There is drop + 2 nexthops shared by all routes");

        for i in 1..=num_routes {
            /* delete v4 routes one at a time */
            let prefix = Prefix::expect_from((format!("7.0.0.{i}").as_str(), 32));
            vrf.del_route(&prefix);

            /* each route prefix should resolve only to default */
            let target = prefix.as_address();
            let (longest, best) = vrf.lpm(&target);

            assert_eq!(longest, Prefix::root_v4(), "Must resolve via default");
            assert_eq!(best.s_nhops.len(), 1);
            assert_eq!(best.s_nhops[0].rc.key.fwaction, FwAction::Drop, "Default is drop");
        }
        check_vrf_is_empty(&vrf);

    }


    #[test]
    fn test_patricia () {
        let mut trie:RTrieMap<Ipv4Prefix, ()> = RTrieMap::new();
        let prefix1 = Ipv4Prefix::from_str("10.0.0.1/32").unwrap();
        trie.insert(prefix1, ());
        trie.remove(&prefix1);
    }

    #[test]
    fn test_route_filtering() {
        let mut vrf = Vrf::new("Default", 0, None);

        /* connected */
        let nh = build_test_nhop(None, Some(1), 0, None);
        let connected = build_test_route(RouteOrigin::Connected, 0, 1);
        let prefix = Prefix::expect_from(("10.0.0.1", 24));
        vrf.add_route(&prefix, connected.clone() /* only test */, &[nh], None);

        /* ospf */
        let nh1 = build_test_nhop(Some("10.0.0.1"), Some(1), 0, None);
        let nh2 = build_test_nhop(Some("10.0.0.2"), Some(2), 0, None);
        let ospf = build_test_route(RouteOrigin::Ospf, 110, 20);
        let prefix = Prefix::expect_from(("7.0.0.1", 32));
        vrf.add_route(&prefix, ospf.clone() /* only test */, &[nh1, nh2], None);

        /* bgp */
        let nh = build_test_nhop(Some("7.0.0.1"), None, 0, None);
        let bgp = build_test_route(RouteOrigin::Bgp, 20, 100);
        let prefix = Prefix::expect_from(("192.168.1.0", 24));
        vrf.add_route(&prefix, bgp.clone() /* only test */, &[nh], None);

        assert_eq!(vrf.len_v4(), 4, "There are 3 routes + drop");

        let only_connected: RouteV4Filter= Box::new(|(_, route): &(&Ipv4Prefix, &Route)| {route.origin == RouteOrigin::Connected});
        let filtered  = vrf.filter_v4(&only_connected);
        assert_eq!(filtered.count(), 1);

        let only_ospf: RouteV4Filter= Box::new(|(_, route): &(&Ipv4Prefix, &Route)| {route.origin == RouteOrigin::Ospf});
        let filtered  = vrf.filter_v4(&only_ospf);
        assert_eq!(filtered.count(), 1);

        let only_bgp: RouteV4Filter= Box::new(|(_, route): &(&Ipv4Prefix, &Route)| {route.origin == RouteOrigin::Bgp});
        let filtered  = vrf.filter_v4(&only_bgp);
        assert_eq!(filtered.count(), 1);
    }

    fn add_vxlan_route(vrf: &mut Vrf, dst: (&str, u8), vni: u32) {
        let route: Route = build_test_route(RouteOrigin::Bgp, 0, 1);
        let nhop = build_test_nhop(
            Some("7.0.0.1"),
            None,
            0,
            Some(Encapsulation::Vxlan(VxlanEncapsulation::new(
                Vni::new_checked(vni).expect("Should be ok"),
                IpAddr::from_str("7.0.0.1").unwrap(),
            ))),
        );
        let prefix = Prefix::expect_from(dst);
        vrf.add_route(&prefix, route, &[nhop], None);
    }
    fn add_vxlan_routes(vrf: &mut Vrf, num_routes: u32) {
        for n in 0..num_routes {
            add_vxlan_route(vrf, (format!("192.168.{n}.0").as_str(), 24), 3000+n);
        }
    }

    // build a sample VRF used for testing
    pub fn build_test_vrf() -> Vrf {
        let mut vrf = Vrf::new("Default", 0, None);

        {
            let route: Route = build_test_route(RouteOrigin::Connected, 0, 1);
            let nhop = build_test_nhop(None, Some(1), 0, None);
            let prefix = Prefix::expect_from(("10.0.0.0", 30));
            vrf.add_route(&prefix, route, &[nhop], None);
        }

        {
            let route: Route = build_test_route(RouteOrigin::Connected, 0, 1);
            let nhop = build_test_nhop(None, Some(2), 0, None);
            let prefix = Prefix::expect_from(("10.0.0.4", 30));
            vrf.add_route(&prefix, route, &[nhop], None);
        }

        {
            let route: Route = build_test_route(RouteOrigin::Connected, 0, 1);
            let nhop = build_test_nhop(None, Some(3), 0, None);
            let prefix = Prefix::expect_from(("10.0.0.8", 30));
            vrf.add_route(&prefix, route, &[nhop], None);
        }

        {
            let route: Route = build_test_route(RouteOrigin::Ospf, 0, 1);
            let n1 = build_test_nhop(Some("10.0.0.1"), None, 0, Some(Encapsulation::Mpls(8001)));
            let n2 = build_test_nhop(Some("10.0.0.5"), None, 0, Some(Encapsulation::Mpls(8005)));
            let prefix = Prefix::expect_from(("8.0.0.1", 32));
            vrf.add_route(&prefix, route, &[n1, n2], None);
        }

        {
            let route: Route = build_test_route(RouteOrigin::Ospf, 0, 1);
            let n2 = build_test_nhop(Some("10.0.0.5"), None, 0, Some(Encapsulation::Mpls(8005)));
            let n3 = build_test_nhop(Some("10.0.0.9"), None, 0, Some(Encapsulation::Mpls(8009)));
            let prefix = Prefix::expect_from(("8.0.0.2", 32));
            vrf.add_route(&prefix, route, &[n2, n3], None);
        }

        {
            let route: Route = build_test_route(RouteOrigin::Bgp, 0, 1);
            let n1 = build_test_nhop(Some("8.0.0.1"), None, 0, Some(Encapsulation::Mpls(7000)));
            let n2 = build_test_nhop(Some("8.0.0.2"), None, 0, Some(Encapsulation::Mpls(7000)));
            let prefix = Prefix::expect_from(("7.0.0.1", 32));
            vrf.add_route(&prefix, route, &[n1, n2], None);
        }

        add_vxlan_routes(&mut vrf, 5);

        vrf.dump(Some("VRF With next-hops lazily resolved on addition"));
        vrf
    }

    // build a sample VRF used for testing
    pub fn build_test_vrf_nhops_partially_resolved() -> Vrf {
        let mut vrf = Vrf::new("Default", 0, None);

        {
            let route: Route = build_test_route(RouteOrigin::Ospf, 0, 1);
            let n1 = build_test_nhop(Some("10.0.0.1"), Some(2), 0, Some(Encapsulation::Mpls(8001)));
            let n2 = build_test_nhop(Some("10.0.0.5"), Some(3), 0, Some(Encapsulation::Mpls(8005)));
            let prefix = Prefix::expect_from(("8.0.0.1", 32));
            vrf.add_route(&prefix, route, &[n1, n2], None);
        }

        {
            let route: Route = build_test_route(RouteOrigin::Ospf, 0, 1);
            let n2 = build_test_nhop(Some("10.0.0.5"), Some(3), 0, Some(Encapsulation::Mpls(8005)));
            let n3 = build_test_nhop(Some("10.0.0.9"), Some(4), 0, Some(Encapsulation::Mpls(8009)));
            let prefix = Prefix::expect_from(("8.0.0.2", 32));
            vrf.add_route(&prefix, route, &[n2, n3], None);
        }

        {
            let route: Route = build_test_route(RouteOrigin::Bgp, 0, 1);
            let n1 = build_test_nhop(Some("8.0.0.1"), None, 0, Some(Encapsulation::Mpls(7000)));
            let n2 = build_test_nhop(Some("8.0.0.2"), None, 0, Some(Encapsulation::Mpls(7000)));
            let prefix = Prefix::expect_from(("7.0.0.1", 32));
            vrf.add_route(&prefix, route, &[n1, n2], None);
        }

        add_vxlan_routes(&mut vrf, 5);

        vrf.dump(Some("VRF With next-hops with partially resolved nexthops, lazily resolved on addition"));
        vrf
    }


    #[test]
    fn test_vrf_lazy_nhop_resolution() {
        let vrf = build_test_vrf();

        let nhkey = NhopKey {
            address: Some(mk_addr("7.0.0.1")),
            ifindex: None,
            encap: Some(Encapsulation::Vxlan(VxlanEncapsulation::new(
                Vni::new_checked(3000).expect("Should be ok"),
                IpAddr::from_str("7.0.0.1").unwrap(),
            ))),
            fwaction: FwAction::default(),
        };

        /* check how the next-hop has been resolved */
        let _nhop = vrf.nhstore.get_nhop(&nhkey).expect("Should be there");
        /* Todo: finish test */
    }
}
