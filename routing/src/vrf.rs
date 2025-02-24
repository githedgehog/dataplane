// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VRF module to store Ipv4 and Ipv6 routing tables

use std::hash::Hash;
use std::net::IpAddr;

use crate::nexthop::{Nhop, NhopKey, NhopStore};
use crate::prefix::Prefix;
use crate::pretty_utils::Frame;
use iptrie::map::RTrieMap;
use iptrie::{Ipv4Prefix, Ipv6Prefix};
use net::vxlan::Vni;
use std::sync::Arc;

/// We'll use the RPC definitions for these
use dplane_rpc::msg::{RouteDistance, RouteMetric, RouteType};

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

#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub rtype: RouteType,
    pub distance: RouteDistance,
    pub metric: RouteMetric,
    pub s_nhops: Vec<ShimNhop>,
}
impl Default for Route {
    fn default() -> Self {
        Self {
            rtype: RouteType::Other,
            distance: 0,
            metric: 0,
            s_nhops: Vec::with_capacity(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShimNhop {
    pub shim: VrfId,
    pub rc: Arc<Nhop>,
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
}

#[allow(dead_code)]
impl Vrf {
    /////////////////////////////////////////////////////////////////////////
    /// Create a new VRF with the given name and vrfId
    /// Initial capacities are 0. We may want to have some default sizes.
    /// Else, we can always call Self::with_capacities().
    /////////////////////////////////////////////////////////////////////////
    pub fn new(name: &str, vrfid: VrfId) -> Self {
        Self::with_capacities(name, vrfid, 0, 0)
    }

    /////////////////////////////////////////////////////////////////////////
    /// Dump the contents of a Vrf, preceded by some optional heading
    /////////////////////////////////////////////////////////////////////////
    pub fn dump(&self, heading: Option<&str>) {
        if let Some(heading) = heading {
            print!("{}", Frame(heading.to_owned()));
        }
        print!("{}", self);
    }

    /////////////////////////////////////////////////////////////////////////
    /// Create VRF with some initial capacities
    /////////////////////////////////////////////////////////////////////////
    pub fn with_capacities(name: &str, vrfid: VrfId, capa_v4: usize, capa_v6: usize) -> Self {
        let mut vrf = Self {
            name: name.to_owned(),
            vrfid,
            routesv4: RTrieMap::with_capacity(capa_v4),
            routesv6: RTrieMap::with_capacity(capa_v6),
            nhstore: NhopStore::new(),
            vni: None,
        };
        /* add default routes with default next-hop with action DROP */
        vrf.add_route(
            &Prefix::root_v4(),
            Route::default(),
            &[RouteNhop::default()],
        );
        vrf.add_route(
            &Prefix::root_v6(),
            Route::default(),
            &[RouteNhop::default()],
        );
        vrf
    }

    /////////////////////////////////////////////////////////////////////////
    /// Set the VNI for a Vrf
    /////////////////////////////////////////////////////////////////////////
    pub fn set_vni(&mut self, vni: Vni) {
        self.vni = Some(vni);
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
            // shim next-hop created here
            let shared = self.register_shared_nhop(nhop);
            let shim = ShimNhop {
                shim: nhop.vrfid,
                rc: shared,
            };
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
    #[inline(always)]
    fn add_route_v4(&mut self, prefix: &Ipv4Prefix, mut route: Route, nhops: &[RouteNhop]) {
        self.register_shared_nhops(&mut route, nhops);
        self.routesv4.insert(*prefix, route);
    }

    #[inline(always)]
    fn add_route_v6(&mut self, prefix: &Ipv6Prefix, mut route: Route, nhops: &[RouteNhop]) {
        self.register_shared_nhops(&mut route, nhops);
        self.routesv6.insert(*prefix, route);
    }
    pub fn add_route(&mut self, prefix: &Prefix, route: Route, nhops: &[RouteNhop]) {
        match prefix {
            Prefix::IPV4(p) => self.add_route_v4(p, route, nhops),
            Prefix::IPV6(p) => self.add_route_v6(p, route, nhops),
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
            self.add_route_v4(prefix, Route::default(), &[RouteNhop::default()]);
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
            self.add_route_v6(prefix, Route::default(), &[RouteNhop::default()]);
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
    use dplane_rpc::msg::RouteType;
    use crate::interface::IfIndex;
    use crate::vrf::VrfId;
    use crate::nexthop::{FwAction, NhopKey};
    use crate::encapsulation::Encapsulation;

    #[test]
    fn test_vrf_build() {
        let vrf = Vrf::new("Default", 0);
        assert_eq!(vrf.routesv4.len().get(), 1, "An Ipv4 default route must exist.");
        assert_eq!(vrf.routesv6.len().get(), 1, "An Ipv6 default route must exist.");
        assert_eq!(vrf.nhstore.len(), 1, "A single 'drop' nexthop must be there.");
        vrf.dump(Some("Brand new VRF"));
    }

    fn check_default_drop_v4(vrf: &Vrf) {
        let prefix: Prefix = Prefix::root_v4();
        let recovered = vrf.get_route_v4(&prefix.get_v4()).expect("There must be a default route");
        assert_eq!(recovered.s_nhops.len(), 1);
        assert_eq!(recovered.s_nhops[0].rc.key.fwaction, FwAction::Drop);
    }
    fn check_default_drop_v6(vrf: &Vrf) {
        let prefix: Prefix = Prefix::root_v6();
        let recovered = vrf.get_route_v6(&prefix.get_v6()).expect("There must be a default route");
        assert_eq!(recovered.s_nhops.len(), 1);
        assert_eq!(recovered.s_nhops[0].rc.key.fwaction, FwAction::Drop);
    }
    fn check_vrf_is_empty(vrf: &Vrf) {
        assert_eq!(vrf.routesv4.len().get(), 1,"Only default(root) route for Ipv4");
        assert_eq!(vrf.routesv6.len().get(), 1,"Only default(root) route for Ipv6");
        assert_eq!(vrf.nhstore.len(), 1, "Only next-hop for default route w/ Fwaction::Drop");
        check_default_drop_v4(vrf);
        check_default_drop_v6(vrf);
    }

    #[test]
    fn test_default_idempotence() {
        let mut vrf = Vrf::new("Default", 0);

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
        vrf.add_route(&pref_v4, Route::default(), &[RouteNhop::default()]);
        vrf.add_route(&pref_v6, Route::default(), &[RouteNhop::default()]);
        check_default_drop_v4(&vrf);
        check_default_drop_v6(&vrf);
        vrf.dump(None);
    }

    pub fn build_address(a: &str) -> IpAddr {
        IpAddr::from_str(a).expect("Bad address")
    }

    pub fn build_test_nhop(
        address: Option<&str>,
        ifindex: Option<IfIndex>,
        vrfid: VrfId,
        encap: Option<Encapsulation>,
    ) -> RouteNhop {
        let key = NhopKey::new(
            address.map(build_address),
            ifindex, encap,FwAction::Forward);

        RouteNhop {
            vrfid,
            key,
        }
    }
    pub fn build_test_route(rtype: RouteType, distance: RouteDistance, metric: RouteMetric) -> Route {
        Route {
            rtype,
            distance,
            metric,
            s_nhops: vec![],
        }
    }

    #[test]
    fn test_default_replace_v4() {
        let mut vrf = Vrf::new("Default", 0);
        vrf.dump(Some("Initial (clean)"));

        /* Add static default via 10.0.0.1 */
        let prefix: Prefix = Prefix::root_v4();
        let route = build_test_route(RouteType::Static, 1, 0);
        let nhop = build_test_nhop(Some("10.0.0.1"), None, 0, None);
        vrf.add_route(&prefix, route, &[nhop]);

        assert_eq!(vrf.routesv4.len().get(), 1, "Should have replaced the default");
        vrf.dump(Some("With static IPv4 default non-drop route"));

        /* delete the static default. This should put back again a default route with action DROP */
        vrf.del_route(&prefix);
        check_default_drop_v4(&vrf);

        vrf.dump(Some("After removing the IPv4 static default"));
    }

    #[test]
    fn test_default_replace_v6() {
        let mut vrf = Vrf::new("Default", 0);
        vrf.dump(Some("Initial (clean)"));

        /* Add static default via 2001::1 */
        let prefix: Prefix = Prefix::root_v4();
        let route = build_test_route(RouteType::Static, 1, 0);
        let nhop = build_test_nhop(Some("2001::1"), None, 0, None);
        vrf.add_route(&prefix, route, &[nhop]);

        assert_eq!(vrf.routesv6.len().get(), 1, "Should have replaced the default");
        vrf.dump(Some("With static IPv6 default non-drop route"));

        /* delete the static default. This should put back again a default route with action DROP */
        vrf.del_route(&prefix);
        check_default_drop_v6(&vrf);

        vrf.dump(Some("After removing the IPv6 static default"));
    }

    #[test]
    fn test_vrf_basic() {
        let num_routes = 10;
        let mut vrf = Vrf::new("Default", 0);

        /* Add 'num_routes' routes */
        for i in 1..=num_routes {
            /* add a v4 route */
            let nh1 = build_test_nhop(Some("10.0.0.1"), Some(1), 0, None);
            let nh2 = build_test_nhop(Some("10.0.0.2"), Some(2), 0, None);
            let route = build_test_route(RouteType::Ospf, 110, 20);
            let prefix = Prefix::from((format!("7.0.0.{}", i).as_str(), 32));
            vrf.add_route(&prefix, route.clone() /* only test */, &[nh1, nh2]);

            /* since route is /32, it should resolve to itself */
            let target = prefix.as_address();
            let (longest, best) = vrf.lpm(&target);
            assert_eq!(longest, prefix);
            assert_eq!(best.distance, route.distance);
            assert_eq!(best.metric, route.metric);
            assert_eq!(best.rtype, route.rtype);
            assert_eq!(best.s_nhops.len(), 2);
            assert!(best.s_nhops.iter().any(|s| s.rc.key.address == Some(build_address("10.0.0.1")) && s.rc.key.ifindex == Some(1)));
            assert!(best.s_nhops.iter().any(|s| s.rc.key.address == Some(build_address("10.0.0.2")) && s.rc.key.ifindex == Some(2)));
        }
        assert_eq!(vrf.routesv4.len().get(),  (1 + num_routes) as usize, "There must be default + the ones added");
        assert_eq!(vrf.nhstore.len(), 3usize,"There is drop + 2 nexthops shared by all routes");

        for i in 1..=num_routes {
            /* delete v4 routes one at a time */
            let prefix = Prefix::from((format!("7.0.0.{}", i).as_str(), 32));
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

}
