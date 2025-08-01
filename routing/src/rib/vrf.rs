// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VRF module to store Ipv4 and Ipv6 routing tables

use std::hash::Hash;
use std::iter::Filter;
use std::net::IpAddr;
use std::rc::Rc;
use tracing::debug;

#[cfg(test)]
use crate::pretty_utils::Frame;

use super::nexthop::{FwAction, Nhop, NhopKey, NhopStore};
use crate::evpn::{RmacStore, Vtep};
use crate::fib::fibobjects::FibGroup;
use crate::fib::fibtype::{FibId, FibReader, FibWriter};
use lpm::prefix::{Ipv4Prefix, Ipv6Prefix, Prefix};
use lpm::trie::{PrefixMapTrieWithDefault, TrieMap};
use net::interface::InterfaceIndex;
use net::route::RouteTableId;
use net::vxlan::Vni;

/// Every VRF is univocally identified with a numerical VRF id
pub type VrfId = u32;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
/// A next-hop in the VRF
pub struct RouteNhop {
    pub vrfid: VrfId,
    pub key: NhopKey,
}
impl RouteNhop {
    fn from_nhkey(key: &NhopKey) -> RouteNhop {
        Self {
            vrfid: 0,
            key: key.clone(),
        }
    }
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
#[derive(Debug, Default, Clone, Eq, Hash, Copy, Ord, PartialOrd, PartialEq)]
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
impl Route {
    fn with_origin(origin: RouteOrigin) -> Self {
        Self {
            origin,
            distance: 0,
            metric: 0,
            s_nhops: vec![],
        }
    }
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
    pub rc: Rc<Nhop>,
}
impl ShimNhop {
    fn new(ext_vrf: Option<VrfId>, rc: Rc<Nhop>) -> Self {
        Self { ext_vrf, rc }
    }
}

#[derive(Copy, Clone, PartialEq)]
#[allow(unused)]
pub enum VrfStatus {
    Active,
    Deleting,
    Deleted,
}

//////////////////////////////////////////////////////////////////////////////////
/// A [`Vrf`] is the main object to represent a VRF
//////////////////////////////////////////////////////////////////////////////////
#[allow(unused)]
pub struct Vrf {
    pub name: String,
    pub vrfid: VrfId,
    pub tableid: Option<RouteTableId>,
    pub description: Option<String>,
    pub(crate) status: VrfStatus,
    pub(crate) routesv4: PrefixMapTrieWithDefault<Ipv4Prefix, Route>,
    pub(crate) routesv6: PrefixMapTrieWithDefault<Ipv6Prefix, Route>,
    pub(crate) nhstore: NhopStore,
    pub(crate) vni: Option<Vni>,
    pub(crate) fibw: Option<FibWriter>,
}

//////////////////////////////////////////////////////////////////////////////////
/// A [`RouterVrfConfig`] contains the configuration to create a [`Vrf`]
//////////////////////////////////////////////////////////////////////////////////
#[derive(Clone, Debug, PartialEq)]
pub struct RouterVrfConfig {
    pub vrfid: VrfId,                  /* Id of VRF - may equate to ifindex */
    pub name: String,                  /* name of kernel interface */
    pub description: Option<String>,   /* VRF description - may get from cfg or add ourselves */
    pub tableid: Option<RouteTableId>, /* kernel table-id */
    pub vni: Option<Vni>,              /* vni */
}
impl RouterVrfConfig {
    pub fn new(vrfid: VrfId, name: &str) -> Self {
        Self {
            vrfid,
            name: name.to_owned(),
            description: None,
            tableid: None,
            vni: None,
        }
    }
    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_owned();
    }
    pub fn set_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_owned());
        self
    }
    pub fn set_tableid(mut self, tableid: RouteTableId) -> Self {
        self.tableid = Some(tableid);
        self
    }
    pub fn set_vni(mut self, vni: Option<Vni>) -> Self {
        self.vni = vni;
        self
    }
    pub fn reset_vni(&mut self, vni: Option<Vni>) {
        self.vni = vni;
    }
}

pub type RouteV4Filter = Box<dyn Fn(&(&Ipv4Prefix, &Route)) -> bool>;
pub type RouteV6Filter = Box<dyn Fn(&(&Ipv6Prefix, &Route)) -> bool>;

impl Vrf {
    const DEFAULT_IPV4_CAPACITY: usize = 0;
    const DEFAULT_IPV6_CAPACITY: usize = 0;

    /////////////////////////////////////////////////////////////////////////
    /// Create a new [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(config: &RouterVrfConfig) -> Self {
        let routesv4 = PrefixMapTrieWithDefault::with_capacity(Vrf::DEFAULT_IPV4_CAPACITY);
        let routesv6 = PrefixMapTrieWithDefault::with_capacity(Vrf::DEFAULT_IPV6_CAPACITY);
        let mut vrf = Self {
            name: config.name.to_owned(),
            vrfid: config.vrfid,
            tableid: config.tableid,
            description: config.description.to_owned(),
            vni: config.vni,
            status: VrfStatus::Active,
            routesv4,
            routesv6,
            nhstore: NhopStore::new(),
            fibw: None,
        };

        /* add default routes with default next-hop with action DROP */
        /* These adds make the unsafe code above safe */
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
    /// Dump the contents of a Vrf, preceded by some optional heading
    /////////////////////////////////////////////////////////////////////////
    #[cfg(test)]
    pub fn dump(&self, heading: Option<&str>) {
        if let Some(heading) = heading {
            print!("{}", Frame(heading.to_owned()));
        }
        print!("{self}");
    }

    ////////////////////////////////////////////////////////////////////////
    /// Set the table id for a [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    pub fn set_tableid(&mut self, tableid: RouteTableId) {
        self.tableid = Some(tableid);
    }

    ////////////////////////////////////////////////////////////////////////
    /// Set a description for a [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    pub fn set_description(&mut self, description: &str) {
        self.description = Some(description.to_owned());
    }

    ////////////////////////////////////////////////////////////////////////
    /// Set the fibw for a [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    pub fn set_fibw(&mut self, fibw: FibWriter) {
        self.fibw = Some(fibw);
    }

    ////////////////////////////////////////////////////////////////////////
    /// Get a fibreader for the fib associated to this [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn get_vrf_fibr(&self) -> Option<FibReader> {
        self.fibw.as_ref().map(|fibw| fibw.as_fibreader())
    }

    ////////////////////////////////////////////////////////////////////////
    /// Get the `FibId` of the Fib associated to this [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    pub fn get_vrf_fibid(&self) -> Option<FibId> {
        self.get_vrf_fibr()?.get_id()
    }

    /////////////////////////////////////////////////////////////////////////
    /// Set the [`Vni`] for a [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    pub fn set_vni(&mut self, vni: Vni) {
        self.vni = Some(vni);
        debug!("Associated vni {vni} to Vrf '{}'", self.name);
    }

    /////////////////////////////////////////////////////////////////////////
    /// Set the status of a [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    pub fn set_status(&mut self, status: VrfStatus) {
        // the default vrf (vrfid = 0) can't be deleted and it's always active
        if self.status != status && self.vrfid != 0 {
            self.status = status;
            debug!("Vrf {} status changed to {status}", self.name);
        }
    }

    /////////////////////////////////////////////////////////////////////////
    /// Check if a [`Vrf`] needs to be deleted and mark it as such. Only
    /// [`Vrf`]s in state `Deleting` can be deleted and the default VRF never
    /// gets to that status.
    /////////////////////////////////////////////////////////////////////////
    pub fn check_deletion(&mut self) {
        if self.status == VrfStatus::Deleting {
            if self.routesv4.len() == 1 && self.routesv6.len() == 1 {
                let r1 = self
                    .get_route(Prefix::root_v4())
                    .unwrap_or_else(|| unreachable!());
                let r2 = self
                    .get_route(Prefix::root_v6())
                    .unwrap_or_else(|| unreachable!());
                // make sure the only route present for 0.0.0.0/ or ::0/0 is the
                // route set by us
                if (r1.origin == RouteOrigin::Other && r2.origin == RouteOrigin::Other)
                    && r1.s_nhops.len() == 1
                    && r2.s_nhops.len() == 1
                    && r1.s_nhops[0].rc.key.fwaction == FwAction::Drop
                    && r2.s_nhops[0].rc.key.fwaction == FwAction::Drop
                {
                    self.set_status(VrfStatus::Deleted);
                }
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////
    /// Tell if a vrf can be deleted
    /////////////////////////////////////////////////////////////////////////
    pub fn can_be_deleted(&self) -> bool {
        self.status == VrfStatus::Deleted
    }

    /////////////////////////////////////////////////////////////////////////
    /// Set the VTEP for a [`Vrf`]. This should be set on vrf creation or anytime
    /// the config causes the vtep ip or mac to change.
    /////////////////////////////////////////////////////////////////////////
    pub fn set_vtep(&mut self, vtep: &Vtep) {
        if let Some(ref mut fibw) = self.fibw {
            debug!("Updating VTEP for VRF {}...", self.name);
            fibw.set_vtep(vtep.clone());
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////
    /// Get the VTEP for a [`Vrf`]. N.B: this gets the value currently visible by readers
    //////////////////////////////////////////////////////////////////////////////////////
    pub fn get_vtep(&self) -> Option<Vtep> {
        self.fibw.as_ref().map(|fibw| fibw.get_vtep().clone())
    }

    #[inline]
    #[must_use]
    /////////////////////////////////////////////////////////////////////////
    /// Add next-hop if it does not exist and get a refcounted reference to it.
    /////////////////////////////////////////////////////////////////////////
    fn register_shared_nhop(&mut self, nhop: &RouteNhop) -> Rc<Nhop> {
        self.nhstore.add_nhop(&nhop.key)
    }

    /////////////////////////////////////////////////////////////////////////
    /// Register a shared next-hop for the route if not there
    /////////////////////////////////////////////////////////////////////////
    fn register_shared_nhops(&mut self, route: &mut Route, nhops: &[RouteNhop]) {
        for nhop in nhops {
            let shared = self.register_shared_nhop(nhop);
            let ext_vrf = if nhop.vrfid == self.vrfid {
                None
            } else {
                Some(nhop.vrfid)
            };
            /* create shim next-hop */
            let shim = ShimNhop::new(ext_vrf, shared);

            /* add to route */
            route.s_nhops.push(shim);
        }
    }

    #[inline]
    /////////////////////////////////////////////////////////////////////////
    /// Declare next-hop is no longer needed. Nhop will be deleted if no one
    /// needs it.
    /////////////////////////////////////////////////////////////////////////
    fn deregister_shared_nhop(&mut self, shim: ShimNhop) {
        let key = shim.rc.key.clone();
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
        // register next-hops. This mutates the route adding refernces to the stored next-hops
        self.register_shared_nhops(&mut route, nhops);

        // resolve next-hops
        let rvrf = vrf0.unwrap_or(self);
        for shim in &route.s_nhops {
            shim.rc.lazy_resolve(rvrf);
        }

        // store route
        match prefix {
            Prefix::IPV4(p) => self.routesv4.insert(*p, route.clone()),
            Prefix::IPV6(p) => self.routesv6.insert(*p, route.clone()),
        };
    }

    #[allow(unused)] // Not used
    pub fn refresh_fib(&mut self, rstore: &RmacStore, resvrf: &Vrf) {
        self.nhstore.lazy_resolve_all(resvrf);
        self.nhstore.set_fibgroup_all(rstore);

        let updates: Vec<(Prefix, FibGroup)> = self
            .iter_v4()
            .map(|(prefix, route)| {
                let mut fibgroup = FibGroup::new();
                for nhop in &route.s_nhops {
                    let nhfibg = &*nhop.rc.fibgroup.borrow();
                    fibgroup.extend(nhfibg);
                }
                (Prefix::IPV4(*prefix), fibgroup)
            })
            .collect(); /* collect to avoid borrow-checker complaints */
        if let Some(fibw) = &mut self.fibw {
            updates.into_iter().for_each(|(prefix, fibgroup)| {
                fibw.add_fibgroup(prefix, fibgroup, false);
            });
            fibw.publish();
        }
    }

    pub fn refresh_fib_updates(&self, rstore: &RmacStore, resvrf: &Vrf) -> Vec<(Prefix, FibGroup)> {
        self.nhstore.lazy_resolve_all(resvrf);
        self.nhstore.set_fibgroup_all(rstore);

        let updates: Vec<(Prefix, FibGroup)> = self
            .iter_v4()
            .map(|(prefix, route)| {
                let mut fibgroup = FibGroup::new();
                for nhop in &route.s_nhops {
                    let nhfibg = &*nhop.rc.fibgroup.borrow();
                    fibgroup.extend(nhfibg);
                }
                (Prefix::IPV4(*prefix), fibgroup)
            })
            .collect();
        updates
    }

    pub fn add_route_complete(
        &mut self,
        prefix: &Prefix,
        mut route: Route,
        nhops: &[RouteNhop],
        vrf0: Option<&Vrf>,
        rstore: &RmacStore,
    ) {
        // register next-hops. This mutates the route adding references to the stored next-hops
        self.register_shared_nhops(&mut route, nhops);

        // resolve next-hops
        let rvrf = vrf0.unwrap_or(self);

        // resolve the next-hops of the received route
        for shim in &route.s_nhops {
            let refc = self.nhstore.get_nhop_rc_count(&shim.rc.key);
            if refc == 2 {
                shim.rc.lazy_resolve(rvrf);
                shim.rc.as_ref().set_fibgroup(rstore);
            }
        }

        // Fib is optional atm
        if let Some(fibw) = &mut self.fibw {
            // build a fib group from the fib groups of all next-hops for this route
            let mut fibgroup = FibGroup::new();
            for nhop in &route.s_nhops {
                let nhfibg = &*nhop.rc.fibgroup.borrow();
                fibgroup.extend(nhfibg);
            }
            // add to fib
            fibw.add_fibgroup(*prefix, fibgroup, true);
        }

        // store the route
        let prior = match prefix {
            Prefix::IPV4(p) => self.routesv4.insert(*p, route),
            Prefix::IPV6(p) => self.routesv6.insert(*p, route),
        };
        // if we happen to replace a route, unregister its next-hops
        if let Some(mut prior) = prior {
            self.deregister_shared_nexthops(&mut prior);
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Route removal
    /////////////////////////////////////////////////////////////////////////

    #[inline]
    fn del_route_v4(&mut self, prefix: Ipv4Prefix) {
        // iptrie forbids removing the default route (at root).
        // So, we have to replace it with a dummy route with action Drop, to actually represent a lack of route.
        if prefix == Ipv4Prefix::default() {
            if let Some(mut prior) = self.routesv4.insert(prefix, Route::default()) {
                self.deregister_shared_nexthops(&mut prior);
            }
            self.add_route(
                &Prefix::from(prefix),
                Route::default(),
                &[RouteNhop::default()],
                None,
            );
        } else if let Some(found) = &mut self.routesv4.remove(&prefix) {
            self.deregister_shared_nexthops(found);
        }
    }
    #[inline]
    fn del_route_v6(&mut self, prefix: Ipv6Prefix) {
        // iptrie forbids removing the default route (at root).
        // So, we have to replace it with a dummy route with action Drop, to actually represent a lack of route.
        if prefix == Ipv6Prefix::default() {
            if let Some(mut prior) = self.routesv6.insert(prefix, Route::default()) {
                self.deregister_shared_nexthops(&mut prior);
            }
            self.add_route(
                &Prefix::from(prefix),
                Route::default(),
                &[RouteNhop::default()],
                None,
            );
        } else if let Some(found) = &mut self.routesv6.remove(&prefix) {
            self.deregister_shared_nexthops(found);
        }
    }
    pub fn del_route(&mut self, prefix: Prefix) {
        match prefix {
            Prefix::IPV4(p) => self.del_route_v4(p),
            Prefix::IPV6(p) => self.del_route_v6(p),
        }
        if let Some(fibw) = &mut self.fibw {
            fibw.del_fibgroup(prefix);
        }
        self.check_deletion();
    }

    /////////////////////////////////////////////////////////////////////////
    // Route retrieval
    /////////////////////////////////////////////////////////////////////////

    #[inline]
    fn get_route_v4(&self, prefix: Ipv4Prefix) -> Option<&Route> {
        self.routesv4.get(&prefix)
    }
    #[inline]
    fn get_route_v6(&self, prefix: Ipv6Prefix) -> Option<&Route> {
        self.routesv6.get(&prefix)
    }
    pub fn get_route(&self, prefix: Prefix) -> Option<&Route> {
        match prefix {
            Prefix::IPV4(p) => self.get_route_v4(p),
            Prefix::IPV6(p) => self.get_route_v6(p),
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Route retrieval (mutable): we may not need this and if we do, extra
    // care should be taken modifying route internals
    /////////////////////////////////////////////////////////////////////////

    #[inline]
    fn get_route_v4_mut(&mut self, prefix: Ipv4Prefix) -> Option<&mut Route> {
        self.routesv4.get_mut(&prefix)
    }
    #[inline]
    fn get_route_v6_mut(&mut self, prefix: Ipv6Prefix) -> Option<&mut Route> {
        self.routesv6.get_mut(&prefix)
    }
    pub fn get_route_mut(&mut self, prefix: Prefix) -> Option<&mut Route> {
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
        self.routesv4.len()
    }
    pub fn len_v6(&self) -> usize {
        self.routesv6.len()
    }
    /////////////////////////////////////////////////////////////////////////
    // LPM, single call
    /////////////////////////////////////////////////////////////////////////

    #[inline]
    fn lpm_v4(&self, target: Ipv4Prefix) -> (&Ipv4Prefix, &Route) {
        self.routesv4.lookup_wd(target)
    }
    #[inline]
    fn lpm_v6(&self, target: Ipv6Prefix) -> (&Ipv6Prefix, &Route) {
        self.routesv6.lookup_wd(target)
    }
    pub fn lpm(&self, target: IpAddr) -> (Prefix, &Route) {
        match target {
            IpAddr::V4(a) => {
                let (p, r) = self.lpm_v4(a.into());
                (Prefix::IPV4(*p), r)
            }
            IpAddr::V6(a) => {
                let (p, r) = self.lpm_v6(a.into());
                (Prefix::IPV6(*p), r)
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////
    /// Special routes
    /////////////////////////////////////////////////////////////////////////
    pub fn add_link_local_intf_multicast_route(&mut self, ifindex: InterfaceIndex) {
        let nhkey = NhopKey::new(
            RouteOrigin::Local,
            None,
            Some(ifindex),
            None,
            FwAction::default(),
            None,
        );
        self.add_route(
            &Prefix::ipv4_link_local_mcast_prefix(),
            Route::with_origin(RouteOrigin::Local),
            &[RouteNhop::from_nhkey(&nhkey)],
            None,
        );
    }
}

#[cfg(test)]
#[rustfmt::skip]
pub mod tests {
    use super::*;
    use std::str::FromStr;
    use crate::rib::vrf::VrfId;
    use crate::rib::nexthop::{FwAction, NhopKey};
    use crate::rib::encapsulation::{Encapsulation, VxlanEncapsulation};

    #[test]
    fn test_vrf_build() {
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let vrf = Vrf::new(&vrf_cfg);
        assert_eq!(vrf.len_v4(), 1, "An Ipv4 default route must exist.");
        assert_eq!(vrf.len_v6(), 1, "An Ipv6 default route must exist.");
        assert_eq!(vrf.nhstore.len(), 1, "A single 'drop' nexthop must be there.");
        vrf.dump(Some("Brand new VRF"));
    }

    fn check_default_drop_v4(vrf: &Vrf) {
        let prefix: Prefix = Prefix::root_v4();
        let recovered = vrf.get_route_v4(*prefix.get_v4()).expect("There must be a default route");
        assert_eq!(recovered.s_nhops.len(), 1);
        assert_eq!(recovered.s_nhops[0].rc.key.fwaction, FwAction::Drop);
    }
    fn check_default_drop_v6(vrf: &Vrf) {
        let prefix: Prefix = Prefix::root_v6();
        let recovered = vrf.get_route_v6(*prefix.get_v6()).expect("There must be a default route");
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
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);

        let pref_v4: Prefix = Prefix::root_v4();
        let pref_v6: Prefix = Prefix::root_v6();

        /* default-Drop routes must be there */
        check_default_drop_v4(&vrf);
        check_default_drop_v6(&vrf);

        /* default-Drop routes cannot be deleted */
        vrf.del_route(pref_v4);
        vrf.del_route(pref_v6);
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
        ifindex: Option<u32>,
        vrfid: VrfId,
        encap: Option<Encapsulation>,
    ) -> RouteNhop {
        let key = NhopKey::new(
            RouteOrigin::default(),
            address.map(mk_addr),
            ifindex.map(|i| InterfaceIndex::try_new(i).unwrap()), encap,FwAction::Forward, None);

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
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);
        vrf.dump(Some("Initial (clean)"));

        /* Add static default via 10.0.0.1 */
        let prefix: Prefix = Prefix::root_v4();
        let route = build_test_route(RouteOrigin::Static, 1, 0);
        let nhop = build_test_nhop(Some("10.0.0.1"), None, 0, None);
        vrf.add_route(&prefix, route, &[nhop], None);

        assert_eq!(vrf.len_v4(), 1, "Should have replaced the default");
        vrf.dump(Some("With static IPv4 default non-drop route"));

        /* delete the static default. This should put back again a default route with action DROP */
        vrf.del_route(prefix);
        check_default_drop_v4(&vrf);

        vrf.dump(Some("After removing the IPv4 static default"));
    }

    #[test]
    fn test_default_replace_v6() {
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);

        vrf.dump(Some("Initial (clean)"));

        /* Add static default via 2001::1 */
        let prefix: Prefix = Prefix::root_v4();
        let route = build_test_route(RouteOrigin::Static, 1, 0);
        let nhop = build_test_nhop(Some("2001::1"), None, 0, None);
        vrf.add_route(&prefix, route, &[nhop], None);

        assert_eq!(vrf.len_v6(), 1, "Should have replaced the default");
        vrf.dump(Some("With static IPv6 default non-drop route"));

        /* delete the static default. This should put back again a default route with action DROP */
        vrf.del_route(prefix);
        check_default_drop_v6(&vrf);

        vrf.dump(Some("After removing the IPv6 static default"));
    }

    #[test]
    fn test_vrf_basic() {
        let num_routes = 10;
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);

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
            let (longest, best) = vrf.lpm(target);
            assert_eq!(longest, prefix);
            assert_eq!(best.distance, route.distance);
            assert_eq!(best.metric, route.metric);
            assert_eq!(best.origin, route.origin);
            assert_eq!(best.s_nhops.len(), 2);
            assert!(best.s_nhops.iter().any(|s| s.rc.key.address == Some(mk_addr("10.0.0.1")) && s.rc.key.ifindex == Some(InterfaceIndex::try_new(1).unwrap())));
            assert!(best.s_nhops.iter().any(|s| s.rc.key.address == Some(mk_addr("10.0.0.2")) && s.rc.key.ifindex == Some(InterfaceIndex::try_new(2).unwrap())));
        }
        assert_eq!(vrf.len_v4(),  (1 + num_routes) as usize, "There must be default + the ones added");
        assert_eq!(vrf.nhstore.len(), 3usize,"There is drop + 2 nexthops shared by all routes");

        for i in 1..=num_routes {
            /* delete v4 routes one at a time */
            let prefix = Prefix::expect_from((format!("7.0.0.{i}").as_str(), 32));
            vrf.del_route(prefix);

            /* each route prefix should resolve only to default */
            let target = prefix.as_address();
            let (longest, best) = vrf.lpm(target);

            assert_eq!(longest, Prefix::root_v4(), "Must resolve via default");
            assert_eq!(best.s_nhops.len(), 1);
            assert_eq!(best.s_nhops[0].rc.key.fwaction, FwAction::Drop, "Default is drop");
        }
        check_vrf_is_empty(&vrf);

    }


    #[test]
    fn test_route_filtering() {
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);

        /* connected */
        let nh = build_test_nhop(None, Some(1), 0, None);
        let connected = build_test_route(RouteOrigin::Connected, 0, 1);
        let prefix = Prefix::expect_from(("10.0.0.0", 24));
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
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);

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
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);

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
            origin: RouteOrigin::default(),
            address: Some(mk_addr("7.0.0.1")),
            ifindex: None,
            encap: Some(Encapsulation::Vxlan(VxlanEncapsulation::new(
                Vni::new_checked(3000).expect("Should be ok"),
                IpAddr::from_str("7.0.0.1").unwrap(),
            ))),
            fwaction: FwAction::default(),
            ifname: None,
        };

        /* check how the next-hop has been resolved */
        let _nhop = vrf.nhstore.get_nhop(&nhkey).expect("Should be there");
        /* Todo: finish test */
    }
}
