// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VRF module to store Ipv4 and Ipv6 routing tables

use bitflags::bitflags;
use std::borrow::Cow;
use std::hash::Hash;
use std::net::IpAddr;
use std::rc::{Rc, Weak};
use tracing::{debug, warn};

#[cfg(test)]
use common::cliprovider::Frame;

use super::nexthop::{FwAction, Nhop, NhopKey, NhopStore};
use crate::evpn::{RmacStore, Vtep};
use crate::fib::fibtype::FibWriter;
use lpm::prefix::{Ipv4Prefix, Ipv6Prefix, Prefix};
use lpm::trie::{PrefixMapTrie, TrieMap, TrieMapFactory};
use net::route::RouteTableId;
use net::vxlan::Vni;
use std::time::Instant;

/// Every VRF is univocally identified with a numerical VRF id
pub type VrfId = u32;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
/// A temporary data structure that represents a route next-hop
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

bitflags! {
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct RouteFlags: u8 {
        const STALE = 0b0000_0001; /* the route is stale, if set */
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
    pub flags: RouteFlags,
    pub origin: RouteOrigin,
    pub distance: u8,
    pub metric: u32,
    pub s_nhops: Vec<ShimNhop>,
    pub tstamp: Instant,
}
impl Default for Route {
    fn default() -> Self {
        Self {
            flags: RouteFlags::default(),
            origin: RouteOrigin::default(),
            distance: 0,
            metric: 0,
            s_nhops: Vec::with_capacity(1),
            tstamp: clock::now(),
        }
    }
}
impl Route {
    #[must_use]
    pub fn is_stale(&self) -> bool {
        self.flags.contains(RouteFlags::STALE)
    }
    pub fn set_stale(&mut self, value: bool) {
        if value {
            self.flags.insert(RouteFlags::STALE);
        } else {
            self.flags.remove(RouteFlags::STALE);
        }
    }
    #[must_use]
    pub fn is_preset_drop_route(&self) -> bool {
        self.origin == RouteOrigin::Other
            && self.s_nhops.len() == 1
            && self.metric == 0
            && self.distance == 0
            && self.s_nhops[0].rc.key.fwaction == FwAction::Drop
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

#[derive(Copy, Clone, Debug, PartialEq)]
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
    pub(crate) routesv4: PrefixMapTrie<Ipv4Prefix, Route>,
    pub(crate) routesv6: PrefixMapTrie<Ipv6Prefix, Route>,
    pub(crate) nhstore: NhopStore,
    pub(crate) vni: Option<Vni>,
    pub(crate) fibw: Option<FibWriter>,
}

//////////////////////////////////////////////////////////////////////////////////
/// A [`RouterVrfConfig`] contains the configuration to create a vrf
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
    #[must_use]
    pub fn new(vrfid: VrfId, name: &str) -> Self {
        Self {
            vrfid,
            name: name.to_string(),
            description: None,
            tableid: None,
            vni: None,
        }
    }
    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
    }
    #[must_use]
    pub fn set_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_owned());
        self
    }
    #[must_use]
    pub fn set_tableid(mut self, tableid: RouteTableId) -> Self {
        self.tableid = Some(tableid);
        self
    }
    #[must_use]
    pub fn set_vni(mut self, vni: Option<Vni>) -> Self {
        self.vni = vni;
        self
    }
    pub fn reset_vni(&mut self, vni: Option<Vni>) {
        self.vni = vni;
    }
}

pub type RouteV4Filter = Box<dyn Fn(&(Ipv4Prefix, &Route)) -> bool>;
pub type RouteV6Filter = Box<dyn Fn(&(Ipv6Prefix, &Route)) -> bool>;

impl Vrf {
    /// The `VrfId` of the default `Vrf`.
    pub const DEFAULT_VRFID: VrfId = 0;

    /////////////////////////////////////////////////////////////////////////
    /// Create a new [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(config: &RouterVrfConfig) -> Self {
        let routesv4 = PrefixMapTrie::create();
        let routesv6 = PrefixMapTrie::create();
        let mut vrf = Self {
            name: config.name.clone(),
            vrfid: config.vrfid,
            tableid: config.tableid,
            description: config.description.clone(),
            vni: config.vni,
            status: VrfStatus::Active,
            routesv4,
            routesv6,
            nhstore: NhopStore::new(),
            fibw: None,
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

    /////////////////////////////////////////////////////////////////////////
    /// Set the [`Vni`] for a [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    pub fn set_vni(&mut self, vni: Vni) {
        self.vni = Some(vni);
        debug!("Set vni {vni} to Vrf {} ({})", self.vrfid, self.name);
    }

    /////////////////////////////////////////////////////////////////////////
    /// Set the status of a [`Vrf`]
    /////////////////////////////////////////////////////////////////////////
    pub fn set_status(&mut self, status: VrfStatus) {
        // the default vrf (vrfid = 0) can't be deleted and it's always active
        if self.status != status && !self.is_default_vrf() {
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
                // Mark as deleted if the only two routes are the 'drop' ones
                // that we automatically set on VRF creation. If they aren't
                // they should be deleted first.
                if r1.is_preset_drop_route() && r2.is_preset_drop_route() {
                    self.set_status(VrfStatus::Deleted);
                }
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////
    /// Tell if a vrf is the default vrf
    /////////////////////////////////////////////////////////////////////////
    pub fn is_default_vrf(&self) -> bool {
        self.vrfid == Self::DEFAULT_VRFID
    }

    /////////////////////////////////////////////////////////////////////////
    /// Tell if a vrf can be deleted
    /////////////////////////////////////////////////////////////////////////
    pub fn can_be_deleted(&self) -> bool {
        self.status == VrfStatus::Deleted
    }

    /////////////////////////////////////////////////////////////////////////
    /// Tell if a vrf is in deleting state
    /////////////////////////////////////////////////////////////////////////
    pub fn is_deleting(&self) -> bool {
        self.status == VrfStatus::Deleting
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
        self.fibw.as_ref().and_then(FibWriter::get_vtep)
    }

    /////////////////////////////////////////////////////////////////////////
    /// Register a shared next-hop for the route if not there and return a
    /// vector of shared references to the next-hops used by the route.
    /////////////////////////////////////////////////////////////////////////
    fn register_shared_nhops(&mut self, nhops: &[RouteNhop]) -> Vec<ShimNhop> {
        let mut nhop_refs = Vec::with_capacity(nhops.len());
        for nhop in nhops {
            let shared = self.nhstore.add_nhop(&nhop.key);
            let ext_vrf = if nhop.vrfid == self.vrfid {
                None
            } else {
                Some(nhop.vrfid)
            };
            let shim = ShimNhop::new(ext_vrf, shared);
            nhop_refs.push(shim);
        }
        nhop_refs
    }

    #[inline]
    /////////////////////////////////////////////////////////////////////////
    /// Declare next-hop is no longer needed. The next-hop may not be removed
    /// at this point since it may be used by other routes. This method returns
    /// true if the next-hop was removed and false otherwise.
    /////////////////////////////////////////////////////////////////////////
    fn deregister_shared_nhop(&mut self, shim: ShimNhop) -> bool {
        let key = shim.rc.key.clone();
        drop(shim);
        self.nhstore.del_nhop(&key)
    }

    /////////////////////////////////////////////////////////////////////////
    /// De-register a shared next-hop for the route
    /////////////////////////////////////////////////////////////////////////
    fn deregister_shared_nexthops(&mut self, route: &mut Route) {
        let mut count = 0;
        while let Some(shim) = route.s_nhops.pop() {
            let key = shim.rc.key.clone();
            if self.deregister_shared_nhop(shim) {
                count += 1;
                if let Some(fibw) = &mut self.fibw {
                    fibw.unregister_fibgroup(&key, false);
                }
            }
        }
        if count > 0 {
            if let Some(fibw) = &mut self.fibw {
                fibw.publish();
            }
        }
    }

    fn nhops_or_drop<'a>(prefix: &Prefix, nhops: &'a [RouteNhop]) -> Cow<'a, [RouteNhop]> {
        if nhops.is_empty() {
            warn!("Route to {prefix} has no next-hop: will install it with action drop");
            Cow::Owned(vec![RouteNhop::default()])
        } else {
            Cow::Borrowed(nhops)
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Route Insertion
    /////////////////////////////////////////////////////////////////////////
    fn add_route(
        &mut self,
        prefix: &Prefix,
        mut route: Route,
        nhops: &[RouteNhop],
        vrf0: Option<&Vrf>,
    ) {
        // register next-hops and let the route keep references to the shared nexthops created/found
        route.s_nhops = self.register_shared_nhops(&Self::nhops_or_drop(prefix, nhops));

        // resolve the new route next-hops. This is only for testing. In prod code,
        // this method is only used for drop routes which require no resolution.
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

    /// Rebuild all next-hop state. This is where consistency is maintained
    fn refresh_nhops(&self, rstore: &RmacStore, resvrf: Option<&Vrf>) -> Vec<Weak<Nhop>> {
        let resvrf = resvrf.unwrap_or(self);
        self.nhstore.rebuild_nhop_instructions(rstore);
        self.nhstore.lazy_resolve_all(resvrf);
        self.nhstore.rebuild_fibgroups(rstore)
    }

    /// Apply the given changes to a fib
    fn update_fib(fibw: &mut FibWriter, changes: &[Weak<Nhop>]) {
        if changes.is_empty() {
            return;
        }
        let mut count = 0;
        for nhop in changes.iter().filter_map(Weak::upgrade) {
            let fibgroup = &nhop.fibgroup.borrow();
            debug!("Updating fib group for nhop {}...", nhop.key);
            fibw.register_fibgroup(&nhop.key, fibgroup, false);
            count += 1;
        }
        if count > 0 {
            fibw.publish();
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    /// Re-resolve the next-hops of a `Vrf`, rebuild their fibgroups and, if they changed, reflect
    /// the changes in the corresponding `Fib`
    ////////////////////////////////////////////////////////////////////////////////////////////////
    pub(crate) fn refresh_fib(&mut self, rstore: &RmacStore, resvrf: Option<&Vrf>) {
        let changes = self.refresh_nhops(rstore, resvrf);
        if let Some(fibw) = &mut self.fibw {
            Self::update_fib(fibw, &changes);
        }
    }

    pub(crate) fn add_route_complete(
        &mut self,
        prefix: &Prefix,
        mut route: Route,
        nhops: &[RouteNhop],
        vrf0: Option<&Vrf>,
        rstore: &RmacStore,
    ) {
        // register next-hops and let the route keep references to the shared nexthops created/found
        route.s_nhops = self.register_shared_nhops(&Self::nhops_or_drop(prefix, nhops));

        let rvrf = vrf0.unwrap_or(self);

        // resolve the next-hops of the received route: none of this is needed since we
        // call refresh_fib at the end. Leaving it for future optimizations.
        for shim in &route.s_nhops {
            let refc = self.nhstore.nhop_strong_count(&shim.rc.key);
            shim.rc.build_nhop_instructions(rstore); // not needed, set_fibgroup() calls it
            if refc == 2 {
                shim.rc.lazy_resolve(rvrf);
            }
        }

        // update fib: this is not needed if we always call refresh fib.
        // Leaving it for future optimizations.
        if let Some(fibw) = &mut self.fibw {
            let mut nhkeys = Vec::with_capacity(route.s_nhops.len());
            for shim in &route.s_nhops {
                if shim.rc.as_ref().set_fibgroup(rstore) {
                    let fibgroup = &*shim.rc.as_ref().fibgroup.borrow();
                    fibw.register_fibgroup(&shim.rc.key, fibgroup, false);
                }
                nhkeys.push(shim.rc.key.clone());
            }
            fibw.add_fibroute(*prefix, nhkeys, true);
        }

        // store the route in this vrf
        let prior = match prefix {
            Prefix::IPV4(p) => self.routesv4.insert(*p, route),
            Prefix::IPV6(p) => self.routesv6.insert(*p, route),
        };

        // if we happen to replace a route, unregister its next-hops
        if let Some(mut prior) = prior {
            self.deregister_shared_nexthops(&mut prior);
        }

        // refresh FIB
        self.refresh_fib(rstore, vrf0);
    }

    /////////////////////////////////////////////////////////////////////////
    // Route removal
    /////////////////////////////////////////////////////////////////////////

    #[inline]
    fn del_route_v4(&mut self, prefix: Ipv4Prefix) {
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
        } else if let Some(found) = &mut self.routesv4.remove(prefix) {
            self.deregister_shared_nexthops(found);
        }
    }
    #[inline]
    fn del_route_v6(&mut self, prefix: Ipv6Prefix) {
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
        } else if let Some(found) = &mut self.routesv6.remove(prefix) {
            self.deregister_shared_nexthops(found);
        }
    }
    pub(crate) fn del_route(&mut self, prefix: Prefix, vrf0: Option<&Vrf>, rstore: &RmacStore) {
        match prefix {
            Prefix::IPV4(p) => self.del_route_v4(p),
            Prefix::IPV6(p) => self.del_route_v6(p),
        }
        if let Some(fibw) = &mut self.fibw {
            fibw.del_fibroute(prefix);
        }
        self.check_deletion();
        self.refresh_fib(rstore, vrf0);
    }

    /////////////////////////////////////////////////////////////////////////
    // Route retrieval
    /////////////////////////////////////////////////////////////////////////

    #[inline]
    fn get_route_v4(&self, prefix: Ipv4Prefix) -> Option<&Route> {
        self.routesv4.get(prefix)
    }

    #[inline]
    fn get_route_v6(&self, prefix: Ipv6Prefix) -> Option<&Route> {
        self.routesv6.get(prefix)
    }
    #[must_use]
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

    #[cfg(test)]
    fn get_route_v4_mut(&mut self, prefix: Ipv4Prefix) -> Option<&mut Route> {
        self.routesv4.get_mut(prefix)
    }
    #[cfg(test)]
    fn get_route_v6_mut(&mut self, prefix: Ipv6Prefix) -> Option<&mut Route> {
        self.routesv6.get_mut(prefix)
    }
    #[allow(unused)]
    #[cfg(test)]
    pub fn get_route_mut(&mut self, prefix: Prefix) -> Option<&mut Route> {
        match prefix {
            Prefix::IPV4(p) => self.get_route_v4_mut(p),
            Prefix::IPV6(p) => self.get_route_v6_mut(p),
        }
    }

    // ///////////////////////////////////////////////////////////////////////
    // iterators, filters and counts
    // //////////////////////////////////////////////////////////////////////
    pub fn iter_v4(&self) -> impl Iterator<Item = (Ipv4Prefix, &Route)> {
        self.routesv4.iter()
    }
    pub fn iter_v6(&self) -> impl Iterator<Item = (Ipv6Prefix, &Route)> {
        self.routesv6.iter()
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
    fn lpm_v4(&self, target: Ipv4Prefix) -> (Ipv4Prefix, &Route) {
        self.routesv4
            .lookup(target)
            .unwrap_or_else(|| unreachable!())
    }
    #[inline]
    fn lpm_v6(&self, target: Ipv6Prefix) -> (Ipv6Prefix, &Route) {
        self.routesv6
            .lookup(target)
            .unwrap_or_else(|| unreachable!())
    }
    pub fn lpm(&self, target: IpAddr) -> (Prefix, &Route) {
        match target {
            IpAddr::V4(a) => {
                let (p, r) = self.lpm_v4(a.into());
                (Prefix::IPV4(p), r)
            }
            IpAddr::V6(a) => {
                let (p, r) = self.lpm_v6(a.into());
                (Prefix::IPV6(p), r)
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////
    /// Set/unset stale flag for all `Route`s in a `Vrf`
    /////////////////////////////////////////////////////////////////////////
    pub fn set_stale(&mut self, value: bool) {
        self.routesv4
            .iter_mut()
            .filter(|(prefix, route)| {
                *prefix != Ipv4Prefix::default() && !route.is_preset_drop_route()
            })
            .for_each(|(_, route)| route.set_stale(value));

        self.routesv6
            .iter_mut()
            .filter(|(prefix, route)| {
                *prefix != Ipv6Prefix::default() && !route.is_preset_drop_route()
            })
            .for_each(|(_, route)| route.set_stale(value));
    }

    /////////////////////////////////////////////////////////////////////////
    /// Remove all ipv4 routes marked as stale from a `Vrf`
    /////////////////////////////////////////////////////////////////////////
    fn remove_stale_routes_v4(&mut self, vrf0: Option<&Vrf>, rstore: &RmacStore) {
        // collect all prefixes that contain stale routes. We need to first collect
        // them and then delete to make the borrow-checker happy.
        let prefixes: Vec<_> = self
            .routesv4
            .iter()
            .filter_map(
                |(prefix, route)| {
                    if route.is_stale() { Some(prefix) } else { None }
                },
            )
            .collect();
        // delete the routes
        for prefix in prefixes {
            debug!("vrf {}: removing stale route to {}", self.name, prefix);
            self.del_route(prefix.into(), vrf0, rstore);
        }
    }
    /////////////////////////////////////////////////////////////////////////
    /// Remove all ipv6 routes marked as stale from a `Vrf`
    /////////////////////////////////////////////////////////////////////////
    fn remove_stale_routes_v6(&mut self, vrf0: Option<&Vrf>, rstore: &RmacStore) {
        let prefixes: Vec<_> = self
            .routesv6
            .iter()
            .filter_map(
                |(prefix, route)| {
                    if route.is_stale() { Some(prefix) } else { None }
                },
            )
            .collect();
        for prefix in prefixes {
            debug!("vrf {}: removing stale route to {}..", self.name, prefix);
            self.del_route(prefix.into(), vrf0, rstore);
        }
    }
    /////////////////////////////////////////////////////////////////////////
    /// Remove all the ipv4 & ipv6 routes marked as stale from a `Vrf`
    /////////////////////////////////////////////////////////////////////////
    pub fn remove_stale_routes(&mut self, vrf0: Option<&Vrf>, rstore: &RmacStore) {
        debug!("Removing stale routes from vrf {}..", self.name);
        self.remove_stale_routes_v4(vrf0, rstore);
        self.remove_stale_routes_v6(vrf0, rstore);
    }
}

#[cfg(test)]
#[rustfmt::skip]
#[allow(clippy::cast_sign_loss)]
pub mod tests {
    use net::interface::InterfaceIndex;
    use common::cliprovider::Frame;

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
        let rstore = RmacStore::new();
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);

        let pref_v4: Prefix = Prefix::root_v4();
        let pref_v6: Prefix = Prefix::root_v6();

        /* default-Drop routes must be there */
        check_default_drop_v4(&vrf);
        check_default_drop_v6(&vrf);

        /* default-Drop routes cannot be deleted */
        vrf.del_route(pref_v4, None, &rstore);
        vrf.del_route(pref_v6, None, &rstore);
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
            flags: RouteFlags::default(),
            origin,
            distance,
            metric,
            s_nhops: vec![],
            tstamp: clock::now(),
        }
    }

    #[test]
    fn test_default_replace_v4() {
        let rstore = RmacStore::new();
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);
        vrf.dump(Some("Initial (clean)"));

        /* Add some connected route */
        let prefix = Prefix::expect_from("10.0.0.0/24");
        let route = build_test_route(RouteOrigin::Connected, 1, 10);
        let nhop = build_test_nhop(None, Some(7), 0, None);
        vrf.add_route(&prefix, route, &[nhop], None);
        vrf.dump(Some("After adding connected route"));

        /* Add static default via 10.0.0.1 */
        let prefix: Prefix = Prefix::root_v4();
        let route = build_test_route(RouteOrigin::Static, 1, 123);
        let nhop = build_test_nhop(Some("10.0.0.1"), None, 0, None);
        vrf.add_route(&prefix, route, &[nhop], None);

        /* static default is added and resolves next-hop over connected route */
        let route = vrf.get_route(prefix).unwrap();
        assert_eq!(route.distance, 1);
        assert_eq!(route.metric, 123);
        assert_eq!(route.origin, RouteOrigin::Static);
        let resolvers = &route.s_nhops;
        assert_eq!(resolvers.len(), 1);
        assert_eq!(resolvers[0].rc.key.fwaction, FwAction::Forward);
        assert_eq!(resolvers[0].rc.key.address, Some(IpAddr::from_str("10.0.0.1").unwrap()));

        assert_eq!(vrf.len_v4(), 2, "Should have replaced the default");
        vrf.dump(Some("With static IPv4 default non-drop route"));

        /* delete the static default. This should put back again a default route with action DROP */
        vrf.del_route(prefix, None, &rstore);
        check_default_drop_v4(&vrf);

        vrf.dump(Some("After removing the IPv4 static default"));
    }

    #[test]
    fn test_default_replace_v6() {
        let rstore = RmacStore::new();
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);
        vrf.dump(Some("Initial (clean)"));

        /* Add some connected route */
        let prefix = Prefix::expect_from("2001::/80");
        let route = build_test_route(RouteOrigin::Connected, 1, 10);
        let nhop = build_test_nhop(None, Some(7), 0, None);
        vrf.add_route(&prefix, route, &[nhop], None);
        vrf.dump(Some("After adding connected route"));

        /* Add static default via 2001::1 */
        let prefix: Prefix = Prefix::root_v6();
        let route = build_test_route(RouteOrigin::Static, 1, 123);
        let nhop = build_test_nhop(Some("2001::1"), None, 0, None);
        vrf.add_route(&prefix, route, &[nhop], None);

        /* static default is added and resolves next-hop over connected route */
        let route = vrf.get_route(prefix).unwrap();
        assert_eq!(route.distance, 1);
        assert_eq!(route.metric, 123);
        assert_eq!(route.origin, RouteOrigin::Static);
        let resolvers = &route.s_nhops;
        assert_eq!(resolvers.len(), 1);
        assert_eq!(resolvers[0].rc.key.fwaction, FwAction::Forward);
        assert_eq!(resolvers[0].rc.key.address, Some(IpAddr::from_str("2001::1").unwrap()));

        assert_eq!(vrf.len_v6(), 2, "Should have replaced the default");
        vrf.dump(Some("With static IPv6 default non-drop route"));

        /* delete the static default. This should put back again a default route with action DROP */
        vrf.del_route(prefix, None, &rstore);
        check_default_drop_v6(&vrf);

        vrf.dump(Some("After removing the IPv6 static default"));
    }

    #[test]
    fn test_vrf_basic() {
        let rstore = RmacStore::new();
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
            vrf.del_route(prefix, None, &rstore);

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

    // modify the test vrf
    pub fn mod_test_vrf_1(vrf: &mut Vrf) {
        println!("{}", Frame("Removing paths via 10.0.0.5".to_string()));
        {
            let route: Route = build_test_route(RouteOrigin::Ospf, 0, 1);
            let n1 = build_test_nhop(Some("10.0.0.1"), None, 0, Some(Encapsulation::Mpls(8001)));
            let prefix = Prefix::expect_from(("8.0.0.1", 32));
            vrf.add_route(&prefix, route, &[n1], None);
        }
        {
            let route: Route = build_test_route(RouteOrigin::Ospf, 0, 1);
            let n3 = build_test_nhop(Some("10.0.0.9"), None, 0, Some(Encapsulation::Mpls(8009)));
            let prefix = Prefix::expect_from(("8.0.0.2", 32));
            vrf.add_route(&prefix, route, &[n3], None);
        }
    }

    // modify the test vrf
    pub fn mod_test_vrf_2(vrf: &mut Vrf) {
        println!("{}", Frame("Making 7.0.0.1 reachable only over 8.0.0.1 and 10.0.0.5".to_string()));
        {
            let route: Route = build_test_route(RouteOrigin::Ospf, 0, 1);
            let n2 = build_test_nhop(Some("10.0.0.5"), None, 0, Some(Encapsulation::Mpls(8005)));
            let prefix = Prefix::expect_from(("8.0.0.1", 32));
            vrf.add_route(&prefix, route, &[n2], None);
        }
        {
            let route: Route = build_test_route(RouteOrigin::Bgp, 0, 1);
            let n1 = build_test_nhop(Some("8.0.0.1"), None, 0, Some(Encapsulation::Mpls(7000)));
            let prefix = Prefix::expect_from(("7.0.0.1", 32));
            vrf.add_route(&prefix, route, &[n1], None);
        }
    }

    // Initialize test vrf with test routes
    pub fn init_test_vrf(vrf: &mut Vrf) {
        println!("{}", Frame("Initializing VRF routes"));
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

        add_vxlan_routes(vrf, 5);

    }

    // build a sample VRF used for testing
    pub fn build_test_vrf() -> Vrf {
        let vrf_cfg = RouterVrfConfig::new(0, "default");
        let mut vrf = Vrf::new(&vrf_cfg);
        init_test_vrf(&mut vrf);
        vrf.dump(Some("VRF With next-hops lazily resolved on addition"));
        vrf
    }

    // build a sample VRF used for testing
    pub fn build_test_vrf_nhops_partially_resolved() -> Vrf {
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
            let n1 = build_test_nhop(Some("10.0.0.1"), Some(1), 0, Some(Encapsulation::Mpls(8001)));
            let n2 = build_test_nhop(Some("10.0.0.5"), Some(2), 0, Some(Encapsulation::Mpls(8005)));
            let prefix = Prefix::expect_from(("8.0.0.1", 32));
            vrf.add_route(&prefix, route, &[n1, n2], None);
        }

        {
            let route: Route = build_test_route(RouteOrigin::Ospf, 0, 1);
            let n2 = build_test_nhop(Some("10.0.0.5"), Some(2), 0, Some(Encapsulation::Mpls(8005)));
            let n3 = build_test_nhop(Some("10.0.0.9"), Some(3), 0, Some(Encapsulation::Mpls(8009)));
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

        vrf.dump(Some("VRF with partially resolved nexthops, lazily resolved on addition"));
        vrf
    }

}

#[cfg(test)]
mod vrf_properties {
    use super::*;
    use crate::fib::fibtype::{FibKey, FibWriter};
    use crate::rib::nexthop::NhopKey;
    use bolero::{Driver, ValueGenerator};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const NUM_PREFIXES: u8 = 8;
    const NUM_NHOPS: u8 = 3;
    const MAX_CHANGES: u8 = 10;
    const MAX_NHOPS_PER_ROUTE: u8 = 3;

    const ROOT_V4: usize = 0;
    const ROOT_V6: usize = 5;

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

    fn nhops() -> Vec<RouteNhop> {
        vec![
            tests::build_test_nhop(Some("10.0.0.1"), Some(1), 0, None),
            tests::build_test_nhop(Some("10.0.0.2"), None, 0, None),
            tests::build_test_nhop(None, Some(3), 0, None),
        ]
    }

    #[derive(Debug, Clone)]
    enum Change {
        AddRoute {
            prefix: usize,
            nhops: Vec<usize>,
        },
        DelRoute {
            prefix: usize,
        },
        SetStale {
            value: bool,
        },
        RemoveStale,
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct ChangeSequences;

    fn index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        driver
            .gen_u8(Included(&0), Included(&(count - 1)))
            .map(usize::from)
    }

    impl ValueGenerator for ChangeSequences {
        type Output = Vec<Change>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Vec<Change>> {
            let len = driver.gen_u8(Included(&0), Included(&MAX_CHANGES))?;
            let mut out = Vec::with_capacity(usize::from(len));
            for _ in 0..len {
                let change = match driver.gen_u8(Included(&0), Included(&3))? {
                    0 => {
                        let prefix = index(driver, NUM_PREFIXES)?;
                        let count = driver.gen_u8(Included(&0), Included(&MAX_NHOPS_PER_ROUTE))?;
                        let mut nhops = Vec::with_capacity(usize::from(count));
                        for _ in 0..count {
                            nhops.push(index(driver, NUM_NHOPS)?);
                        }
                        Change::AddRoute { prefix, nhops }
                    }
                    1 => Change::DelRoute {
                        prefix: index(driver, NUM_PREFIXES)?,
                    },
                    2 => Change::SetStale {
                        value: driver.produce::<bool>()?,
                    },
                    _ => Change::RemoveStale,
                };
                out.push(change);
            }
            Some(out)
        }
    }

    #[derive(Debug, Clone)]
    struct Model {
        routes: BTreeMap<usize, (Vec<NhopKey>, bool)>,
    }

    impl Model {
        fn preset() -> Vec<NhopKey> {
            vec![NhopKey::with_drop()]
        }

        fn new() -> Self {
            Self {
                routes: BTreeMap::from([
                    (ROOT_V4, (Self::preset(), false)),
                    (ROOT_V6, (Self::preset(), false)),
                ]),
            }
        }

        fn is_root(prefix: usize) -> bool {
            prefix == ROOT_V4 || prefix == ROOT_V6
        }

        fn referenced(&self) -> BTreeSet<NhopKey> {
            self.routes
                .values()
                .flat_map(|(nhops, _)| nhops.iter().cloned())
                .collect()
        }

        fn lpm(&self, addr: &IpAddr, pool: &[Prefix]) -> Option<usize> {
            self.routes
                .keys()
                .copied()
                .filter(|i| pool[*i].covers_addr(addr))
                .max_by_key(|i| pool[*i].length())
        }

        fn apply(&mut self, change: &Change, pool: &[RouteNhop]) {
            match change {
                Change::AddRoute { prefix, nhops } => {
                    let keys = if nhops.is_empty() {
                        Self::preset()
                    } else {
                        nhops.iter().map(|i| pool[*i].key.clone()).collect()
                    };
                    self.routes.insert(*prefix, (keys, false));
                }
                Change::DelRoute { prefix } => {
                    if Self::is_root(*prefix) {
                        self.routes.insert(*prefix, (Self::preset(), false));
                    } else {
                        self.routes.remove(prefix);
                    }
                }
                Change::SetStale { value } => {
                    for (prefix, (_, stale)) in &mut self.routes {
                        if !Self::is_root(*prefix) {
                            *stale = *value;
                        }
                    }
                }
                Change::RemoveStale => {
                    let stale: Vec<usize> = self
                        .routes
                        .iter()
                        .filter_map(|(prefix, (_, stale))| stale.then_some(*prefix))
                        .collect();
                    for prefix in stale {
                        self.apply(&Change::DelRoute { prefix }, pool);
                    }
                }
            }
        }
    }

    fn apply_to_vrf(vrf: &mut Vrf, rstore: &RmacStore, change: &Change, pool: &[RouteNhop]) {
        let prefixes = prefixes();
        match change {
            Change::AddRoute { prefix, nhops } => {
                let route = tests::build_test_route(RouteOrigin::Bgp, 20, 100);
                let nhops: Vec<RouteNhop> = nhops.iter().map(|i| pool[*i].clone()).collect();
                vrf.add_route_complete(&prefixes[*prefix], route, &nhops, None, rstore);
            }
            Change::DelRoute { prefix } => vrf.del_route(prefixes[*prefix], None, rstore),
            Change::SetStale { value } => vrf.set_stale(*value),
            Change::RemoveStale => vrf.remove_stale_routes(None, rstore),
        }
    }

    fn check(vrf: &Vrf, model: &Model, at: &str) {
        let prefixes = prefixes();
        let probes = probes();

        let held: BTreeSet<usize> = (0..prefixes.len())
            .filter(|i| vrf.get_route(prefixes[*i]).is_some())
            .collect();
        let want: BTreeSet<usize> = model.routes.keys().copied().collect();
        assert_eq!(held, want, "route set {at}");
        assert_eq!(
            vrf.len_v4() + vrf.len_v6(),
            model.routes.len(),
            "route count {at}"
        );

        for (prefix, (nhops, stale)) in &model.routes {
            let route = vrf
                .get_route(prefixes[*prefix])
                .unwrap_or_else(|| panic!("no route for {prefix} {at}"));
            let got: Vec<NhopKey> = route.s_nhops.iter().map(|s| s.rc.key.clone()).collect();
            assert_eq!(got, *nhops, "next-hops of {prefix} {at}");
            assert_eq!(route.is_stale(), *stale, "stale flag of {prefix} {at}");
        }

        let stored: BTreeSet<NhopKey> = vrf.nhstore.iter().map(|rc| rc.key.clone()).collect();
        assert_eq!(stored, model.referenced(), "next-hop store {at}");

        for probe in &probes {
            let want = model
                .lpm(probe, &prefixes)
                .unwrap_or_else(|| panic!("model has no route for {probe} {at}"));
            let (hit, _) = vrf.lpm(*probe);
            assert_eq!(hit, prefixes[want], "lpm for {probe} {at}");
        }

        let fibw = vrf.fibw.as_ref().unwrap_or_else(|| unreachable!());
        let fib = fibw.enter().unwrap_or_else(|| unreachable!());
        let mut want_v4 = BTreeSet::new();
        let mut want_v6 = BTreeSet::new();
        for prefix in model.routes.keys() {
            match prefixes[*prefix] {
                Prefix::IPV4(p) => want_v4.insert(p),
                Prefix::IPV6(p) => want_v6.insert(p),
            };
        }
        let fib_v4: BTreeSet<Ipv4Prefix> = fib.iter_v4().map(|(prefix, _)| prefix).collect();
        let fib_v6: BTreeSet<Ipv6Prefix> = fib.iter_v6().map(|(prefix, _)| prefix).collect();
        assert_eq!(fib_v4, want_v4, "fib ipv4 prefixes {at}");
        assert_eq!(fib_v6, want_v6, "fib ipv6 prefixes {at}");
    }

    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(prefixes().len(), usize::from(NUM_PREFIXES));
        assert_eq!(nhops().len(), usize::from(NUM_NHOPS));
        assert_eq!(prefixes()[ROOT_V4], Prefix::root_v4());
        assert_eq!(prefixes()[ROOT_V6], Prefix::root_v6());
    }

    #[test]
    fn a_vrfs_routes_and_next_hops_stay_in_step() {
        let pool = nhops();
        let rstore = RmacStore::new();

        bolero::check!()
            .with_generator(ChangeSequences)
            .cloned()
            .for_each(|changes: Vec<Change>| {
                let config = RouterVrfConfig::new(1, "test");
                let mut vrf = Vrf::new(&config);
                let (fibw, _fibr) = FibWriter::new(FibKey::from_vrfid(1));
                vrf.set_fibw(fibw);
                let mut model = Model::new();

                check(&vrf, &model, "on a fresh vrf");
                for (step, change) in changes.iter().enumerate() {
                    apply_to_vrf(&mut vrf, &rstore, change, &pool);
                    model.apply(change, &pool);
                    check(&vrf, &model, &format!("at step {step} of {changes:?}"));
                }
            });
    }
}
