// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Routing database keeps most of the routing information in memory

#![allow(clippy::collapsible_if)]

use crate::adjacency::AdjacencyTable;
use crate::errors::RouterError;
use crate::fib::fibtable::FibTableWriter;
use crate::fib::fibtype::FibId;
use crate::interfaces::iftable::IfTable;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::rmac::{RmacStore, Vtep};
use crate::vrf::{Vrf, VrfId};
use net::vxlan::Vni;
use std::collections::HashMap;
use std::collections::hash_map;
use std::sync::Arc;
use std::sync::RwLock;
use tracing::{debug, error};

pub struct VrfTable {
    by_id: HashMap<VrfId, Arc<RwLock<Vrf>>>, /* Fixme: replace by RC */
    by_vni: HashMap<Vni, Arc<RwLock<Vrf>>>,  /* Fixme: replace by RC */
    fibtable: Option<FibTableWriter>,
}

#[allow(dead_code)]
#[allow(clippy::new_without_default)]
#[allow(clippy::len_without_is_empty)]
/// Table of VRFs. All VRFs in the system are represented here.
/// Every VRF is uniquely identified by a vrfId, which acts as the master key.
/// Vrfs that have a VNI associated can also be looked up by VNI.
impl VrfTable {
    pub fn new(fibtable: Option<FibTableWriter>) -> Self {
        Self {
            by_id: HashMap::new(),
            by_vni: HashMap::new(),
            fibtable,
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Create a new VRF with some name and Id, and optional Vni.
    //////////////////////////////////////////////////////////////////
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn add_vrf(
        &mut self,
        name: &str,
        vrfid: VrfId,
        vni: Option<u32>,
    ) -> Result<Arc<RwLock<Vrf>>, RouterError> {
        /* Check Vni if provided */
        let vni_checked = if let Some(vni) = vni {
            Some(Vni::new_checked(vni).map_err(|_| RouterError::VniInvalid(vni))?)
        } else {
            None
        };

        /* Forbid VRF addition if one exists with same vni */
        #[allow(clippy::collapsible_if)]
        if let Some(vni) = vni_checked {
            if self.by_vni.contains_key(&vni) {
                return Err(RouterError::VniInUse(vni.as_u32()));
            }
        }

        /* Forbid VRF addition if one exists with same id */
        if self.by_id.contains_key(&vrfid) {
            return Err(RouterError::VrfExists(vrfid));
        }

        /* Build VRF */
        let mut vrf = Vrf::new(name, vrfid, None);

        /* set vni if there */
        if let Some(vni) = vni_checked {
            vrf.set_vni(vni);
        }

        /* create fib if we have a fibtablewriter */
        if let Some(fibtw) = self.fibtable.as_mut() {
            let (fibw, _) = fibtw.add_fib(FibId::Id(vrf.vrfid), vrf.vni);
            vrf.set_fibw(fibw);
        }

        // FIXME: replace ARC by RC
        let vrf = Arc::new(RwLock::new(vrf));
        self.by_id.entry(vrfid).or_insert(vrf.clone());
        if let Some(vni) = vni_checked {
            self.by_vni.entry(vni).insert_entry(vrf.clone());
        }

        Ok(vrf)
    }

    ///////////////////////////////////////////////////////////////////////////////////
    /// Remove the vni from a VRF. This clears the vni field in a VRF if found and
    /// removes it from the by_vni map.
    ///////////////////////////////////////////////////////////////////////////////////
    pub fn vrf_remove_vni(&mut self, vrfid: VrfId) -> Result<(), RouterError> {
        let mut old_vni: Option<Vni> = None;
        if let Ok(arc_vrf) = self.get_vrf(vrfid) {
            if let Ok(ref mut vrf) = arc_vrf.write() {
                if vrf.vni.is_some() {
                    old_vni = vrf.vni.take();
                }
            } else {
                error!("Hit poisoned RWlock!");
                arc_vrf.clear_poison();
                return Err(RouterError::Internal);
            }
        } else {
            return Err(RouterError::NoSuchVrf);
        }
        if let Some(old_vni) = old_vni {
            self.by_vni.remove(&old_vni);
        }
        debug!("Vrf with Id {vrfid} no longer has a VNI associated");
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// set the vni for a certain VRF that is already in the vrf table
    //////////////////////////////////////////////////////////////////
    pub fn set_vni(&mut self, vrfid: VrfId, vni: Vni) -> Result<(), RouterError> {
        if let Ok(arc_vrf) = self.get_vrf_by_vni(vni.as_u32()) {
            if let Ok(vrf) = arc_vrf.read() {
                if vrf.vrfid != vrfid {
                    // another vrf has that vni
                    return Err(RouterError::VniInUse(vni.as_u32()));
                }
                // we're done, vrf has the vni requested already
                return Ok(());
            }
        }
        /* No vrf has the requested vni, including the vrf with id vrfId.
           However the vrf w/ id VrfId may have another vni associated.
        */
        self.vrf_remove_vni(vrfid)?;

        /* set the vni to the VRF */
        if let Ok(ref mut arc_vrf) = self.get_vrf(vrfid) {
            if let Ok(mut vrf) = arc_vrf.write() {
                assert!(vrf.vni.is_none());
                vrf.set_vni(vni);
            } else {
                error!("Hit poisoned RWlock!");
                arc_vrf.clear_poison();
            }
            self.by_vni.insert(vni, arc_vrf.clone());
        }
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// Remove the vrf with the given id
    //////////////////////////////////////////////////////////////////
    pub fn remove_vrf(&mut self, vrfid: VrfId, iftable: &IfTable) -> Result<(), RouterError> {
        if let Some(vrf) = self.by_id.remove(&vrfid) {
            if let Some(fibtablew) = &mut self.fibtable {
                if let Ok(vrf) = vrf.read() {
                    if vrf.fibw.is_some() {
                        fibtablew.del_fib(&FibId::Id(vrfid), vrf.vni);
                    }
                }
            }
            if let Ok(vrf) = vrf.read() {
                iftable.detach_vrf_interfaces(&vrf);
                if let Some(vni) = vrf.vni {
                    self.by_vni.remove(&vni);
                }
            }
            Ok(())
        } else {
            Err(RouterError::NoSuchVrf)
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Access a VRF, for read or write, from its id.
    /// Calling `read()` or `write()` on the resulting Ok value acquires a
    /// read / write lock respectively
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf(&self, vrfid: VrfId) -> Result<&Arc<RwLock<Vrf>>, RouterError> {
        if let Some(vrf) = self.by_id.get(&vrfid) {
            Ok(vrf)
        } else {
            Err(RouterError::NoSuchVrf)
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Access a VRF, for read or write, from its vni.
    /// Calling read() or write() on the resulting Ok value acquire a
    /// read / write lock respectively
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf_by_vni(&self, vni: u32) -> Result<&Arc<RwLock<Vrf>>, RouterError> {
        let vni = Vni::new_checked(vni).map_err(|_| RouterError::VniInvalid(vni))?;
        if let Some(vrf) = self.by_vni.get(&vni) {
            Ok(vrf)
        } else {
            Err(RouterError::NoSuchVrf)
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Iterate over all VRFs
    //////////////////////////////////////////////////////////////////
    pub fn values(&self) -> hash_map::Values<'_, VrfId, Arc<RwLock<Vrf>>> {
        self.by_id.values()
    }

    //////////////////////////////////////////////////////////////////
    /// Get the number of VRFs in the vrf table
    //////////////////////////////////////////////////////////////////
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    //////////////////////////////////////////////////////////////////
    /// Get the number of VRFs that have a Vxlan associated to them
    //////////////////////////////////////////////////////////////////
    pub fn len_with_vni(&self) -> usize {
        self.by_vni.len()
    }
}

/// Routing database
pub struct RoutingDb {
    pub vrftable: RwLock<VrfTable>,
    pub rmac_store: RwLock<RmacStore>,
    pub vtep: RwLock<Vtep>,
    pub atable: RwLock<AdjacencyTable>,
    pub iftw: IfTableWriter,
}
#[allow(unused)]
#[allow(clippy::new_without_default)]
impl RoutingDb {
    #[allow(dead_code)]
    pub fn new(fibtable: Option<FibTableWriter>, iftw: IfTableWriter) -> Self {
        let mut db = Self {
            vrftable: RwLock::new(VrfTable::new(fibtable)),
            rmac_store: RwLock::new(RmacStore::new()),
            vtep: RwLock::new(Vtep::new()),
            atable: RwLock::new(AdjacencyTable::new()),
            iftw,
        };
        /* create default vrf */
        if let Ok(mut vrftable) = db.vrftable.write() {
            vrftable.add_vrf("default", 0, None);
        }
        db
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::adjacency::tests::build_test_atable;
    use crate::fib::fibtype::FibId;
    use crate::interfaces::tests::build_test_iftable;

    use crate::rmac::tests::{build_sample_rmac_store, build_sample_vtep};
    use crate::route_processor::FibGroup;
    use crate::testfib::TestFib;
    use crate::vrf::tests::build_test_vrf_nhops_partially_resolved;
    use crate::vrf::tests::{build_test_vrf, mk_addr};

    #[test]
    fn vrf_table() {
        let (fibtw, _fibtr) = FibTableWriter::new();
        let mut vrftable = VrfTable::new(Some(fibtw));
        let iftable = build_test_iftable();

        /* add VRFs */
        let vrf0 = vrftable.add_vrf("default", 0, None).unwrap();
        let vrf1 = vrftable.add_vrf("VPC-1", 1, Some(3000)).unwrap();
        let _vrf2 = vrftable.add_vrf("VPC-2", 2, Some(4000)).unwrap();
        vrftable.add_vrf("VPC-3", 3, Some(5000)).unwrap();

        /* attempt to add VRF with used id */
        assert!(
            vrftable
                .add_vrf("duped-id", 1, None)
                .is_err_and(|e| e == RouterError::VrfExists(1)),
            "Vrf id 1 is already used"
        );

        /* add VRF with unused id but used vni */
        assert!(
            vrftable
                .add_vrf("duped-vni", 999, Some(3000))
                .is_err_and(|e| e == RouterError::VniInUse(3000)),
            "Should err because 3000 is already in use"
        );

        /* get VRF (by vrfid) */
        let vrf3 = vrftable.get_vrf(3).expect("Should be there");
        assert_eq!(vrf3.read().unwrap().name, "VPC-3");

        /* get VRF (by vni) */
        let vrf3_2 = vrftable.get_vrf_by_vni(5000).expect("Should be there");
        assert_eq!(vrf3_2.read().unwrap().name, "VPC-3");

        /* get interfaces from iftable and attach them */
        {
            let mut eth0 = iftable
                .get_interface(2)
                .expect("Should be there")
                .borrow_mut();
            eth0.attach(&vrf0.read().unwrap()).expect("Should succeed");
            assert!(eth0.is_attached_to_fib(&FibId::Id(0)));

            let mut eth1 = iftable
                .get_interface(3)
                .expect("Should be there")
                .borrow_mut();
            eth1.attach(&vrf0.read().unwrap()).expect("Should succeed");
            assert!(eth1.is_attached_to_fib(&FibId::Id(0)));

            let mut vlan100 = iftable
                .get_interface(4)
                .expect("Should be there")
                .borrow_mut();
            vlan100
                .attach(&vrf1.read().unwrap())
                .expect("Should succeed");
            assert!(vlan100.is_attached_to_fib(&FibId::Id(1)));

            let mut vlan200 = iftable
                .get_interface(5)
                .expect("Should be there")
                .borrow_mut();
            vlan200
                .attach(&vrf1.read().unwrap())
                .expect("Should succeed");
            assert!(vlan200.is_attached_to_fib(&FibId::Id(1)));
        }

        /* remove VRFs 0 - interfaces should be automatically detached */
        {
            let _ = vrftable.remove_vrf(0, &iftable);
            assert!(
                vrftable
                    .get_vrf(0)
                    .is_err_and(|e| e == RouterError::NoSuchVrf)
            );

            let eth0 = iftable
                .get_interface(2)
                .expect("Should be there")
                .borrow_mut();

            assert!(!eth0.is_attached_to_fib(&FibId::Id(0)));

            let eth1 = iftable
                .get_interface(3)
                .expect("Should be there")
                .borrow_mut();

            assert!(!eth1.is_attached_to_fib(&FibId::Id(0)));
        }

        /* remove VRFs 1 - interfaces should be automatically detached */
        let _ = vrftable.remove_vrf(1, &iftable);
        assert!(
            vrftable
                .get_vrf(1)
                .is_err_and(|e| e == RouterError::NoSuchVrf)
        );
        let vlan100 = iftable
            .get_interface(4)
            .expect("Should be there")
            .borrow_mut();

        assert!(!vlan100.is_attached_to_fib(&FibId::Id(1)));

        let vlan200 = iftable
            .get_interface(5)
            .expect("Should be there")
            .borrow_mut();

        assert!(!vlan200.is_attached_to_fib(&FibId::Id(1)));

        /* Should be gone from by_vni map */
        assert!(
            vrftable
                .get_vrf_by_vni(3000)
                .is_err_and(|e| e == RouterError::NoSuchVrf),
        );
    }

    #[test]
    fn test_vrf_fibgroup() {
        let vrf = build_test_vrf();
        let rmac_store = build_sample_rmac_store();
        let vtep = build_sample_vtep();
        let _iftable = build_test_iftable();
        let _atable = build_test_atable();

        {
            // do lpm just to get access to a next-hop object
            let (_prefix, route) = vrf.lpm(&mk_addr("192.168.0.1"));
            let nhop = &route.s_nhops[0].rc;
            println!("{}", nhop);

            // build fib entry for next-hop
            let mut fibgroup = nhop.as_fib_entry_group();
            println!("{}", fibgroup);

            fibgroup.resolve(&rmac_store, &vtep);
            println!("{}", fibgroup);
        }

        {
            // do lpm just to get access several next-hop objects
            let (_prefix, route) = vrf.lpm(&mk_addr("8.0.0.1"));

            // we have to collect all fib entries
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                fibgroup.append(&mut nhop.rc.as_fib_entry_group());
            }

            fibgroup.resolve(&rmac_store, &vtep);
            println!("{}", fibgroup);
        }

        {
            // do lpm just to get access several next-hop objects
            let (_prefix, route) = vrf.lpm(&mk_addr("7.0.0.1"));

            // we have to collect all fib entries
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                fibgroup.append(&mut nhop.rc.as_fib_entry_group());
            }

            fibgroup.resolve(&rmac_store, &vtep);
            println!("{}", fibgroup);
        }
    }

    fn do_test_vrf_fibgroup_lazy(vrf: Vrf) {
        let rmac_store = build_sample_rmac_store();
        let vtep = build_sample_vtep();
        let _iftable = build_test_iftable();
        let _atable = build_test_atable();

        // resolve beforehand, offline, and once
        vrf.nhstore.resolve_nhop_instructions(&rmac_store, &vtep);

        // create FIB
        let mut fib = TestFib::new();

        {
            let (_prefix, route) = vrf.lpm(&mk_addr("192.168.0.1"));

            // build the fib groups for all next-hops (only one here)
            // and merge them together in the same fib group
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                println!("next-hop is:\n {}", nhop);
                fibgroup.extend(&nhop.rc.as_fib_entry_group_lazy());
            }
            println!("Fib group is:\n {}", fibgroup);

            {
                let _r1 = fib.add_group(fibgroup.clone());
                let _r2 = fib.add_group(fibgroup.clone());
                let _r3 = fib.add_group(fibgroup.clone());
                let r4 = fib.add_group(fibgroup);
                assert_eq!(Arc::strong_count(&r4), 5);
            }
            assert_eq!(fib.len(), 1);
        }

        {
            let (_prefix, route) = vrf.lpm(&mk_addr("192.168.1.1"));

            // build the fib groups for all next-hops (only one here)
            // and merge them together in the same fib group
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                println!("next-hop is:\n {}", nhop);
                fibgroup.append(&mut nhop.rc.as_fib_entry_group_lazy());
            }
            println!("Fib group is:\n {}", fibgroup);

            let r1 = fib.add_group(fibgroup.clone());
            assert_eq!(Arc::strong_count(&r1), 2);

            println!("{}", fib);

            assert_eq!(fib.len(), 2);
            fib.purge();
            assert_eq!(fib.len(), 1);
            println!("{}", fib);
        }

        {
            // do lpm just to get access several next-hop objects
            let (_prefix, route) = vrf.lpm(&mk_addr("7.0.0.1"));

            // we have to collect all fib entries
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                fibgroup.append(&mut nhop.rc.as_fib_entry_group_lazy());
            }
        }
        fib.purge();
        println!("{}", fib);
        for nhop in vrf.nhstore.iter() {
            let fibgroup = nhop.as_fib_entry_group_lazy();
            let _ = fib.add_group(fibgroup.clone());
        }
        println!("{}", fib);
        //println!("{}", vrf.nhstore);
    }

    #[test]
    fn test_vrf_fibgroup_lazy_1() {
        do_test_vrf_fibgroup_lazy(build_test_vrf());
    }

    #[test]
    fn test_vrf_fibgroup_lazy_2_nhops_partially_resolved() {
        do_test_vrf_fibgroup_lazy(build_test_vrf_nhops_partially_resolved());
    }
}
