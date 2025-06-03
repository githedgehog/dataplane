// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Vrf table module that stores multiple vrfs. Every vrf is uniquely identified by a vrfid
//! and optionally identified by a Vni. A vrf table always has a default vrf.

#![allow(clippy::collapsible_if)]

use super::vrf::{Vrf, VrfId};
use crate::errors::RouterError;
use crate::fib::fibtable::FibTableWriter;
use crate::fib::fibtype::FibId;
use crate::interfaces::iftable::IfTable;
use net::vxlan::Vni;
use std::collections::HashMap;

#[allow(unused)]
use tracing::{debug, error};

pub struct VrfTable {
    by_id: HashMap<VrfId, Vrf>,
    by_vni: HashMap<Vni, VrfId>,
    fibtable: Option<FibTableWriter>,
}

#[allow(clippy::new_without_default)]
#[allow(clippy::len_without_is_empty)]
impl VrfTable {
    //////////////////////////////////////////////////////////////////
    /// Create a [`VrfTable`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(fibtable: Option<FibTableWriter>) -> Self {
        let mut vrftable = Self {
            by_id: HashMap::new(),
            by_vni: HashMap::new(),
            fibtable,
        };
        /* create default vrf: this can't fail */
        let _ = vrftable.add_vrf("default", 0, None);
        vrftable
    }

    //////////////////////////////////////////////////////////////////
    /// Create a new [`Vrf`] with some name and Id, and optional Vni.
    //////////////////////////////////////////////////////////////////
    pub fn add_vrf(
        &mut self,
        name: &str,
        vrfid: VrfId,
        vni: Option<u32>,
    ) -> Result<(), RouterError> {
        /* Check Vni if provided */
        let vni_checked = if let Some(vni) = vni {
            Some(Vni::new_checked(vni).map_err(|_| RouterError::VniInvalid(vni))?)
        } else {
            None
        };

        /* Forbid VRF addition if one exists with same id */
        if self.by_id.contains_key(&vrfid) {
            error!("Failed to add VRF with id {vrfid}: a VRF with that id already exists");
            return Err(RouterError::VrfExists(vrfid));
        }

        /* Build new VRF object */
        let mut vrf = Vrf::new(name, vrfid, None);

        /* Forbid addition of a vrf if one exists with same vni */
        if let Some(vni) = vni_checked {
            if self.by_vni.contains_key(&vni) {
                error!("Failed to add VRF with Vni {vni}: Vni is already in use");
                return Err(RouterError::VniInUse(vni.as_u32()));
            }
            /* set vni */
            vrf.set_vni(vni);
        }

        /* create fib if we have a fibtablewriter */
        if let Some(fibtw) = self.fibtable.as_mut() {
            let (fibw, _) = fibtw.add_fib(FibId::Id(vrf.vrfid), vrf.vni);
            vrf.set_fibw(fibw);
        }

        /* store */
        self.by_id.entry(vrfid).or_insert(vrf);
        if let Some(vni) = vni_checked {
            self.by_vni.entry(vni).insert_entry(vrfid);
        }
        debug!("Successfully added VRF {name}, id {vrfid}");
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////////////
    /// Remove the vni from a VRF. This clears the vni field in a VRF if found and
    /// removes it from the `by_vni` map.
    ///////////////////////////////////////////////////////////////////////////////////
    pub fn vrf_remove_vni(&mut self, vrfid: VrfId) -> Result<(), RouterError> {
        debug!("Removing vni from vrf {vrfid}...");
        let vrf = self.get_vrf_mut(vrfid)?;
        if let Some(old_vni) = vrf.vni {
            vrf.vni.take();
            self.by_vni.remove(&old_vni);
        }
        debug!("Vrf with Id {vrfid} no longer has a VNI associated");
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// set the vni for a certain VRF that is already in the vrf table
    //////////////////////////////////////////////////////////////////
    pub fn set_vni(&mut self, vrfid: VrfId, vni: Vni) -> Result<(), RouterError> {
        if let Ok(vrf) = self.get_vrf_by_vni(vni.as_u32()) {
            if vrf.vrfid != vrfid {
                return Err(RouterError::VniInUse(vni.as_u32()));
            }
            return Ok(()); /* vrf already has that vni */
        }
        // No vrf has the requested vni, including the vrf with id vrfId.
        // However the vrf with id VrfId may have another vni associated,

        /* remove vni from vrf  */
        self.vrf_remove_vni(vrfid)?;

        /* set the vni to the vrf */
        let vrf = self.get_vrf_mut(vrfid)?;
        vrf.set_vni(vni);

        /* register vni */
        self.by_vni.insert(vni, vrfid);

        /* register fib */
        if let Some(fibtw) = &mut self.fibtable {
            fibtw.register_fib_by_vni(FibId::from_vrfid(vrfid), vni);
        }
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// Remove the vrf with the given id
    //////////////////////////////////////////////////////////////////
    pub fn remove_vrf(&mut self, vrfid: VrfId, iftable: &mut IfTable) -> Result<(), RouterError> {
        debug!("Removing VRF with vrfid {vrfid}...");
        if let Some(vrf) = self.by_id.remove(&vrfid) {
            if let Some(fibtablew) = &mut self.fibtable {
                if vrf.fibw.is_some() {
                    let fib_id = FibId::Id(vrfid);
                    debug!("Deleting fib with id {fib_id}...");
                    fibtablew.del_fib(&fib_id, vrf.vni);
                }
            }
            iftable.detach_vrf_interfaces(&vrf);
            if let Some(vni) = vrf.vni {
                debug!("Unregistering vni {vni}");
                self.by_vni.remove(&vni);
            }
            Ok(())
        } else {
            error!("No vrf with id {vrfid} exists");
            Err(RouterError::NoSuchVrf)
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Access a VRF, for read or write, from its id.
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf(&self, vrfid: VrfId) -> Result<&Vrf, RouterError> {
        self.by_id.get(&vrfid).ok_or(RouterError::NoSuchVrf)
    }

    pub fn get_vrf_mut(&mut self, vrfid: VrfId) -> Result<&mut Vrf, RouterError> {
        self.by_id.get_mut(&vrfid).ok_or(RouterError::NoSuchVrf)
    }

    //////////////////////////////////////////////////////////////////
    /// Access a VRF from its vni.
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf_by_vni(&self, vni: u32) -> Result<&Vrf, RouterError> {
        let vni = Vni::new_checked(vni).map_err(|_| RouterError::VniInvalid(vni))?;
        let vrfid = self.by_vni.get(&vni).ok_or(RouterError::NoSuchVrf)?;
        self.get_vrf(*vrfid)
    }

    //////////////////////////////////////////////////////////////////
    /// Get a mutable reference to a Vrf and an immutable one to the default VRF
    //////////////////////////////////////////////////////////////////
    pub fn get_with_default_mut(&mut self, vrfid: VrfId) -> Result<(&mut Vrf, &Vrf), RouterError> {
        if vrfid == 0 {
            return Err(RouterError::Internal("Bug: misuse of vrf lookup"));
        }
        match self.by_id.get_disjoint_mut([&vrfid, &0]) {
            [Some(vrf), Some(vrf0)] => Ok((vrf, vrf0)),
            [None, Some(_vrf0)] => {
                error!("Unable to find vrf with id {vrfid}");
                Err(RouterError::NoSuchVrf)
            }
            [Some(_vrf), None] => {
                error!("Unable to find default vrf!");
                Err(RouterError::NoSuchVrf)
            }
            [None, None] => {
                error!("Unable to find default vrf nor vrf with id {vrfid}!");
                Err(RouterError::NoSuchVrf)
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Iterate over all VRFs
    //////////////////////////////////////////////////////////////////
    pub fn values(&self) -> impl Iterator<Item = &Vrf> {
        self.by_id.values()
    }

    //////////////////////////////////////////////////////////////////
    /// Get the number of VRFs in the vrf table
    //////////////////////////////////////////////////////////////////
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    //////////////////////////////////////////////////////////////////
    /// Get the number of VRFs that have a VNI associated to them
    //////////////////////////////////////////////////////////////////
    pub fn len_with_vni(&self) -> usize {
        self.by_vni.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evpn::rmac::tests::{build_sample_rmac_store, build_sample_vtep};
    use crate::fib::fibobjects::FibGroup;
    use crate::fib::fibtype::FibId;
    use crate::interfaces::tests::build_test_iftable;
    use crate::rib::vrf::tests::build_test_vrf_nhops_partially_resolved;
    use crate::rib::vrf::tests::{build_test_vrf, mk_addr};
    use crate::testfib::TestFib;
    use std::sync::Arc;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn vrf_table() {
        /* create fib table */
        let (fibtw, _fibtr) = FibTableWriter::new();

        /* create vrf table */
        let mut vrftable = VrfTable::new(Some(fibtw));

        /* create sample iftable */
        let mut iftable = build_test_iftable();

        /* add VRFs (default VRF is always there) */
        vrftable.add_vrf("VPC-1", 1, Some(3000)).unwrap();
        vrftable.add_vrf("VPC-2", 2, Some(4000)).unwrap();
        vrftable.add_vrf("VPC-3", 3, Some(5000)).unwrap();

        /* add VRF with already used id */
        assert!(
            vrftable
                .add_vrf("duped-id", 1, None)
                .is_err_and(|e| e == RouterError::VrfExists(1))
        );
        /* add VRF with unused id but used vni */
        assert!(
            vrftable
                .add_vrf("duped-vni", 999, Some(3000))
                .is_err_and(|e| e == RouterError::VniInUse(3000))
        );
        /* add VRF with invalid vni */
        assert!(
            vrftable
                .add_vrf("duped-vni", 999, Some(0))
                .is_err_and(|e| e == RouterError::VniInvalid(0))
        );

        /* get VRF by vrfid - success case */
        let vrf3 = vrftable.get_vrf(3).expect("Should be there");
        assert_eq!(vrf3.name, "VPC-3");

        /* get VRF by vrfid - non-existent vrf */
        let vrf = vrftable.get_vrf(13);
        assert!(vrf.is_err_and(|e| e == RouterError::NoSuchVrf));

        /* get VRF by vni - success */
        let vrf3 = vrftable.get_vrf_by_vni(5000).expect("Should be there");
        assert_eq!(vrf3.name, "VPC-3");

        /* get VRF by vni - bad vni */
        let vrf = vrftable.get_vrf_by_vni(16777216);
        assert!(vrf.is_err_and(|e| e == RouterError::VniInvalid(16777216)));

        /* get VRF by vni - bad vni */
        let vrf = vrftable.get_vrf_by_vni(1234);
        assert!(vrf.is_err_and(|e| e == RouterError::NoSuchVrf));

        /* check default vrf exists */
        let vrf0 = vrftable.get_vrf(0).expect("Default always exists");
        assert_eq!(vrf0.name, "default");
        assert_eq!(vrf0.vni, None);

        /* get interfaces from iftable and attach them */
        let eth0 = iftable.get_interface_mut(2).expect("Should be there");
        eth0.attach(&vrf0).expect("Should succeed");
        assert!(eth0.is_attached_to_fib(FibId::Id(0)));

        let eth1 = iftable.get_interface_mut(3).expect("Should be there");
        eth1.attach(&vrf0).expect("Should succeed");
        assert!(eth1.is_attached_to_fib(FibId::Id(0)));

        let vlan100 = iftable.get_interface_mut(4).expect("Should be there");
        let vrf1 = vrftable.get_vrf(1).expect("Should succeed");
        vlan100.attach(&vrf1).expect("Should succeed");
        assert!(vlan100.is_attached_to_fib(FibId::Id(1)));

        let vlan200 = iftable.get_interface_mut(5).expect("Should be there");
        vlan200.attach(&vrf1).expect("Should succeed");
        assert!(vlan200.is_attached_to_fib(FibId::Id(1)));
        println!("{iftable}");

        /* remove non-existent vrf */
        let vrf = vrftable.remove_vrf(987, &mut iftable);
        assert!(vrf.is_err_and(|e| e == RouterError::NoSuchVrf));

        /* remove VRFs 0 - interfaces should be automatically detached */
        let _ = vrftable.remove_vrf(0, &mut iftable);
        assert!(
            vrftable
                .get_vrf(0)
                .is_err_and(|e| e == RouterError::NoSuchVrf)
        );
        let eth0 = iftable.get_interface(2).expect("Should be there");
        assert!(!eth0.is_attached_to_fib(FibId::Id(0)));
        let eth1 = iftable.get_interface(3).expect("Should be there");
        assert!(!eth1.is_attached_to_fib(FibId::Id(0)));

        /* remove VRFs 1 - interfaces should be automatically detached */
        vrftable
            .remove_vrf(1, &mut iftable)
            .expect("Should succeed");
        assert!(
            vrftable
                .get_vrf(1)
                .is_err_and(|e| e == RouterError::NoSuchVrf)
        );
        let vlan100 = iftable.get_interface(4).expect("Should be there");
        assert!(!vlan100.is_attached_to_fib(FibId::Id(1)));
        let vlan200 = iftable.get_interface(5).expect("Should be there");
        assert!(!vlan200.is_attached_to_fib(FibId::Id(1)));

        /* Should be gone from by_vni map */
        assert!(
            vrftable
                .get_vrf_by_vni(3000)
                .is_err_and(|e| e == RouterError::NoSuchVrf),
        );
        println!("{iftable}");
    }

    #[test]
    fn test_vrf_fibgroup() {
        let vrf = build_test_vrf();
        let rmac_store = build_sample_rmac_store();
        let vtep = build_sample_vtep();
        let _iftable = build_test_iftable();

        {
            // do lpm just to get access to a next-hop object
            let (_prefix, route) = vrf.lpm(&mk_addr("192.168.0.1"));
            let nhop = &route.s_nhops[0].rc;
            println!("{nhop}");

            // build fib entry for next-hop
            let mut fibgroup = nhop.as_fib_entry_group();
            println!("{fibgroup}");

            fibgroup.resolve(&rmac_store, &vtep);
            println!("{fibgroup}");
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
            println!("{fibgroup}");
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
            println!("{fibgroup}");
        }
    }

    fn do_test_vrf_fibgroup_lazy(vrf: Vrf) {
        let rmac_store = build_sample_rmac_store();
        let vtep = build_sample_vtep();
        let _iftable = build_test_iftable();

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
                println!("next-hop is:\n {nhop}");
                fibgroup.extend(&nhop.rc.as_fib_entry_group_lazy());
            }
            println!("Fib group is:\n {fibgroup}");

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
                println!("next-hop is:\n {nhop}");
                fibgroup.append(&mut nhop.rc.as_fib_entry_group_lazy());
            }
            println!("Fib group is:\n {fibgroup}");

            let r1 = fib.add_group(fibgroup.clone());
            assert_eq!(Arc::strong_count(&r1), 2);

            println!("{fib}");

            assert_eq!(fib.len(), 2);
            fib.purge();
            assert_eq!(fib.len(), 1);
            println!("{fib}");
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
        println!("{fib}");
        for nhop in vrf.nhstore.iter() {
            let fibgroup = nhop.as_fib_entry_group_lazy();
            let _ = fib.add_group(fibgroup.clone());
        }
        println!("{fib}");
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
