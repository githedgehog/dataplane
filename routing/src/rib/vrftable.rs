// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Vrf table module that stores multiple vrfs. Every vrf is uniquely identified by a vrfid
//! and optionally identified by a Vni. A vrf table always has a default vrf.

use super::vrf::{Vrf, VrfId, VrfStatus};
use crate::errors::RouterError;
use crate::fib::fibtable::FibTableWriter;
use crate::fib::fibtype::FibId;
use crate::interfaces::iftablerw::IfTableWriter;
use net::vxlan::Vni;
use std::collections::HashMap;

#[allow(unused)]
use tracing::{debug, error};

pub struct VrfTable {
    by_id: HashMap<VrfId, Vrf>,
    by_vni: HashMap<Vni, VrfId>,
    fibtablew: FibTableWriter,
}

#[allow(clippy::new_without_default)]
#[allow(clippy::len_without_is_empty)]
impl VrfTable {
    //////////////////////////////////////////////////////////////////
    /// Create a [`VrfTable`]
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(fibtablew: FibTableWriter) -> Self {
        let mut vrftable = Self {
            by_id: HashMap::new(),
            by_vni: HashMap::new(),
            fibtablew,
        };
        /* create default vrf: this can't fail */
        let _ = vrftable.add_vrf("default", 0, None);
        vrftable
    }

    //////////////////////////////////////////////////////////////////////////
    /// Create a new [`Vrf`] with some name, [`VrfId`], and optional [`Vni`].
    //////////////////////////////////////////////////////////////////////////
    pub fn add_vrf(
        &mut self,
        name: &str,
        vrfid: VrfId,
        vni: Option<Vni>,
    ) -> Result<(), RouterError> {
        /* Forbid VRF addition if one exists with same id */
        if self.by_id.contains_key(&vrfid) {
            error!("Can't add VRF with id {vrfid}: a VRF with that id already exists");
            return Err(RouterError::VrfExists(vrfid));
        }

        /* Build new VRF object */
        let mut vrf = Vrf::new(name, vrfid, None);

        /* Forbid addition of a vrf if one exists with same vni */
        if let Some(vni) = vni {
            if self.by_vni.contains_key(&vni) {
                error!("Can't add VRF (id {vrfid}) with Vni {vni}: Vni is already in use");
                return Err(RouterError::VniInUse(vni.as_u32()));
            }
            /* set vni */
            vrf.set_vni(vni);
        }

        /* create fib */
        let (fibw, _) = self.fibtablew.add_fib(FibId::Id(vrf.vrfid), vrf.vni);
        vrf.set_fibw(fibw);

        /* store */
        self.by_id.entry(vrfid).or_insert(vrf);
        if let Some(vni) = vni {
            self.by_vni.entry(vni).insert_entry(vrfid);
        }
        debug!("Successfully added VRF {name}, id {vrfid}");
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// set the vni for a certain VRF that is already in the vrf table
    //////////////////////////////////////////////////////////////////
    pub fn set_vni(&mut self, vrfid: VrfId, vni: Vni) -> Result<(), RouterError> {
        if let Ok(vrf) = self.get_vrf_by_vni(vni) {
            if vrf.vrfid != vrfid {
                return Err(RouterError::VniInUse(vni.as_u32()));
            }
            return Ok(()); /* vrf already has that vni */
        }
        // No vrf has the requested vni, including the vrf with id vrfId.
        // However the vrf with id VrfId may have another vni associated,

        /* remove vni from vrf if it has one */
        self.unset_vni(vrfid)?;

        /* set the vni to the vrf */
        let vrf = self.get_vrf_mut(vrfid)?;
        vrf.set_vni(vni);

        /* register vni */
        self.by_vni.insert(vni, vrfid);

        /* register fib */
        self.fibtablew
            .register_fib_by_vni(FibId::from_vrfid(vrfid), vni);
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////////////
    /// Remove the vni from a VRF. This clears the vni field in a VRF if found and
    /// removes it from the `by_vni` map. It also unindexes the vrf's FIB by the vni.
    ///////////////////////////////////////////////////////////////////////////////////
    pub fn unset_vni(&mut self, vrfid: VrfId) -> Result<(), RouterError> {
        let vrf = self.get_vrf_mut(vrfid)?;
        if let Some(vni) = vrf.vni {
            debug!("Removing vni {vni} from vrf {vrfid}...");
            vrf.vni.take();
            self.by_vni.remove(&vni);
            self.fibtablew.unregister_vni(vni);
            debug!("Vrf with Id {vrfid} no longer has a VNI associated");
        }
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// Remove the vrf with the given [`VrfId`]
    //////////////////////////////////////////////////////////////////
    pub fn remove_vrf(
        &mut self,
        vrfid: VrfId,
        iftablew: &mut IfTableWriter,
    ) -> Result<(), RouterError> {
        debug!("Removing VRF with vrfid {vrfid}...");
        let Some(vrf) = self.by_id.remove(&vrfid) else {
            error!("No vrf with id {vrfid} exists");
            return Err(RouterError::NoSuchVrf);
        };
        // delete the corresponding fib
        if vrf.fibw.is_some() {
            let fib_id = FibId::Id(vrfid);
            debug!("Deleting fib with id {fib_id}...");
            self.fibtablew.del_fib(&fib_id, vrf.vni);
            iftablew.detach_interfaces_from_vrf(fib_id);
        }

        // if the VRF had a vni assigned, unregister it
        if let Some(vni) = vrf.vni {
            debug!("Unregistering vni {vni}");
            self.by_vni.remove(&vni);
        }
        Ok(())
    }

    //////////////////////////////////////////////////////////////////
    /// Remove the vrf with the given [`VrfId`]
    //////////////////////////////////////////////////////////////////
    pub fn remove_deleted_vrfs(&mut self, iftablew: &mut IfTableWriter) {
        // collect the ids of the vrfs with status deleted
        let to_delete: Vec<VrfId> = self
            .by_id
            .values()
            .filter_map(|vrf| (vrf.status == VrfStatus::Deleted).then_some(vrf.vrfid))
            .collect();

        // delete them
        for vrfid in &to_delete {
            if let Err(e) = self.remove_vrf(*vrfid, iftablew) {
                error!("Failed to delete vrf with id {vrfid}: {e}");
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Immutably access a VRF from its id.
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf(&self, vrfid: VrfId) -> Result<&Vrf, RouterError> {
        self.by_id.get(&vrfid).ok_or(RouterError::NoSuchVrf)
    }

    //////////////////////////////////////////////////////////////////
    /// Mutably access a VRF from its id.
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf_mut(&mut self, vrfid: VrfId) -> Result<&mut Vrf, RouterError> {
        self.by_id.get_mut(&vrfid).ok_or(RouterError::NoSuchVrf)
    }

    //////////////////////////////////////////////////////////////////
    /// Access a VRF from its vni.
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf_by_vni(&self, vni: Vni) -> Result<&Vrf, RouterError> {
        let vrfid = self.by_vni.get(&vni).ok_or(RouterError::NoSuchVrf)?;
        self.get_vrf(*vrfid)
    }

    //////////////////////////////////////////////////////////////////
    /// Lookup the vrf id of the vrf that has a certain vni
    //////////////////////////////////////////////////////////////////
    pub fn get_vrfid_by_vni(&self, vni: Vni) -> Result<VrfId, RouterError> {
        self.by_vni.get(&vni).ok_or(RouterError::NoSuchVrf).copied()
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
    /// Iterate mutably over all VRFs
    //////////////////////////////////////////////////////////////////
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut Vrf> {
        self.by_id.values_mut()
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
    use crate::evpn::rmac::tests::build_sample_rmac_store;
    use crate::fib::fibobjects::FibGroup;
    use crate::fib::fibtype::FibId;
    use crate::interfaces::tests::build_test_iftable;
    use crate::interfaces::tests::build_test_iftable_left_right;
    use crate::rib::vrf::tests::build_test_vrf_nhops_partially_resolved;
    use crate::rib::vrf::tests::{build_test_vrf, mk_addr};
    use crate::testfib::TestFib;
    use std::sync::Arc;
    use tracing_test::traced_test;

    fn mk_vni(vni: u32) -> Vni {
        vni.try_into().expect("Bad vni")
    }

    #[traced_test]
    #[test]
    fn vrf_table() {
        /* create fib table */
        let (fibtw, _fibtr) = FibTableWriter::new();

        /* create iftable */
        let mut iftable = build_test_iftable();
        let (mut iftw, _iftr) = IfTableWriter::new();
        for interface in iftable.values() {
            iftw.add_interface(interface.clone());
        }

        /* create vrf table */
        let mut vrftable = VrfTable::new(fibtw);

        /* add VRFs (default VRF is always there) */
        vrftable.add_vrf("VPC-1", 1, Some(mk_vni(3000))).unwrap();
        vrftable.add_vrf("VPC-2", 2, Some(mk_vni(4000))).unwrap();
        vrftable.add_vrf("VPC-3", 3, Some(mk_vni(5000))).unwrap();

        /* add VRF with already used id */
        assert!(
            vrftable
                .add_vrf("duped-id", 1, None)
                .is_err_and(|e| e == RouterError::VrfExists(1))
        );
        /* add VRF with unused id but used vni */
        assert!(
            vrftable
                .add_vrf("duped-vni", 999, Some(mk_vni(3000)))
                .is_err_and(|e| e == RouterError::VniInUse(3000))
        );

        /* get VRF by vrfid - success case */
        let vrf3 = vrftable.get_vrf(3).expect("Should be there");
        assert_eq!(vrf3.name, "VPC-3");

        /* get VRF by vrfid - non-existent vrf */
        let vrf = vrftable.get_vrf(13);
        assert!(vrf.is_err_and(|e| e == RouterError::NoSuchVrf));

        /* get VRF by vni - success */
        let vrf3 = vrftable
            .get_vrf_by_vni(mk_vni(5000))
            .expect("Should be there");
        assert_eq!(vrf3.name, "VPC-3");

        /* get VRF by vni - nonexistent vrf */
        let vrf = vrftable.get_vrf_by_vni(mk_vni(1234));
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
        let vrf = vrftable.remove_vrf(987, &mut iftw);
        assert!(vrf.is_err_and(|e| e == RouterError::NoSuchVrf));

        /* remove VRFs 0 - interfaces should be automatically detached */
        let _ = vrftable.remove_vrf(0, &mut iftw);
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
        vrftable.remove_vrf(1, &mut iftw).expect("Should succeed");
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
                .get_vrf_by_vni(mk_vni(3000))
                .is_err_and(|e| e == RouterError::NoSuchVrf),
        );
        println!("{iftable}");
    }

    #[traced_test]
    #[test]
    fn vrf_table_vnis() {
        debug!("━━━━Test: Create vrf table");
        let (fibtw, fibtr) = FibTableWriter::new();
        let (_iftw, _iftr) = IfTableWriter::new();
        let mut vrftable = VrfTable::new(fibtw);

        let vrfid = 999;
        let vni = mk_vni(3000);

        debug!("━━━━Test: create VRF without VNI");
        vrftable
            .add_vrf("VPC-1", vrfid, None)
            .expect("Should be created");
        let vrf = vrftable.get_vrf(vrfid).expect("Should be there");
        assert_eq!(vrf.name, "VPC-1");
        assert_eq!(vrf.vni, None);

        debug!("━━━━Test: set vni {vni} to the vrf");
        vrftable.set_vni(vrfid, vni).expect("Should succeed");
        let vrf = vrftable.get_vrf(vrfid).expect("Should still be found");
        assert_eq!(vrf.vni, Some(vni));
        vrftable
            .get_vrf_by_vni(vni)
            .expect("Should be found by vni");
        let id = vrftable
            .get_vrfid_by_vni(vni)
            .expect("Should find vrfid by vni");
        assert_eq!(id, vrfid);
        debug!("\n{vrftable}");
        if let Some(fibtable) = fibtr.enter() {
            let fib = fibtable.get_fib(&FibId::from_vrfid(vrfid));
            assert!(fib.is_some());
            let fib = fibtable.get_fib(&FibId::from_vni(vni));
            assert!(fib.is_some());
        }

        debug!("━━━━Test: Unset vni {vni} from the vrf");
        vrftable.unset_vni(vrfid).expect("Should succeed");
        let vrf = vrftable.get_vrf_by_vni(vni);
        assert!((vrf.is_err_and(|e| e == RouterError::NoSuchVrf)));
        let vrf = vrftable.get_vrf(vrfid).expect("Should still be found");
        assert_eq!(vrf.vni, None);
        let id = vrftable.get_vrfid_by_vni(vni);
        assert!((id.is_err_and(|e| e == RouterError::NoSuchVrf)));
        debug!("\n{vrftable}");
        if let Some(fibtable) = fibtr.enter() {
            let fib = fibtable.get_fib(&FibId::from_vrfid(vrfid));
            assert!(fib.is_some());
            let fib = fibtable.get_fib(&FibId::from_vni(vni));
            assert!(fib.is_none());
        }
    }

    #[traced_test]
    #[test]
    fn vrf_table_deletions() {
        debug!("━━━━Test: Create vrf table");
        let (fibtw, fibtr) = FibTableWriter::new();
        let (mut iftw, iftr) = build_test_iftable_left_right();
        let mut vrftable = VrfTable::new(fibtw);

        let vrfid = 999;
        let vni = mk_vni(3000);

        debug!("━━━━Test: create VRF and associate VNI {vni}");
        vrftable
            .add_vrf("VPC-1", vrfid, None)
            .expect("Should be created");
        vrftable.set_vni(vrfid, vni).expect("Should succeed");
        assert_eq!(vrftable.len(), 2); // default is always there
        debug!("\n{vrftable}");

        debug!("━━━━Test: deleting removed VRFs: nothing should be removed");
        vrftable.remove_deleted_vrfs(&mut iftw);
        assert_eq!(vrftable.len(), 2); // default is always there

        debug!("━━━━Test: Get interface from iftable");
        if let Some(iftable) = iftr.enter() {
            let iface = iftable.get_interface(2).expect("Should be there");
            assert_eq!(iface.name, "eth0");
            debug!("\n{}", *iftable);
        }

        debug!("━━━━Test: Attach interface to vrf");
        iftw.attach_interface_to_vrf(2, vrfid, &vrftable)
            .expect("Should succeed");
        if let Some(iftable) = iftr.enter() {
            let iface = iftable.get_interface(2).expect("Should be there");
            assert!(iface.attachment.is_some());
            debug!("\n{}", *iftable);
        }

        debug!("━━━━Test: Get vrf and mark as deleted");
        let vrf = vrftable.get_vrf_mut(vrfid).expect("Should be there");
        vrf.set_status(VrfStatus::Deleted);
        debug!("\n{vrftable}");

        debug!("━━━━Test: remove vrfs marked as deleted again - VPC-1 vrf should be gone");
        vrftable.remove_deleted_vrfs(&mut iftw);
        assert_eq!(vrftable.len(), 1, "should be gone");

        // check fib table
        if let Some(fibtable) = fibtr.enter() {
            let fib = fibtable.get_fib(&FibId::from_vrfid(vrfid));
            assert!(fib.is_none());
            let fib = fibtable.get_fib(&FibId::from_vni(vni));
            assert!(fib.is_none());
            assert_eq!(fibtable.len(), 1);
        }
        if let Some(iftable) = iftr.enter() {
            let iface = iftable.get_interface(2).expect("Should be there");
            assert!(iface.attachment.is_none(), "Should have been detached");
        }

        debug!("\n{vrftable}");
    }

    #[test]
    fn test_vrf_fibgroup() {
        let vrf = build_test_vrf();
        let rmac_store = build_sample_rmac_store();
        let _iftable = build_test_iftable();

        {
            // do lpm just to get access to a next-hop object
            let (_prefix, route) = vrf.lpm(mk_addr("192.168.0.1"));
            let nhop = &route.s_nhops[0].rc;
            println!("{nhop}");

            // build fib entry for next-hop
            let mut fibgroup = nhop.as_fib_entry_group();
            println!("{fibgroup}");

            fibgroup.resolve(&rmac_store);
            println!("{fibgroup}");
        }

        {
            // do lpm just to get access several next-hop objects
            let (_prefix, route) = vrf.lpm(mk_addr("8.0.0.1"));

            // we have to collect all fib entries
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                fibgroup.extend(&mut nhop.rc.as_fib_entry_group());
            }

            fibgroup.resolve(&rmac_store);
            println!("{fibgroup}");
        }

        {
            // do lpm just to get access several next-hop objects
            let (_prefix, route) = vrf.lpm(mk_addr("7.0.0.1"));

            // we have to collect all fib entries
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                fibgroup.extend(&mut nhop.rc.as_fib_entry_group());
            }

            fibgroup.resolve(&rmac_store);
            println!("{fibgroup}");
        }
    }

    fn do_test_vrf_fibgroup_lazy(vrf: Vrf) {
        let rmac_store = build_sample_rmac_store();
        let _iftable = build_test_iftable();

        // resolve beforehand, offline, and once
        vrf.nhstore.resolve_nhop_instructions(&rmac_store);

        // create FIB
        let mut fib = TestFib::new();

        {
            let (_prefix, route) = vrf.lpm(mk_addr("192.168.0.1"));

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
            let (_prefix, route) = vrf.lpm(mk_addr("192.168.1.1"));

            // build the fib groups for all next-hops (only one here)
            // and merge them together in the same fib group
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                println!("next-hop is:\n {nhop}");
                fibgroup.extend(&mut nhop.rc.as_fib_entry_group_lazy());
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
            let (_prefix, route) = vrf.lpm(mk_addr("7.0.0.1"));

            // we have to collect all fib entries
            let mut fibgroup = FibGroup::new();
            for nhop in route.s_nhops.iter() {
                fibgroup.extend(&mut nhop.rc.as_fib_entry_group_lazy());
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
