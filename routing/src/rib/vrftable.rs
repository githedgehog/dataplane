// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Vrf table module that stores multiple vrfs. Every vrf is uniquely identified by a vrfid
//! and optionally identified by a Vni. A vrf table always has a default vrf.

#[cfg(test)]
use super::vrf::VrfStatus;
use super::vrf::{Vrf, VrfId};
use crate::fib::fibtable::FibTableWriter;
use crate::fib::fibtype::FibId;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::{errors::RouterError, rib::vrf::RouterVrfConfig};
use ahash::RandomState;
use net::vxlan::Vni;
use std::collections::HashMap;

#[allow(unused)]
use tracing::{debug, error};

pub struct VrfTable {
    by_id: HashMap<VrfId, Vrf, RandomState>,
    by_vni: HashMap<Vni, VrfId, RandomState>,
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
            by_id: HashMap::with_hasher(RandomState::with_seed(0)),
            by_vni: HashMap::with_hasher(RandomState::with_seed(0)),
            fibtablew,
        };
        /* create default vrf: this can't fail */
        let _ = vrftable.add_vrf(&RouterVrfConfig::new(0, "default"));
        vrftable
    }

    //////////////////////////////////////////////////////////////////////////
    /// Create a new [`Vrf`] with some name, [`VrfId`], and optional [`Vni`].
    //////////////////////////////////////////////////////////////////////////
    pub fn add_vrf(&mut self, config: &RouterVrfConfig) -> Result<(), RouterError> {
        let vrfid = config.vrfid;
        let name = &config.name;
        debug!("Creating new VRF name:{name} id: {vrfid}");

        /* Forbid VRF addition if one exists with same id */
        if self.by_id.contains_key(&vrfid) {
            error!("Can't add VRF with id {vrfid}: one with that id exists");
            return Err(RouterError::VrfExists(vrfid));
        }

        /* Build new VRF object */
        let mut vrf = Vrf::new(&config);

        /* Forbid addition of a vrf if one exists with same vni */
        if let Some(vni) = config.vni {
            if self.by_vni.contains_key(&vni) {
                error!("Can't add VRF (id {vrfid}) with Vni {vni}: Vni is in use");
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
        if let Some(vni) = config.vni {
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

    ///////////////////////////////////////////////////////////////////////////////////
    /// Check the correctness of a vni configuration for the vrf with the given [`VrfId`].
    /// This method returns an error if the indicated vrf does not exist, does not have
    /// a [`Vni`] configured or it does but the internal state is not the expected.
    ///////////////////////////////////////////////////////////////////////////////////
    pub fn check_vni(&self, vrfid: VrfId) -> Result<(), RouterError> {
        let vrf = self.get_vrf(vrfid)?;
        let Some(vni) = &vrf.vni else {
            return Err(RouterError::Internal("No vni found"));
        };
        let found = self.get_vrfid_by_vni(*vni)?;
        if found != vrfid {
            error!("Vni {vni} refers to vrfid {found} and not {vrfid}");
            return Err(RouterError::Internal("Inconsistent vni mapping"));
        }
        // look up fib -- from fibtable
        let fibtable = self
            .fibtablew
            .enter()
            .ok_or(RouterError::Internal("Failed to access fib table"))?;
        let fib = fibtable
            .get_fib(&FibId::Vni(*vni))
            .ok_or(RouterError::Internal("No fib for vni found"))?;
        let fib = fib
            .enter()
            .ok_or(RouterError::Internal("Unable to read fib"))?;
        let found_fibid = fib.get_id();

        // look up fib - direct (TODO: make fib mandatory for VRF)
        if let Some(fibw) = &vrf.fibw {
            let fib = fibw
                .enter()
                .ok_or(RouterError::Internal("Unable to access Fib for vrf"))?;
            let fibid = fib.get_id();
            if fibid != found_fibid {
                error!("Expected: {found_fibid} found: {fibid}");
                return Err(RouterError::Internal("Inconsistent fib id found!"));
            }
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
            debug!("Requesting deletion of vrf {vrfid} FIB. Id is '{fib_id}'");
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
    /// Remove all of the VRFs with status `Deleted``
    //////////////////////////////////////////////////////////////////
    #[cfg(test)]
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

    pub fn get_default_vrf(&self) -> &Vrf {
        self.by_id.get(&0_u32).unwrap_or_else(|| unreachable!())
    }

    pub fn get_default_vrf_mut(&mut self) -> &mut Vrf {
        self.by_id.get_mut(&0_u32).unwrap_or_else(|| unreachable!())
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

    //////////////////////////////////////////////////////////////////
    /// Tell if the [`VrfTable`] contains a [`Vrf`] with some [`VrfId`]
    //////////////////////////////////////////////////////////////////
    pub fn contains(&self, vrfid: VrfId) -> bool {
        self.by_id.contains_key(&vrfid)
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
    fn vrf_table_basic() {
        /* create fib table */
        let (fibtw, _fibtr) = FibTableWriter::new();

        /* create iftable */
        debug!("━━━━━━━━ Test: Populate iftable");
        let (mut iftw, iftr) = build_test_iftable_left_right();

        let ift = iftr.enter().unwrap();
        println!("{}", *ift);
        drop(ift);

        /* create vrf table */
        let mut vrftable = VrfTable::new(fibtw);

        /* add VRFs (default VRF is always there) */
        debug!("━━━━━━━━ Test: Add VRFs");
        let cfg = RouterVrfConfig::new(1, "VPC-1").set_vni(Some(mk_vni(3000)));
        vrftable.add_vrf(&cfg).expect("Should succeed");

        let cfg = RouterVrfConfig::new(2, "VPC-2").set_vni(Some(mk_vni(4000)));
        vrftable.add_vrf(&cfg).expect("Should succeed");

        let cfg = RouterVrfConfig::new(3, "VPC-3").set_vni(Some(mk_vni(5000)));
        vrftable.add_vrf(&cfg).expect("Should succeed");

        /* add VRF with already used id */
        debug!("━━━━━━━━ Test: Add VRF with duplicated vrfid 1");
        let cfg = RouterVrfConfig::new(1, "duped-id");
        assert!(
            vrftable
                .add_vrf(&cfg)
                .is_err_and(|e| e == RouterError::VrfExists(1))
        );

        /* add VRF with unused id but used vni */
        debug!("━━━━━━━━ Test: Add VRF with duplicated vni 3000");
        let cfg = RouterVrfConfig::new(999, "duped-vni").set_vni(Some(mk_vni(3000)));
        assert!(
            vrftable
                .add_vrf(&cfg)
                .is_err_and(|e| e == RouterError::VniInUse(3000))
        );

        /* get VRF by vrfid - success case */
        debug!("━━━━━━━━ Test: Lookup vrf with id 3");
        let vrf3 = vrftable.get_vrf(3).expect("Should be there");
        assert_eq!(vrf3.name, "VPC-3");

        /* get VRF by vrfid - non-existent vrf */
        debug!("━━━━━━━━ Test: Lookup non-existent vrf with id 13");
        let vrf = vrftable.get_vrf(13);
        assert!(vrf.is_err_and(|e| e == RouterError::NoSuchVrf));

        /* get VRF by vni - success */
        debug!("━━━━━━━━ Test: Lookup vrf by vni 5000");
        let vrf3 = vrftable
            .get_vrf_by_vni(mk_vni(5000))
            .expect("Should be there");
        assert_eq!(vrf3.name, "VPC-3");

        /* get VRF by vni - nonexistent vrf */
        debug!("━━━━━━━━ Test: Lookup VRF by non-existent vni 1234");
        let vrf = vrftable.get_vrf_by_vni(mk_vni(1234));
        assert!(vrf.is_err_and(|e| e == RouterError::NoSuchVrf));

        /* check default vrf exists */
        debug!("━━━━━━━━ Test: Lookup default VRF");
        let vrf0 = vrftable.get_vrf(0).expect("Default always exists");
        assert_eq!(vrf0.name, "default");
        assert_eq!(vrf0.vni, None);

        println!("{vrftable}");

        /* Attach eth0 */
        let vrfid = 2;
        debug!("━━━━━━━━ Test: Attach eth0 to vrf {vrfid}");
        iftw.attach_interface_to_vrf(2, vrfid, &vrftable)
            .expect("Should succeed");
        let ift = iftr.enter().unwrap();
        let eth0 = ift.get_interface(2).expect("Should find interface");
        assert!(eth0.is_attached_to_fib(FibId::Id(vrfid)));
        println!("{}", *ift);
        drop(ift);

        /* Attach eth1 */
        let vrfid = 2;
        debug!("━━━━━━━━ Test: Attach eth1 to vrf {vrfid}");
        iftw.attach_interface_to_vrf(3, vrfid, &vrftable)
            .expect("Should succeed");
        let ift = iftr.enter().unwrap();
        let eth1 = ift.get_interface(3).expect("Should find interface");
        assert!(eth1.is_attached_to_fib(FibId::Id(vrfid)));
        println!("{}", *ift);
        drop(ift);

        /* Attach vlan100 */
        let vrfid = 1;
        debug!("━━━━━━━━ Test: Attach eth2 to vrf {vrfid}");
        iftw.attach_interface_to_vrf(4, vrfid, &vrftable)
            .expect("Should succeed");
        let ift = iftr.enter().unwrap();
        let eth2 = ift.get_interface(4).expect("Should find interface");
        assert!(eth2.is_attached_to_fib(FibId::Id(vrfid)));
        println!("{}", *ift);
        drop(ift);

        /* Attach vlan200 */
        let vrfid = 1;
        debug!("━━━━━━━━ Test: Attach eth1.100 to vrf {vrfid}");
        iftw.attach_interface_to_vrf(5, vrfid, &vrftable)
            .expect("Should succeed");
        let ift = iftr.enter().unwrap();
        let iface = ift.get_interface(5).expect("Should find interface");
        assert!(iface.is_attached_to_fib(FibId::Id(vrfid)));
        println!("{}", *ift);
        drop(ift);

        /* remove VRFs 1 - interfaces should be detached */
        let vrfid = 1;
        debug!("━━━━━━━━ Test: Remove vrf {vrfid} -- interfaces should be detached");
        vrftable
            .remove_vrf(vrfid, &mut iftw)
            .expect("Should succeed");
        assert!(
            vrftable
                .get_vrf(vrfid)
                .is_err_and(|e| e == RouterError::NoSuchVrf)
        );
        println!("{vrftable}");
        let ift = iftr.enter().unwrap();
        let iface = ift.get_interface(4).expect("Should be there");
        assert!(!iface.is_attached_to_fib(FibId::Id(vrfid)));
        assert!(iface.attachment.is_none());
        let iface = ift.get_interface(5).expect("Should be there");
        assert!(!iface.is_attached_to_fib(FibId::Id(vrfid)));
        assert!(iface.attachment.is_none());
        println!("{}", *ift);
        drop(ift);

        /* Vrf Should be gone from by_vni map */
        debug!("━━━━━━━━ Test: lookup by vni 3000");
        assert!(
            vrftable
                .get_vrf_by_vni(mk_vni(3000))
                .is_err_and(|e| e == RouterError::NoSuchVrf),
        );

        /* remove non-existent vrf */
        debug!("━━━━━━━━ Test: Remove vrf 987 - non-existent");
        let vrf = vrftable.remove_vrf(987, &mut iftw);
        assert!(vrf.is_err_and(|e| e == RouterError::NoSuchVrf));

        /* remove VRFs 2 - interfaces should be automatically detached */
        let vrfid = 2;
        debug!("━━━━━━━━ Test: Remove vrf {vrfid} -- interfaces should be detached");
        let _ = vrftable.remove_vrf(vrfid, &mut iftw);
        assert!(
            vrftable
                .get_vrf(vrfid)
                .is_err_and(|e| e == RouterError::NoSuchVrf)
        );
        let ift = iftr.enter().unwrap();
        let eth0 = ift.get_interface(2).expect("Should be there");
        assert!(!eth0.is_attached_to_fib(FibId::Id(vrfid)));
        assert!(eth0.attachment.is_none());
        let eth1 = ift.get_interface(3).expect("Should be there");
        assert!(!eth1.is_attached_to_fib(FibId::Id(vrfid)));
        assert!(eth1.attachment.is_none());
        println!("{}", *ift);
        drop(ift);

        /* Vrf Should be gone from by_vni map */
        debug!("━━━━━━━━ Test: lookup by vni 4000");
        assert!(
            vrftable
                .get_vrf_by_vni(mk_vni(4000))
                .is_err_and(|e| e == RouterError::NoSuchVrf),
        );

        println!("{vrftable}");
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

        debug!("━━━━Test: Add a VRF without VNI");
        let vrf_cfg = RouterVrfConfig::new(vrfid, "VPC-1");
        vrftable.add_vrf(&vrf_cfg).expect("Should be created");

        let vrf = vrftable.get_vrf(vrfid).expect("Should be there");
        assert_eq!(vrf.name, "VPC-1");
        assert_eq!(vrf.vni, None);

        {
            let vrf = vrftable.get_vrf_mut(vrfid).expect("Should be there");
            vrf.set_tableid(1234.try_into().expect("Should succeed"));
            vrf.set_description("This is the vrf for VPC-1 ACME");
        }

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

        debug!("━━━━Test: Add a VRF without Vni");
        let vrf_cfg = RouterVrfConfig::new(vrfid, "VPC-1");
        vrftable.add_vrf(&vrf_cfg).expect("Should be created");

        debug!("━━━━Test: Associate VNI {vni}");
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
