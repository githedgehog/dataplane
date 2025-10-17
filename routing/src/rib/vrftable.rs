// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Vrf table module that stores multiple vrfs. Every vrf is uniquely identified by a vrfid
//! and optionally identified by a Vni. A vrf table always has a default vrf.

use crate::RouterError;
use crate::evpn::RmacStore;
use crate::fib::fibtable::FibTableWriter;
use crate::fib::fibtype::FibKey;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::rib::vrf::{RouterVrfConfig, Vrf, VrfId};

#[cfg(test)]
use crate::rib::vrf::VrfStatus;

use ahash::RandomState;
use net::vxlan::Vni;
use std::collections::HashMap;

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
        let fibw = self.fibtablew.add_fib(vrf.vrfid, vrf.vni);
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
        // However the vrf with id VrfId may have another vni associated.
        // So, unset any vni that the vrf may have associated first.
        self.unset_vni(vrfid)?;

        /* lookup vrf */
        let vrf = self.get_vrf_mut(vrfid)?;

        /* set the vni to the vrf */
        vrf.set_vni(vni);

        /* register vni as key for vrf vrfid in the vrf table */
        self.by_vni.insert(vni, vrfid);

        /* make fib accessible from vni in the fib table */
        self.fibtablew.register_fib_by_vni(vrfid, vni);
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////////////
    /// Remove the vni from a VRF. This clears the vni field in a VRF if found and
    /// removes it from the `by_vni` map. It also unindexes the vrf's FIB by the vni.
    ///////////////////////////////////////////////////////////////////////////////////
    pub fn unset_vni(&mut self, vrfid: VrfId) -> Result<(), RouterError> {
        debug!("Unsetting any vni configuration for vrf {vrfid}..");
        let vrf = self.get_vrf_mut(vrfid)?;

        // check if vrf has vni configured
        if let Some(vni) = vrf.vni {
            debug!("Vrf {vrfid} has vni {vni} associated. Removing...");
            vrf.vni.take();
            self.by_vni.remove(&vni);
            self.fibtablew.unregister_vni(vni);
            debug!("Vrf with Id {vrfid} no longer has a vni {vni} associated");
        } else {
            debug!("Vrf {vrfid} has no vni configured");
        }
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////////////////
    /// Check the correctness of a vni configuration for the vrf with the given [`VrfId`].
    /// This method returns an error if the indicated vrf does not exist, does not have
    /// a [`Vni`] configured or it does but the internal state is not the expected.
    ///////////////////////////////////////////////////////////////////////////////////
    pub fn check_vni(&self, vrfid: VrfId) -> Result<(), RouterError> {
        // lookup vrf: should be found
        let vrf = self.get_vrf(vrfid)?;

        // Vrf must have a vni configured: should succeed
        let Some(vni) = &vrf.vni else {
            return Err(RouterError::Internal("No vni found"));
        };

        // must be able to look up [`Vrf`] by vni and we must find a [`Vrf`] with same [`VrfId`]
        let found = self.get_vrfid_by_vni(*vni)?;
        if found != vrfid {
            error!("Vni {vni} refers to vrfid {found} and not {vrfid}");
            return Err(RouterError::Internal("Inconsistent vni mapping"));
        }

        // access fib table: it should always be possible for us to enter the fib table since
        // the vrf table owns the `FibTableWriter`. Also, as a reader, we should be able to see the latest
        // changes since we published and would otherwise got blocked. To test for correctness, we check
        // the two keys via which this vrf should be accessible and from our thread-local cache.
        let fibtabler = self.fibtablew.as_fibtable_reader();
        fibtabler.get_fib_reader(FibKey::from_vrfid(vrfid))?;

        let fibid = FibKey::from_vrfid(vrfid); // The id it should have
        if let Some(key) = fibtabler.get_fib_reader(FibKey::from_vni(*vni))?.get_id()
            && key != fibid
        {
            return Err(RouterError::Internal("Inconsistent fib id found!"));
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
        // remove the vrf from the vrf table
        debug!("Removing VRF {vrfid}...");
        let Some(vrf) = self.by_id.remove(&vrfid) else {
            error!("No vrf with id {vrfid} exists");
            return Err(RouterError::NoSuchVrf);
        };
        // delete the corresponding fib
        if vrf.fibw.is_some() {
            debug!("Deleting Fib for vrf {vrfid} from the FibTable");
            self.fibtablew.del_fib(vrfid, vrf.vni);
            iftablew.detach_interfaces_from_vrf(vrfid);
        }

        // if the VRF had a vni assigned, unregister it
        if let Some(vni) = vrf.vni {
            debug!("Unregistering vni {vni}");
            self.by_vni.remove(&vni);
        }
        debug!("Vrf {vrfid} has been removed");
        Ok(())
    }

    ///////////////////////////////////////////////////////////////////////
    /// Remove all of the VRFs for which the provided function returns true
    ///////////////////////////////////////////////////////////////////////
    fn remove_vrfs(&mut self, f: fn(&Vrf) -> bool, iftablew: &mut IfTableWriter) {
        // collect the ids of the vrfs with status deleted
        let to_delete: Vec<VrfId> = self
            .by_id
            .values()
            .filter_map(|vrf| f(vrf).then_some(vrf.vrfid))
            .collect();

        // delete them
        for vrfid in &to_delete {
            if let Err(e) = self.remove_vrf(*vrfid, iftablew) {
                error!("Failed to delete vrf with id {vrfid}: {e}");
            }
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Remove all of the VRFs with status `Deleted`
    //////////////////////////////////////////////////////////////////
    pub fn remove_deleted_vrfs(&mut self, iftablew: &mut IfTableWriter) {
        debug!("Removing deletable vrfs...");
        self.remove_vrfs(Vrf::can_be_deleted, iftablew);
    }

    //////////////////////////////////////////////////////////////////
    /// Remove all of the VRFs with status `Deleting`
    //////////////////////////////////////////////////////////////////
    pub fn remove_deleting_vrfs(&mut self, iftablew: &mut IfTableWriter) {
        debug!("Removing vrfs with deleting status...");
        self.remove_vrfs(Vrf::is_deleting, iftablew);
    }

    //////////////////////////////////////////////////////////////////
    /// Immutably access a [`Vrf`] from its id.
    //////////////////////////////////////////////////////////////////
    pub fn get_vrf(&self, vrfid: VrfId) -> Result<&Vrf, RouterError> {
        self.by_id.get(&vrfid).ok_or(RouterError::NoSuchVrf)
    }

    fn is_default_vrf(vrf: &Vrf) -> bool {
        vrf.vrfid == 0
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
    /// Get a Vec<&mut Vrf> of all VRFs except the default one
    ///
    /// # Returns
    ///
    /// A tuple of a Vec<&mut Vrf> of all VRFs except the default one and a
    /// mutable reference to the default VRF.
    ///
    /// # Examples
    /// ```ignore
    /// let (vrfs, vrf0) = self.values_mut_except_default();
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the default VRF is not found.
    ///
    /// # Note
    ///
    /// This is a workaround for the fact that we cannot do
    /// ```compile_fail
    /// let vrf0 = self.get_default_vrf();
    /// let mut vrfs = self.values_mut();
    /// ```
    /// because `vrf0` will borrow `self` immutably and then we want to borrow
    /// `self` mutably in `self.values_mut()`.  In fact, while the above code
    /// looks correct, it is not as `values_mut()` can, in theory, resize
    /// the underlying `self.by_id` data structure and invalidate the reference
    /// to `vrf0`.
    ///
    /// This workaround kind of sucks because we have to traverse the list of all
    /// vrfs to find the default VRF and then the caller will iterate over the
    /// resulting Vec which we had to allocate.
    ///
    /// When `Iterator::partition_in_place` is stabilized, we can use that
    /// instead and avoid the allocation of `Vec`, but we still have a double
    /// traversal of the list of vrfs.
    ///
    /// Perhaps a solution here would be to lift the default VRF out of the
    /// hash table and use it separately?
    //////////////////////////////////////////////////////////////////
    fn values_mut_except_default(&mut self) -> (impl Iterator<Item = &mut Vrf>, &mut Vrf) {
        let (vrfs, mut vrf0): (Vec<_>, Vec<_>) = self
            .values_mut()
            .partition(|vrf| !Self::is_default_vrf(vrf));
        let vrf0 = vrf0.pop().expect("Default VRF should always be present");
        (vrfs.into_iter(), vrf0)
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

    //////////////////////////////////////////////////////////////////
    /// Refresh the fib groups for all non-default vrfs.
    //////////////////////////////////////////////////////////////////
    pub fn refresh_non_default_fibs(&mut self, rstore: &RmacStore) {
        let (vrfs, vrf0) = self.values_mut_except_default();
        for vrf in vrfs {
            vrf.refresh_fib(rstore, Some(vrf0));
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Set/unset stale flag for all routes in all vrfs
    /////////////////////////////////////////////////////////////////////////
    pub fn set_stale(&mut self, value: bool) {
        debug!("Marking all routes as stale..");
        self.by_id.values_mut().for_each(|vrf| vrf.set_stale(value));
    }
    /////////////////////////////////////////////////////////////////////////
    // Remove stale routes across all vrfs
    /////////////////////////////////////////////////////////////////////////
    pub fn remove_stale_routes(&mut self, rstore: &RmacStore) {
        debug!("Removing stale routes..");
        let (vrfs, vrf0) = self.values_mut_except_default();

        // remove stale routes from non-default vrfs
        for vrf in vrfs {
            vrf.remove_stale_routes(Some(vrf0), rstore);
        }

        // remove stale routes from default vrf
        vrf0.remove_stale_routes(None, rstore);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fib::fibobjects::{EgressObject, PktInstruction};
    use crate::fib::fibtype::FibKey;
    use crate::interfaces::tests::build_test_iftable_left_right;
    use crate::pretty_utils::Frame;
    use crate::rib::encapsulation::Encapsulation;
    use crate::rib::vrf::tests::{build_test_vrf, mk_addr};
    use crate::rib::vrf::tests::{
        build_test_vrf_nhops_partially_resolved, init_test_vrf, mod_test_vrf_1, mod_test_vrf_2,
    };
    use crate::{
        evpn::rmac::tests::build_sample_rmac_store, rib::encapsulation::VxlanEncapsulation,
    };
    use net::interface::InterfaceIndex;
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
        let idx2 = InterfaceIndex::try_new(2).unwrap();
        debug!("━━━━━━━━ Test: Attach eth0 to vrf {vrfid}");
        iftw.attach_interface_to_vrf(idx2, vrfid, &vrftable)
            .expect("Should succeed");
        let ift = iftr.enter().unwrap();
        let eth0 = ift.get_interface(idx2).expect("Should find interface");
        assert!(eth0.is_attached_to_fib(FibKey::Id(vrfid)));
        println!("{}", *ift);
        drop(ift);

        /* Attach eth1 */
        let vrfid = 2;
        let idx3 = InterfaceIndex::try_new(3).unwrap();
        debug!("━━━━━━━━ Test: Attach eth1 to vrf {vrfid}");
        iftw.attach_interface_to_vrf(idx3, vrfid, &vrftable)
            .expect("Should succeed");
        let ift = iftr.enter().unwrap();
        let eth1 = ift.get_interface(idx3).expect("Should find interface");
        assert!(eth1.is_attached_to_fib(FibKey::Id(vrfid)));
        println!("{}", *ift);
        drop(ift);

        /* Attach vlan100 */
        let vrfid = 1;
        let idx4 = InterfaceIndex::try_new(4).unwrap();
        debug!("━━━━━━━━ Test: Attach eth2 to vrf {vrfid}");
        iftw.attach_interface_to_vrf(idx4, vrfid, &vrftable)
            .expect("Should succeed");
        let ift = iftr.enter().unwrap();
        let eth2 = ift.get_interface(idx4).expect("Should find interface");
        assert!(eth2.is_attached_to_fib(FibKey::Id(vrfid)));
        println!("{}", *ift);
        drop(ift);

        /* Attach vlan200 */
        let vrfid = 1;
        let idx5 = InterfaceIndex::try_new(5).unwrap();
        debug!("━━━━━━━━ Test: Attach eth1.100 to vrf {vrfid}");
        iftw.attach_interface_to_vrf(idx5, vrfid, &vrftable)
            .expect("Should succeed");
        let ift = iftr.enter().unwrap();
        let iface = ift.get_interface(idx5).expect("Should find interface");
        assert!(iface.is_attached_to_fib(FibKey::Id(vrfid)));
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
        let iface = ift.get_interface(idx4).expect("Should be there");
        assert!(!iface.is_attached_to_fib(FibKey::Id(vrfid)));
        assert!(iface.attachment.is_none());
        let iface = ift.get_interface(idx5).expect("Should be there");
        assert!(!iface.is_attached_to_fib(FibKey::Id(vrfid)));
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
        let eth0 = ift.get_interface(idx2).expect("Should be there");
        assert!(!eth0.is_attached_to_fib(FibKey::Id(vrfid)));
        assert!(eth0.attachment.is_none());
        let eth1 = ift.get_interface(idx3).expect("Should be there");
        assert!(!eth1.is_attached_to_fib(FibKey::Id(vrfid)));
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
            assert!(fibtable.get_fib(&FibKey::from_vrfid(vrfid)).is_some());
            assert!(fibtable.get_fib(&FibKey::from_vni(vni)).is_some());
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
            assert!(fibtable.get_fib(&FibKey::from_vrfid(vrfid)).is_some());
            assert!(fibtable.get_fib(&FibKey::from_vni(vni)).is_none());
        }
    }

    #[traced_test]
    #[test]
    fn vrf_table_deletions() {
        debug!("━━━━Test: Create testing interface table");
        let (mut iftw, iftr) = build_test_iftable_left_right();

        debug!("━━━━Test: Create vrf table");
        let (fibtw, fibtr) = FibTableWriter::new();
        let mut vrftable = VrfTable::new(fibtw);

        debug!("━━━━Test: Check fib access for vrf default");
        if let Some(fibtable) = fibtr.enter() {
            let fibkey = FibKey::from_vrfid(0);
            let fibr = fibtable.get_fib(&fibkey).unwrap();
            let fib = fibr.enter().unwrap();
            assert_eq!(fib.as_ref().get_id(), fibkey);
        }

        let vrfid = 999;
        let vni = mk_vni(3000);

        debug!("━━━━Test: Add a VRF with id {vrfid} but no Vni");
        let vrf_cfg = RouterVrfConfig::new(vrfid, "VPC-1");
        vrftable.add_vrf(&vrf_cfg).expect("Should be created");
        assert_eq!(vrftable.len(), 2); // default is always there
        debug!("\n{vrftable}");

        debug!("━━━━Test: Check fib access for vrf {vrfid}");
        if let Some(fibtable) = fibtr.enter() {
            // check that fib is accessible from vrfid
            let fibkey = FibKey::from_vrfid(vrfid);
            let fibr = fibtable.get_fib(&fibkey).unwrap();
            let fib = fibr.enter().unwrap();
            assert_eq!(fib.as_ref().get_id(), fibkey);
            assert_eq!(fibtable.as_ref().len(), 2);
        }

        debug!("━━━━Test: Associate vni {vni} to vrf {vrfid}");
        vrftable.set_vni(vrfid, vni).expect("Should succeed");
        debug!("\n{vrftable}");

        debug!("━━━━Test: Check fib access for vrf {vrfid} and vni {vni}");
        if let Some(fibtable) = fibtr.enter() {
            // check that fib continues to be accessible via vrfid
            let fibkey = FibKey::from_vrfid(vrfid);
            let fibr = fibtable.get_fib(&fibkey).unwrap();
            let fib = fibr.enter().unwrap();
            assert_eq!(fib.as_ref().get_id(), fibkey);

            // check that fib is accessible from vni
            let fibkey = FibKey::from_vni(vni);
            let fibr = fibtable.get_fib(&fibkey).unwrap();
            let fib = fibr.enter().unwrap();
            assert_eq!(fib.as_ref().get_id(), FibKey::from_vrfid(vrfid));
        }

        debug!("━━━━Test: deleting removed VRFs: nothing should be removed");
        vrftable.remove_deleted_vrfs(&mut iftw);
        assert_eq!(vrftable.len(), 2); // default is always there
        assert_eq!(fibtr.enter().unwrap().len(), 3);
        debug!("\n{vrftable}");

        debug!("━━━━Test: Get interface from iftable");
        let idx = InterfaceIndex::try_new(2).unwrap();
        if let Some(iftable) = iftr.enter() {
            let iface = iftable.get_interface(idx).expect("Should be there");
            assert_eq!(iface.name, "eth0");
            debug!("\n{}", *iftable);
        }

        debug!("━━━━Test: Attach interface to vrf {vrfid}");
        iftw.attach_interface_to_vrf(idx, vrfid, &vrftable)
            .expect("Should succeed");
        if let Some(iftable) = iftr.enter() {
            let iface = iftable.get_interface(idx).expect("Should be there");
            assert!(iface.attachment.is_some());
            debug!("\n{}", *iftable);
        }

        debug!("━━━━Test: Get vrf and mark as deleted");
        let vrf = vrftable.get_vrf_mut(vrfid).expect("Should be there");
        vrf.set_status(VrfStatus::Deleted);
        debug!("\n{vrftable}");

        debug!("━━━━Test: remove vrfs marked as deleted: VPC-1 vrf should be gone");
        vrftable.remove_deleted_vrfs(&mut iftw);
        assert_eq!(vrftable.len(), 1, "should be gone");
        assert_eq!(
            fibtr.enter().unwrap().len(),
            1,
            "only default fib should remain"
        );

        debug!("━━━━Test: Check that no fib is accessible vrfid:{vrfid} nor vni:{vni}");
        if let Some(fibtable) = fibtr.enter() {
            assert!(fibtable.get_fib(&FibKey::from_vrfid(vrfid)).is_none());
            assert!(fibtable.get_fib(&FibKey::from_vni(vni)).is_none());
            assert!(fibtable.get_fib(&FibKey::from_vrfid(0)).is_some());
        }
        debug!("━━━━Test: Interface {idx} should no longer be attached");
        if let Some(iftable) = iftr.enter() {
            let iface = iftable.get_interface(idx).expect("Should be there");
            assert!(iface.attachment.is_none(), "Should have been detached");
        }

        debug!("\n{vrftable}");
    }

    fn show_fibgroups(vrf: &Vrf, destination: &str) {
        let (_prefix, route) = vrf.lpm(mk_addr(destination));
        println!("nhops to {destination} are");
        for shim in route.s_nhops.iter() {
            let nhop = &*shim.rc;
            println!("{nhop}");
        }
        for shim in route.s_nhops.iter() {
            let nhop = &*shim.rc;
            let fibgroup = nhop.fibgroup.borrow().clone();
            println!("fibgroup of nhop {nhop}:\n\n{fibgroup}");
        }
    }

    #[rustfmt::skip]
    fn test_vrf_fibgroup(mut vrf: Vrf) {
        let rstore = build_sample_rmac_store();

        vrf.nhstore.lazy_resolve_all(&vrf);
        vrf.nhstore.resolve_nhop_instructions(&rstore);
        vrf.nhstore.rebuild_fibgroups(&rstore);
        // vrf.refresh_fib(&rstore, None);
        // refresh_fib() won't work because add_route() does not build the packet instructions

        print!("{}", Frame("Initial fibgroups".to_string()));
        show_fibgroups(&vrf, "8.0.0.1");
        show_fibgroups(&vrf, "8.0.0.2");
        show_fibgroups(&vrf, "7.0.0.1");
        show_fibgroups(&vrf, "192.168.0.1");
        let destination = mk_addr("192.168.0.1");
        let (_, route) = vrf.lpm(destination);
        let fibgroup = route.s_nhops[0].rc.fibgroup.borrow().clone();
        assert_eq!(fibgroup.len(), 4);
        for (num, entry) in fibgroup.iter().enumerate() {
            assert_eq!(entry.len(), 4);
            let mut vxlan = VxlanEncapsulation::new(mk_vni(3000), mk_addr("7.0.0.1"));
            vxlan.resolve(&rstore);
            assert_eq!(entry.instructions[0], PktInstruction::Encap(Encapsulation::Vxlan(vxlan)));
            assert_eq!(entry.instructions[1], PktInstruction::Encap(Encapsulation::Mpls(7000)));
            match num {
                0 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(1).ok(), Some(mk_addr("10.0.0.1")), None))),
                1 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5")), None))),
                2 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5")), None))),
                3 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(3).ok(), Some(mk_addr("10.0.0.9")), None))),
                _ => unreachable!(),
            }
        }

        mod_test_vrf_1(&mut vrf);
        vrf.refresh_fib(&rstore, None);
        vrf.dump(Some("After removing path via 10.0.0.5"));

        show_fibgroups(&vrf, "8.0.0.1");
        show_fibgroups(&vrf, "8.0.0.2");
        show_fibgroups(&vrf, "7.0.0.1");
        show_fibgroups(&vrf, "192.168.0.1");

        let (_, route) = vrf.lpm(destination);
        let fibgroup = route.s_nhops[0].rc.fibgroup.borrow().clone();
        assert_eq!(fibgroup.len(), 2);
        for (num, entry) in fibgroup.iter().enumerate() {
            assert_eq!(entry.len(), 4);
            let mut vxlan = VxlanEncapsulation::new(mk_vni(3000), mk_addr("7.0.0.1"));
            vxlan.resolve(&rstore);
            assert_eq!(entry.instructions[0], PktInstruction::Encap(Encapsulation::Vxlan(vxlan)));
            assert_eq!(entry.instructions[1], PktInstruction::Encap(Encapsulation::Mpls(7000)));
            match num {
                0 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(1).ok(), Some(mk_addr("10.0.0.1")), None))),
                1 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(3).ok(), Some(mk_addr("10.0.0.9")), None))),
                _ => unreachable!(),
            }
        }


        mod_test_vrf_2(&mut vrf);
        vrf.refresh_fib(&rstore, None);

        show_fibgroups(&vrf, "8.0.0.1");
        show_fibgroups(&vrf, "7.0.0.1");
        show_fibgroups(&vrf, "192.168.0.1");

        let (_, route) = vrf.lpm(destination);
        let fibgroup = route.s_nhops[0].rc.fibgroup.borrow().clone();
        assert_eq!(fibgroup.len(), 1);
        for (num, entry) in fibgroup.iter().enumerate() {
            assert_eq!(entry.len(), 4);
            let mut vxlan = VxlanEncapsulation::new(mk_vni(3000), mk_addr("7.0.0.1"));
            vxlan.resolve(&rstore);
            assert_eq!(entry.instructions[0], PktInstruction::Encap(Encapsulation::Vxlan(vxlan)));
            assert_eq!(entry.instructions[1], PktInstruction::Encap(Encapsulation::Mpls(7000)));
            match num {
                0 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5")), None))),
                _ => unreachable!(),
            }
        }


        init_test_vrf(&mut vrf);
        vrf.refresh_fib(&rstore, None);
        show_fibgroups(&vrf, "192.168.0.1");

        let (_, route) = vrf.lpm(destination);
        let fibgroup = route.s_nhops[0].rc.fibgroup.borrow().clone();
        assert_eq!(fibgroup.len(), 4);
        for (num, entry) in fibgroup.iter().enumerate() {
            assert_eq!(entry.len(), 4);
            let mut vxlan = VxlanEncapsulation::new(mk_vni(3000), mk_addr("7.0.0.1"));
            vxlan.resolve(&rstore);
            assert_eq!(entry.instructions[0], PktInstruction::Encap(Encapsulation::Vxlan(vxlan)));
            assert_eq!(entry.instructions[1], PktInstruction::Encap(Encapsulation::Mpls(7000)));
            match num {
                0 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(1).ok(), Some(mk_addr("10.0.0.1")), None))),
                1 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5")), None))),
                2 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5")), None))),
                3 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(3).ok(), Some(mk_addr("10.0.0.9")), None))),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_vrf_fibgroup_1() {
        test_vrf_fibgroup(build_test_vrf());
    }

    #[traced_test]
    #[test]
    fn test_vrf_fibgroup_2() {
        test_vrf_fibgroup(build_test_vrf_nhops_partially_resolved());
    }
}
