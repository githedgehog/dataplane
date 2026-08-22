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
        let _ = vrftable.add_vrf(&RouterVrfConfig::new(Vrf::DEFAULT_VRFID, "default"));
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
        let mut vrf = Vrf::new(config);

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

    /////////////////////////////////////////////////////////////////////
    /// set the vni for a certain `Vrf` that is already in the `VrfTable`
    /////////////////////////////////////////////////////////////////////
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
        // Lookup and cross-vrf resolution assume the default vrf always exists.
        if vrfid == Vrf::DEFAULT_VRFID {
            error!("Refusing to remove the default vrf");
            return Err(RouterError::Internal(
                "Bug: the default vrf cannot be removed",
            ));
        }

        // remove the vrf from the vrf table
        debug!("Removing VRF {vrfid}...");
        let Some(mut vrf) = self.by_id.remove(&vrfid) else {
            error!("No vrf with id {vrfid} exists");
            return Err(RouterError::NoSuchVrf);
        };

        // detach interfaces
        iftablew.detach_interfaces_from_vrf(vrfid);

        // delete the corresponding fib
        if let Some(fibw) = vrf.fibw.take() {
            debug!("Deleting Fib for vrf {vrfid} from the FibTable");
            self.fibtablew.del_fib(vrfid);
            fibw.destroy();
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

    #[allow(unused)]
    pub fn get_default_vrf(&self) -> &Vrf {
        self.by_id
            .get(&Vrf::DEFAULT_VRFID)
            .unwrap_or_else(|| unreachable!())
    }

    #[allow(unused)]
    pub fn get_default_vrf_mut(&mut self) -> &mut Vrf {
        self.by_id
            .get_mut(&Vrf::DEFAULT_VRFID)
            .unwrap_or_else(|| unreachable!())
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
        if vrfid == Vrf::DEFAULT_VRFID {
            return Err(RouterError::Internal("Bug: misuse of vrf lookup"));
        }
        match self.by_id.get_disjoint_mut([&vrfid, &Vrf::DEFAULT_VRFID]) {
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
        let (vrfs, mut vrf0): (Vec<_>, Vec<_>) =
            self.values_mut().partition(|vrf| !Vrf::is_default_vrf(vrf));
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

    //////////////////////////////////////////////////////////////////
    /// Refresh the fib groups for all vrfs that have a vni in the
    /// provided set
    //////////////////////////////////////////////////////////////////
    pub fn refresh_fibs_by_vni(&mut self, vnis: &[Vni], rstore: &RmacStore) {
        let (vrfs, vrf0) = self.values_mut_except_default();
        for vrf in vrfs.filter(|v| v.vni.is_some_and(|vni| vnis.contains(&vni))) {
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
#[allow(clippy::too_many_lines)]
#[allow(clippy::match_same_arms)]
mod tests {
    use super::*;
    use crate::fib::fibobjects::{EgressObject, PktInstruction};
    use crate::fib::fibtype::FibKey;
    use crate::interfaces::tests::build_test_iftable_left_right;
    use crate::rib::encapsulation::Encapsulation;
    use crate::rib::vrf::VrfStatus;
    use crate::rib::vrf::tests::{build_test_vrf, mk_addr};
    use crate::rib::vrf::tests::{
        build_test_vrf_nhops_partially_resolved, init_test_vrf, mod_test_vrf_1, mod_test_vrf_2,
    };
    use crate::{
        evpn::rmac::tests::build_sample_rmac_store, rib::encapsulation::VxlanEncapsulation,
    };
    use common::cliprovider::Frame;
    use net::interface::InterfaceIndex;
    use tracing_test::traced_test;

    fn mk_vni(vni: u32) -> Vni {
        vni.try_into().expect("Bad vni")
    }

    #[cfg_attr(not(emulated), traced_test)]
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

    #[cfg_attr(not(emulated), traced_test)]
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
            assert!(fibtable.get_fib(FibKey::from_vrfid(vrfid)).is_some());
            assert!(fibtable.get_fib(FibKey::from_vni(vni)).is_some());
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
            assert!(fibtable.get_fib(FibKey::from_vrfid(vrfid)).is_some());
            assert!(fibtable.get_fib(FibKey::from_vni(vni)).is_none());
        }
    }

    #[cfg_attr(not(emulated), traced_test)]
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
            let fibr = fibtable.get_fib(fibkey).unwrap();
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
            let fibr = fibtable.get_fib(fibkey).unwrap();
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
            let fibr = fibtable.get_fib(fibkey).unwrap();
            let fib = fibr.enter().unwrap();
            assert_eq!(fib.as_ref().get_id(), fibkey);

            // check that fib is accessible from vni
            let fibkey = FibKey::from_vni(vni);
            let fibr = fibtable.get_fib(fibkey).unwrap();
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
            assert!(fibtable.get_fib(FibKey::from_vrfid(vrfid)).is_none());
            assert!(fibtable.get_fib(FibKey::from_vni(vni)).is_none());
            assert!(fibtable.get_fib(FibKey::from_vrfid(0)).is_some());
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
        for shim in &route.s_nhops {
            let nhop = &*shim.rc;
            println!("{nhop}");
        }
        for shim in &route.s_nhops {
            let nhop = &*shim.rc;
            let fibgroup = nhop.fibgroup.borrow().clone();
            println!("fibgroup of nhop {nhop}:\n\n{fibgroup}");
        }
    }

    #[rustfmt::skip]
    fn test_vrf_fibgroup(mut vrf: Vrf) {
        let rstore = build_sample_rmac_store();

        vrf.nhstore.lazy_resolve_all(&vrf);
        vrf.nhstore.rebuild_nhop_instructions(&rstore);
        vrf.nhstore.rebuild_fibgroups(&rstore);
        // vrf.refresh_fib(&rstore, None);
        // refresh_fib() won't work because add_route() does not build the packet instructions
        // It doesn't because it does not get an rmac store by design

        print!("{}", Frame("Initial fibgroups"));
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
                0 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(1).ok(), Some(mk_addr("10.0.0.1"))))),
                1 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5"))))),
                2 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5"))))),
                3 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(3).ok(), Some(mk_addr("10.0.0.9"))))),
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
                0 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(1).ok(), Some(mk_addr("10.0.0.1"))))),
                1 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(3).ok(), Some(mk_addr("10.0.0.9"))))),
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
                0 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5"))))),
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
                0 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(1).ok(), Some(mk_addr("10.0.0.1"))))),
                1 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5"))))),
                2 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(2).ok(), Some(mk_addr("10.0.0.5"))))),
                3 => assert_eq!(entry.instructions[3], PktInstruction::Egress(EgressObject::new(InterfaceIndex::try_new(3).ok(), Some(mk_addr("10.0.0.9"))))),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_vrf_fibgroup_1() {
        test_vrf_fibgroup(build_test_vrf());
    }

    #[cfg_attr(not(emulated), traced_test)]
    #[test]
    fn test_vrf_fibgroup_2() {
        test_vrf_fibgroup(build_test_vrf_nhops_partially_resolved());
    }
}

/// Model-checks vrf id/vni indexes, statuses, and fib aliases.
#[cfg(test)]
mod vrftable_properties {
    use super::*;
    use crate::interfaces::iftablerw::IfTableWriter;
    use crate::rib::vrf::VrfStatus;
    use bolero::{Driver, ValueGenerator};
    use std::collections::BTreeMap;
    use std::ops::Bound::Included;

    const NUM_VRFS: u8 = 3;
    const NUM_VNIS: u8 = 2;
    const NUM_STATUSES: u8 = 3;
    const MAX_CHANGES: u8 = 12;

    fn vrf_ids() -> Vec<VrfId> {
        (0..u32::from(NUM_VRFS)).collect()
    }

    fn vnis() -> Vec<Vni> {
        (1..=u32::from(NUM_VNIS))
            .map(|i| Vni::new_checked(100 * i).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    fn statuses() -> Vec<VrfStatus> {
        vec![VrfStatus::Active, VrfStatus::Deleting, VrfStatus::Deleted]
    }

    #[derive(Debug, Clone)]
    enum Change {
        AddVrf { vrf: usize, vni: Option<usize> },
        SetVni { vrf: usize, vni: usize },
        UnsetVni { vrf: usize },
        RemoveVrf { vrf: usize },
        SetStatus { vrf: usize, status: usize },
        RemoveDeleted,
        RemoveDeleting,
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
                let change = match driver.gen_u8(Included(&0), Included(&6))? {
                    0 => {
                        // The final index encodes no vni without conflating it with exhaustion.
                        let vrf = index(driver, NUM_VRFS)?;
                        let drawn = index(driver, NUM_VNIS + 1)?;
                        Change::AddVrf {
                            vrf,
                            vni: (drawn < usize::from(NUM_VNIS)).then_some(drawn),
                        }
                    }
                    1 => Change::SetVni {
                        vrf: index(driver, NUM_VRFS)?,
                        vni: index(driver, NUM_VNIS)?,
                    },
                    2 => Change::UnsetVni {
                        vrf: index(driver, NUM_VRFS)?,
                    },
                    3 => Change::RemoveVrf {
                        vrf: index(driver, NUM_VRFS)?,
                    },
                    4 => Change::SetStatus {
                        vrf: index(driver, NUM_VRFS)?,
                        status: index(driver, NUM_STATUSES)?,
                    },
                    5 => Change::RemoveDeleted,
                    _ => Change::RemoveDeleting,
                };
                out.push(change);
            }
            Some(out)
        }
    }

    /// Expected vni and status for each vrf.
    type Model = BTreeMap<VrfId, (Option<Vni>, VrfStatus)>;

    fn owner_of(model: &Model, vni: Vni) -> Option<VrfId> {
        model
            .iter()
            .find_map(|(id, (carried, _))| (*carried == Some(vni)).then_some(*id))
    }

    fn fresh_model() -> Model {
        Model::from([(Vrf::DEFAULT_VRFID, (None, VrfStatus::Active))])
    }

    fn apply(table: &mut VrfTable, iftw: &mut IfTableWriter, model: &mut Model, change: &Change) {
        let ids = vrf_ids();
        let all_vnis = vnis();
        match change {
            Change::AddVrf { vrf, vni } => {
                let id = ids[*vrf];
                let vni = vni.map(|i| all_vnis[i]);
                let config = RouterVrfConfig::new(id, &format!("vrf{id}")).set_vni(vni);
                let _ = table.add_vrf(&config);
                if model.contains_key(&id) || vni.is_some_and(|v| owner_of(model, v).is_some()) {
                    return;
                }
                model.insert(id, (vni, VrfStatus::Active));
            }
            Change::SetVni { vrf, vni } => {
                let id = ids[*vrf];
                let vni = all_vnis[*vni];
                let _ = table.set_vni(id, vni);
                match owner_of(model, vni) {
                    Some(_) => (),
                    None => {
                        if let Some(entry) = model.get_mut(&id) {
                            entry.0 = Some(vni);
                        }
                    }
                }
            }
            Change::UnsetVni { vrf } => {
                let id = ids[*vrf];
                let _ = table.unset_vni(id);
                if let Some(entry) = model.get_mut(&id) {
                    entry.0 = None;
                }
            }
            Change::RemoveVrf { vrf } => {
                let id = ids[*vrf];
                let _ = table.remove_vrf(id, iftw);
                if id != Vrf::DEFAULT_VRFID {
                    model.remove(&id);
                }
            }
            Change::SetStatus { vrf, status } => {
                let id = ids[*vrf];
                let status = statuses()[*status];
                if let Ok(vrf) = table.get_vrf_mut(id) {
                    vrf.set_status(status);
                }
                // The default vrf remains active.
                if id != Vrf::DEFAULT_VRFID
                    && let Some(entry) = model.get_mut(&id)
                {
                    entry.1 = status;
                }
            }
            Change::RemoveDeleted => {
                table.remove_deleted_vrfs(iftw);
                model.retain(|_, (_, status)| *status != VrfStatus::Deleted);
            }
            Change::RemoveDeleting => {
                table.remove_deleting_vrfs(iftw);
                model.retain(|_, (_, status)| *status != VrfStatus::Deleting);
            }
        }
    }

    fn check(table: &VrfTable, model: &Model, at: &str) {
        let ids = vrf_ids();
        let all_vnis = vnis();

        // Id index.
        assert_eq!(table.len(), model.len(), "vrf count {at}");
        for id in &ids {
            let Ok(vrf) = table.get_vrf(*id) else {
                assert!(!model.contains_key(id), "vrf {id} missing {at}");
                continue;
            };
            let (vni, status) = model
                .get(id)
                .unwrap_or_else(|| panic!("vrf {id} unexpected {at}"));
            assert_eq!(vrf.vrfid, *id, "vrf {id} filed under the wrong key {at}");
            assert_eq!(vrf.vni, *vni, "vrf {id} vni {at}");
            assert_eq!(vrf.status, *status, "vrf {id} status {at}");
        }

        // Vni index.
        assert_eq!(
            table.by_vni.len(),
            model.values().filter(|(vni, _)| vni.is_some()).count(),
            "vni index size {at}"
        );
        for vni in &all_vnis {
            assert_eq!(
                table.get_vrfid_by_vni(*vni).ok(),
                owner_of(model, *vni),
                "vni {vni} index {at}"
            );
            assert_eq!(
                table.get_vrf_by_vni(*vni).map(|vrf| vrf.vrfid).ok(),
                owner_of(model, *vni),
                "vni {vni} lookup {at}"
            );
        }

        // Fib ids and aliases.
        let fibs = table.fibtablew.enter().unwrap_or_else(|| unreachable!());
        let expected_keys = model.len() + model.values().filter(|(v, _)| v.is_some()).count();
        assert_eq!(fibs.len(), expected_keys, "fib table size {at}");
        for id in &ids {
            let key = FibKey::from_vrfid(*id);
            let Some(fib) = fibs.get_fib(key) else {
                assert!(!model.contains_key(id), "no fib for vrf {id} {at}");
                continue;
            };
            assert!(fib.is_valid(), "fib for vrf {id} is dead {at}");
            assert_eq!(
                fib.get_id(),
                Some(key),
                "fib for vrf {id} is not its own {at}"
            );
        }
        for vni in &all_vnis {
            let Some(fib) = fibs.get_fib(FibKey::from_vni(*vni)) else {
                assert!(owner_of(model, *vni).is_none(), "no fib for vni {vni} {at}");
                continue;
            };
            let owner = owner_of(model, *vni)
                .unwrap_or_else(|| panic!("fib aliased by vni {vni} with no owner {at}"));
            assert!(fib.is_valid(), "fib aliased by vni {vni} is dead {at}");
            assert_eq!(
                fib.get_id(),
                Some(FibKey::from_vrfid(owner)),
                "vni {vni} reaches the wrong fib {at}"
            );
        }
        drop(fibs);

        // Permanent default vrf.
        assert!(table.contains(Vrf::DEFAULT_VRFID), "no default vrf {at}");
        assert_eq!(
            table.get_default_vrf().status,
            VrfStatus::Active,
            "default vrf not active {at}"
        );

        // Built-in consistency check.
        for id in &ids {
            let Some((vni, _)) = model.get(id) else {
                continue;
            };
            assert_eq!(
                table.check_vni(*id).is_ok(),
                vni.is_some(),
                "check_vni disagrees for vrf {id} {at}"
            );
        }
    }

    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(vrf_ids().len(), usize::from(NUM_VRFS));
        assert_eq!(vnis().len(), usize::from(NUM_VNIS));
        assert_eq!(statuses().len(), usize::from(NUM_STATUSES));
        assert_eq!(vrf_ids()[0], Vrf::DEFAULT_VRFID);
    }

    #[test]
    fn a_vrf_tables_four_views_stay_in_step() {
        bolero::check!()
            .with_generator(ChangeSequences)
            .cloned()
            .for_each(|changes: Vec<Change>| {
                let (fibtw, _fibtr) = FibTableWriter::new();
                let (mut iftw, _iftr) = IfTableWriter::new();
                let mut table = VrfTable::new(fibtw);
                let mut model = fresh_model();

                check(&table, &model, "on a fresh table");
                for (step, change) in changes.iter().enumerate() {
                    apply(&mut table, &mut iftw, &mut model, change);
                    check(&table, &model, &format!("at step {step} of {changes:?}"));
                }
            });
    }
}

/// Checks full and selective cross-vrf resolution through the default vrf.
#[cfg(test)]
mod crossvrf_properties {
    use super::*;
    use crate::fib::fibobjects::{EgressObject, FibEntry, PktInstruction};
    use crate::rib::vrf::tests::{build_test_nhop, build_test_route, mk_addr};
    use crate::rib::vrf::{Route, RouteNhop, RouteOrigin};
    use bolero::{Driver, ValueGenerator};
    use lpm::prefix::Prefix;
    use net::interface::InterfaceIndex;
    use std::collections::BTreeMap;
    use std::net::IpAddr;
    use std::ops::Bound::Included;
    use std::str::FromStr;

    const NUM_VRFS: u8 = 2; // non-default vrfs
    const NUM_VNIS: u8 = 2;
    const NUM_UNDERLAY: u8 = 2;
    const NUM_OVERLAY: u8 = 2;
    const NUM_IFINDEXES: u8 = 3;
    const NUM_VIAS: u8 = 3;
    const MAX_ROUTES: u8 = 3;

    fn vrf_ids() -> Vec<VrfId> {
        (1..=u32::from(NUM_VRFS)).collect()
    }

    fn vnis() -> Vec<Vni> {
        (1..=u32::from(NUM_VNIS))
            .map(|i| Vni::new_checked(100 * i).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    fn underlay() -> Vec<Prefix> {
        ["7.0.0.0/8", "7.1.0.0/16"]
            .iter()
            .map(|p| Prefix::from_str(p).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    fn overlay() -> Vec<Prefix> {
        ["10.0.0.0/8", "10.1.0.0/16"]
            .iter()
            .map(|p| Prefix::from_str(p).unwrap_or_else(|_| unreachable!()))
            .collect()
    }

    fn ifindexes() -> Vec<u32> {
        (1..=u32::from(NUM_IFINDEXES)).collect()
    }

    /// On-link addresses make first-interface/last-address merge precedence observable.
    fn onlink_addrs() -> Vec<IpAddr> {
        (1..=NUM_IFINDEXES)
            .map(|i| mk_addr(&format!("7.200.0.{i}")))
            .collect()
    }

    /// The final address is intentionally unreachable through the underlay.
    fn vias() -> Vec<IpAddr> {
        ["7.0.0.1", "7.1.0.1", "8.0.0.1"]
            .iter()
            .map(|a| mk_addr(a))
            .collect()
    }

    #[derive(Debug, Clone)]
    struct Topology {
        vrfs: Vec<bool>,
        underlay: Vec<(usize, usize, bool)>,
        overlay: Vec<(usize, usize, usize)>,
        later: Option<(usize, usize, bool)>,
        selected: Vec<usize>,
    }

    #[derive(Debug, Clone, Copy, Default)]
    struct Topologies;

    fn index<D: Driver>(driver: &mut D, count: u8) -> Option<usize> {
        driver
            .gen_u8(Included(&0), Included(&(count - 1)))
            .map(usize::from)
    }

    impl ValueGenerator for Topologies {
        type Output = Topology;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Topology> {
            let mut vrfs = Vec::with_capacity(usize::from(NUM_VRFS));
            for _ in 0..NUM_VRFS {
                vrfs.push(driver.produce::<bool>()?);
            }

            let count = driver.gen_u8(Included(&0), Included(&MAX_ROUTES))?;
            let mut underlay = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                underlay.push((
                    index(driver, NUM_UNDERLAY)?,
                    index(driver, NUM_IFINDEXES)?,
                    driver.produce::<bool>()?,
                ));
            }

            let count = driver.gen_u8(Included(&0), Included(&MAX_ROUTES))?;
            let mut overlay = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                overlay.push((
                    index(driver, NUM_VRFS)?,
                    index(driver, NUM_OVERLAY)?,
                    index(driver, NUM_VIAS)?,
                ));
            }

            let later = if driver.produce::<bool>()? {
                Some((
                    index(driver, NUM_UNDERLAY)?,
                    index(driver, NUM_IFINDEXES)?,
                    driver.produce::<bool>()?,
                ))
            } else {
                None
            };

            let count = driver.gen_u8(Included(&0), Included(&NUM_VNIS))?;
            let mut selected = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                selected.push(index(driver, NUM_VNIS)?);
            }

            Some(Topology {
                vrfs,
                underlay,
                overlay,
                later,
                selected,
            })
        }
    }

    type Underlay = BTreeMap<usize, (usize, bool)>;

    type Overlay = BTreeMap<(usize, usize), usize>;

    /// Independent longest-prefix-match oracle over the generated underlay.
    fn resolves_to(model: &Underlay, via: usize) -> Option<(u32, bool)> {
        let address = vias()[via];
        let prefixes = underlay();
        model
            .iter()
            .filter(|(prefix, _)| prefixes[**prefix].covers_addr(&address))
            .max_by_key(|(prefix, _)| prefixes[**prefix].length())
            .map(|(_, (ifindex, onlink))| (ifindexes()[*ifindex], *onlink))
    }

    /// Expected entry after resolving an overlay next-hop through the underlay.
    fn expected_entry(model: &Underlay, via: usize) -> FibEntry {
        match resolves_to(model, via) {
            Some((ifindex, onlink)) => {
                let index = usize::try_from(ifindex).unwrap_or_else(|_| unreachable!()) - 1;
                let address = if onlink {
                    onlink_addrs()[index]
                } else {
                    vias()[via]
                };
                FibEntry::with_inst(PktInstruction::Egress(EgressObject::new(
                    InterfaceIndex::try_new(ifindex).ok(),
                    Some(address),
                )))
            }
            None => FibEntry::drop_fibentry(),
        }
    }

    fn underlay_route(ifindex: usize, onlink: bool) -> (Route, Vec<RouteNhop>) {
        let address = onlink.then(|| onlink_addrs()[ifindex].to_string());
        (
            build_test_route(RouteOrigin::Connected, 0, 0),
            vec![build_test_nhop(
                address.as_deref(),
                Some(ifindexes()[ifindex]),
                0,
                None,
            )],
        )
    }

    fn overlay_route(via: usize) -> (Route, Vec<RouteNhop>) {
        (
            build_test_route(RouteOrigin::Bgp, 20, 100),
            vec![build_test_nhop(
                Some(&vias()[via].to_string()),
                None,
                0,
                None,
            )],
        )
    }

    fn realize(topology: &Topology, rstore: &RmacStore) -> (VrfTable, Underlay, Overlay) {
        let (fibtw, _fibtr) = FibTableWriter::new();
        let mut table = VrfTable::new(fibtw);
        let ids = vrf_ids();
        let all_vnis = vnis();

        for (vrf, has_vni) in topology.vrfs.iter().enumerate() {
            let config = RouterVrfConfig::new(ids[vrf], &format!("vrf{vrf}"))
                .set_vni(has_vni.then(|| all_vnis[vrf]));
            table
                .add_vrf(&config)
                .unwrap_or_else(|e| unreachable!("{e}"));
        }

        let mut model = Underlay::new();
        for (prefix, ifindex, onlink) in &topology.underlay {
            let (route, nhops) = underlay_route(*ifindex, *onlink);
            let vrf0 = table
                .get_vrf_mut(Vrf::DEFAULT_VRFID)
                .unwrap_or_else(|e| unreachable!("{e}"));
            vrf0.add_route_complete(&underlay()[*prefix], route, &nhops, None, rstore);
            model.insert(*prefix, (*ifindex, *onlink));
        }

        let mut overlay_model = Overlay::new();
        for (vrf, prefix, via) in &topology.overlay {
            let (route, nhops) = overlay_route(*via);
            // Omit a resolution vrf so only the table-level refresh can resolve this route.
            let target = table
                .get_vrf_mut(ids[*vrf])
                .unwrap_or_else(|e| unreachable!("{e}"));
            target.add_route_complete(&overlay()[*prefix], route, &nhops, None, rstore);
            overlay_model.insert((*vrf, *prefix), *via);
        }

        (table, model, overlay_model)
    }

    fn fib_entries(table: &VrfTable, vrfid: VrfId, prefix: Prefix) -> Option<Vec<FibEntry>> {
        let vrf = table.get_vrf(vrfid).unwrap_or_else(|e| unreachable!("{e}"));
        let fibw = vrf.fibw.as_ref().unwrap_or_else(|| unreachable!());
        let fib = fibw.enter().unwrap_or_else(|| unreachable!());
        let Prefix::IPV4(wanted) = prefix else {
            unreachable!()
        };
        fib.iter_v4().find(|(p, _)| *p == wanted).map(|(_, route)| {
            route
                .iter()
                .flat_map(|group| group.entries().iter().cloned())
                .collect()
        })
    }

    /// Assert the rib-to-fib executable-entry contract across the table.
    fn every_entry_is_executable(table: &VrfTable, at: &str) {
        for vrf in table.values() {
            let fibw = vrf.fibw.as_ref().unwrap_or_else(|| unreachable!());
            let fib = fibw.enter().unwrap_or_else(|| unreachable!());
            for (prefix, route) in fib.iter_v4() {
                for group in route.iter() {
                    assert!(!group.is_empty(), "empty group for {prefix} {at}");
                    for entry in group.iter() {
                        assert!(
                            entry.is_valid(),
                            "vrf {} offers unusable {entry:?} for {prefix} {at}",
                            vrf.vrfid
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_pools_are_the_size_the_generator_thinks() {
        assert_eq!(vrf_ids().len(), usize::from(NUM_VRFS));
        assert_eq!(vnis().len(), usize::from(NUM_VNIS));
        assert_eq!(underlay().len(), usize::from(NUM_UNDERLAY));
        assert_eq!(overlay().len(), usize::from(NUM_OVERLAY));
        assert_eq!(ifindexes().len(), usize::from(NUM_IFINDEXES));
        assert_eq!(vias().len(), usize::from(NUM_VIAS));
        const { assert!(NUM_VNIS >= NUM_VRFS) };
        assert_eq!(onlink_addrs().len(), usize::from(NUM_IFINDEXES));
        let all: Underlay = (0..usize::from(NUM_UNDERLAY))
            .map(|p| (p, (0, false)))
            .collect();
        assert!(resolves_to(&all, usize::from(NUM_VIAS) - 1).is_none());
    }

    #[test]
    fn a_refresh_resolves_other_vrfs_through_the_default_one() {
        let rstore = RmacStore::new();
        bolero::check!()
            .with_generator(Topologies)
            .cloned()
            .for_each(|topology: Topology| {
                let (mut table, model, routes) = realize(&topology, &rstore);
                table.refresh_non_default_fibs(&rstore);
                every_entry_is_executable(&table, "after a refresh");

                let ids = vrf_ids();
                for ((vrf, prefix), via) in &routes {
                    let got = fib_entries(&table, ids[*vrf], overlay()[*prefix])
                        .unwrap_or_else(|| panic!("no fib route for {prefix} in vrf {vrf}"));
                    assert_eq!(
                        got,
                        vec![expected_entry(&model, *via)],
                        "vrf {vrf} prefix {prefix} via {via}, for {topology:?}"
                    );
                }
            });
    }

    #[test]
    fn refreshing_by_vni_touches_only_those_vnis() {
        let rstore = RmacStore::new();
        bolero::check!()
            .with_generator(Topologies)
            .cloned()
            .for_each(|topology: Topology| {
                let Some(later) = topology.later else { return };
                let (mut table, mut model, routes) = realize(&topology, &rstore);
                table.refresh_non_default_fibs(&rstore);

                let ids = vrf_ids();
                let all_vnis = vnis();

                let before: BTreeMap<(usize, usize), Option<Vec<FibEntry>>> = routes
                    .keys()
                    .map(|(vrf, prefix)| {
                        (
                            (*vrf, *prefix),
                            fib_entries(&table, ids[*vrf], overlay()[*prefix]),
                        )
                    })
                    .collect();

                let (prefix, ifindex, onlink) = later;
                let (route, nhops) = underlay_route(ifindex, onlink);
                let vrf0 = table
                    .get_vrf_mut(Vrf::DEFAULT_VRFID)
                    .unwrap_or_else(|e| unreachable!("{e}"));
                vrf0.add_route_complete(&underlay()[prefix], route, &nhops, None, &rstore);
                model.insert(prefix, (ifindex, onlink));

                let selected: Vec<Vni> = topology.selected.iter().map(|i| all_vnis[*i]).collect();
                table.refresh_fibs_by_vni(&selected, &rstore);
                every_entry_is_executable(&table, "after refreshing by vni");

                for ((vrf, prefix), via) in &routes {
                    let got = fib_entries(&table, ids[*vrf], overlay()[*prefix]);
                    let vni = table
                        .get_vrf(ids[*vrf])
                        .unwrap_or_else(|e| unreachable!("{e}"))
                        .vni;
                    if vni.is_some_and(|vni| selected.contains(&vni)) {
                        assert_eq!(
                            got,
                            Some(vec![expected_entry(&model, *via)]),
                            "refreshed vrf {vrf} prefix {prefix}, for {topology:?}"
                        );
                    } else {
                        assert_eq!(
                            got,
                            before[&(*vrf, *prefix)],
                            "untouched vrf {vrf} prefix {prefix}, for {topology:?}"
                        );
                    }
                }
            });
    }

    #[test]
    fn a_stale_sweep_empties_every_vrf() {
        let rstore = RmacStore::new();
        bolero::check!()
            .with_generator(Topologies)
            .cloned()
            .for_each(|topology: Topology| {
                let (mut table, _model, _routes) = realize(&topology, &rstore);
                table.refresh_non_default_fibs(&rstore);

                table.set_stale(true);
                table.remove_stale_routes(&rstore);

                for vrf in table.values() {
                    assert_eq!(vrf.len_v4(), 1, "vrf {} kept ipv4 routes", vrf.vrfid);
                    assert_eq!(vrf.len_v6(), 1, "vrf {} kept ipv6 routes", vrf.vrfid);
                    for prefix in [Prefix::root_v4(), Prefix::root_v6()] {
                        let route = vrf
                            .get_route(prefix)
                            .unwrap_or_else(|| panic!("vrf {} lost {prefix}", vrf.vrfid));
                        assert!(
                            route.is_preset_drop_route(),
                            "vrf {} left {prefix} as something other than the preset drop route",
                            vrf.vrfid
                        );
                    }
                }
                every_entry_is_executable(&table, "after a stale sweep");
            });
    }
}
