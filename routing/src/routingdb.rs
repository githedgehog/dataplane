// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Routing database keeps most of the routing information in memory

use crate::errors::RouterError;
use crate::interface::IfTable;
use crate::rmac::RmacStore;
use crate::vrf::{Vrf, VrfId};
use net::vxlan::Vni;
use std::collections::HashMap;
use std::collections::hash_map;
use std::sync::Arc;
use std::sync::RwLock;

pub struct VrfTable {
    by_id: HashMap<VrfId, Arc<RwLock<Vrf>>>,
    by_vni: HashMap<Vni, Arc<RwLock<Vrf>>>,
}

#[allow(dead_code)]
#[allow(clippy::new_without_default)]
#[allow(clippy::len_without_is_empty)]
/// Table of VRFs. All VRFs in the system are represented here.
/// Every VRF is uniquely identified by a vrfId, which acts as the master key.
/// Vrfs that have a VNI associated can also be looked up by VNI.
impl VrfTable {
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            by_vni: HashMap::new(),
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Create a new VRF with some name and Id, and optional Vni.
    //////////////////////////////////////////////////////////////////
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

        /* Build new VRF */
        let mut vrf = Vrf::new(name, vrfid);
        if let Some(vni) = vni_checked {
            vrf.set_vni(vni);
        }

        let vrf = Arc::new(RwLock::new(vrf));
        self.by_id.entry(vrfid).or_insert(vrf.clone());
        if let Some(vni) = vni_checked {
            self.by_vni.entry(vni).insert_entry(vrf.clone());
        }
        Ok(vrf)
    }

    //////////////////////////////////////////////////////////////////
    /// Remove the vrf with the given id
    //////////////////////////////////////////////////////////////////
    pub fn remove_vrf(&mut self, vrfid: VrfId, iftable: &mut IfTable) -> Result<(), RouterError> {
        if let Some(vrf) = self.by_id.remove(&vrfid) {
            iftable.detach_vrf_interfaces(&vrf);
            #[allow(clippy::collapsible_if)]
            if let Ok(vrf) = vrf.read() {
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
    /// Calling read() or write() on the resulting Ok value acquire a
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
    pub iftable: RwLock<IfTable>,
    pub rmac_store: RwLock<RmacStore>,
}
#[allow(unused)]
#[allow(clippy::new_without_default)]
impl RoutingDb {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            vrftable: RwLock::new(VrfTable::new()),
            iftable: RwLock::new(IfTable::new()),
            rmac_store: RwLock::new(RmacStore::new()),
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;
    use crate::interface::tests::build_test_iftable;

    #[test]
    fn vrf_table() {
        let mut vrftable = VrfTable::new();
        let mut iftable = build_test_iftable();

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
        let eth0 = iftable.get_interface_mut(2).expect("Should be there");
        eth0.attach(&vrf0).expect("Should succeed");

        let eth1 = iftable.get_interface_mut(3).expect("Should be there");
        eth1.attach(&vrf0).expect("Should succeed");

        let vlan100 = iftable.get_interface_mut(4).expect("Should be there");
        vlan100.attach(&vrf1).expect("Should succeed");

        let vlan200 = iftable.get_interface_mut(5).expect("Should be there");
        vlan200.attach(&vrf1).expect("Should succeed");

        /* remove VRFs 0 - interfaces should be automatically detached */
        let _ = vrftable.remove_vrf(0, &mut iftable);
        assert!(
            vrftable
                .get_vrf(0)
                .is_err_and(|e| e == RouterError::NoSuchVrf)
        );
        let eth0 = iftable.get_interface(2).expect("Should be there");
        assert!(eth0.vrf.is_none(), "Eth0 should be detached");
        let eth1 = iftable.get_interface(3).expect("Should be there");
        assert!(eth1.vrf.is_none(), "Eth1 should be detached");

        /* remove VRFs 1 - interfaces should be automatically detached */
        let _ = vrftable.remove_vrf(1, &mut iftable);
        assert!(
            vrftable
                .get_vrf(1)
                .is_err_and(|e| e == RouterError::NoSuchVrf)
        );
        let vlan100 = iftable.get_interface(4).expect("Should be there");
        assert!(vlan100.vrf.is_none(), "vlan100 should be detached");
        let vlan200 = iftable.get_interface(5).expect("Should be there");
        assert!(vlan200.vrf.is_none(), "vlan200 should be detached");

        /* Should be gone from by_vni map */
        assert!(
            vrftable
                .get_vrf_by_vni(3000)
                .is_err_and(|e| e == RouterError::NoSuchVrf),
        );
    }
}
