// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Routing database keeps most of the routing information in memory

use crate::errors::RouterError;
use crate::interface::IfTable;
use crate::vrf::{Vrf, VrfId};

use std::collections::HashMap;
use std::sync::Arc;

use net::vxlan::Vni;

pub struct VrfTable {
    by_id: HashMap<VrfId, Arc<Vrf>>,
    by_vni: HashMap<Vni, Arc<Vrf>>,
}

#[allow(dead_code)]
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
    ) -> Result<Arc<Vrf>, RouterError> {
        /* Check Vni if provided */
        let vni_checked = if let Some(vni) = vni {
            Some(Vni::new_checked(vni).map_err(|_| RouterError::VniInvalid(vni))?)
        } else {
            None
        };

        /* Forbid VRF addition if one exists with same id or same vni */
        if self.by_id.contains_key(&vrfid) {
            return Err(RouterError::VrfExists(vrfid));
        } else if let Some(vni) = &vni_checked {
            if self.by_vni.contains_key(vni) {
                return Err(RouterError::VniInUse(vni.as_u32()));
            }
        }

        /* Build new VRF */
        let mut vrf = Vrf::new(name, vrfid);
        if let Some(vni) = vni_checked {
            vrf.set_vni(vni);
        }
        #[allow(clippy::arc_with_non_send_sync)]
        let vrf = Arc::new(vrf);
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
            iftable.detach_vrf_interfaces(vrfid);
            if let Some(vni) = vrf.vni {
                self.by_vni.remove(&vni);
            }
            Ok(())
        } else {
            Err(RouterError::NoSuchVrf)
        }
    }

    pub fn get_vrf(&self, vrfid: VrfId) -> Result<&Arc<Vrf>, RouterError> {
        if let Some(vrf) = self.by_id.get(&vrfid) {
            Ok(vrf)
        } else {
            Err(RouterError::NoSuchVrf)
        }
    }

    pub fn get_vrf_by_vni(&self, vni: u32) -> Result<&Arc<Vrf>, RouterError> {
        let vni = Vni::new_checked(vni).map_err(|_| RouterError::VniInvalid(vni))?;
        if let Some(vrf) = self.by_vni.get(&vni) {
            Ok(vrf)
        } else {
            Err(RouterError::NoSuchVrf)
        }
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use std::ops::Deref;

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
        assert!(vrftable
            .add_vrf("duped-id", 1, None)
            .is_err_and(|e| e == RouterError::VrfExists(1)));

        /* attempt to add VRF with unused id but used vni */
        assert!(vrftable
            .add_vrf("duped-vni", 999, Some(3000))
            .is_err_and(|e| e == RouterError::VniInUse(3000)));

        /* get VRF (by vrfid) */
        let vrf3 = vrftable.get_vrf(3).expect("Should be there");
        assert_eq!(vrf3.deref().name, "VPC-3");

        /* get VRF (by vni) */
        let vrf3 = vrftable.get_vrf_by_vni(5000).expect("Should be there");
        assert_eq!(vrf3.deref().name, "VPC-3");

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
        assert!(vrftable
            .get_vrf(0)
            .is_err_and(|e| e == RouterError::NoSuchVrf));
        let eth0 = iftable.get_interface(2).expect("Should be there");
        assert!(eth0.vrf.is_none(), "Eth0 should be detached");
        let eth1 = iftable.get_interface(3).expect("Should be there");
        assert!(eth1.vrf.is_none(), "Eth1 should be detached");

        /* remove VRFs 1 - interfaces should be automatically detached */
        let _ = vrftable.remove_vrf(1, &mut iftable);
        assert!(vrftable
            .get_vrf(1)
            .is_err_and(|e| e == RouterError::NoSuchVrf));
        assert!(
            vrftable
                .get_vrf_by_vni(3000)
                .is_err_and(|e| e == RouterError::NoSuchVrf),
            "Should be gone"
        );
        let vlan100 = iftable.get_interface(4).expect("Should be there");
        assert!(vlan100.vrf.is_none(), "vlan100 should be detached");
        let vlan200 = iftable.get_interface(5).expect("Should be there");
        assert!(vlan200.vrf.is_none(), "vlan200 should be detached");
    }
}
