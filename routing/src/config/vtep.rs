// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router VTEP configuration

use crate::RouterError;
use crate::{evpn::Vtep, routingdb::RoutingDb};
use tracing::info;

impl Vtep {
    // Apply a vtep configuration. This method can't fail because
    // we validate that the config has a correct vtep
    pub(crate) fn apply(&self, db: &mut RoutingDb) {
        let vtep = &mut db.vtep;
        let (ip) = self.get_ip().unwrap_or_else(|| unreachable!());
        if Some(ip) != vtep.get_ip() {
            vtep.set_ip(ip);
            info!("Updated VTEP ip address set to {ip}");
        }
        let mac = self.get_mac().unwrap_or_else(|| unreachable!());
        if Some(mac) != vtep.get_mac() {
            vtep.set_mac(mac);
            info!("Updated VTEP mac to {mac}");
        }

        // refresh all VRFs
        db.vrftable
            .values_mut()
            .filter(|vrf| {
                let vtep = vrf.get_vtep();
                vrf.vni.is_some() && (vtep != Some(self.clone()))
            })
            .for_each(|vrf| vrf.set_vtep(vtep))
    }
}
