// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router VTEP configuration

use crate::evpn::Vtep;
use crate::routingdb::RoutingDb;
use tracing::debug;

pub(crate) fn apply_vtep_config(vtep: Option<&Vtep>, db: &mut RoutingDb) {
    let current = db.vtep.as_ref();
    match (current, vtep) {
        (Some(old), None) => debug!("VTEP config {old} was removed"),
        (Some(old), Some(new)) if old == new => debug!("VTEP config has not changed"),
        (Some(old), Some(new)) => debug!("VTEP config changed. Previous: {old} new: {new}"),
        (None, Some(new)) => debug!("VTEP config was newly received: {new}"),
        (None, None) => {}
    }
    // update the vrfs
    for vrf in db.vrftable.values_mut() {
        let wanted = vtep.filter(|_| vrf.vni.is_some());
        if vrf.get_vtep().as_ref() != wanted {
            match wanted {
                Some(v) => vrf.set_vtep(v),
                None => vrf.unset_vtep(),
            }
        }
    }
    // store latest config
    db.vtep = vtep.cloned();
}
