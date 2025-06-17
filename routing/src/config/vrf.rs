// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router VRF configuration

use std::collections::VecDeque;
use std::fmt::Display;
use tracing::debug;

use net::vxlan::Vni;

use crate::RouterError;
use crate::config::RouterConfig;
use crate::rib::vrf::{RouterVrfConfig, VrfId, VrfStatus};
use crate::rib::{Vrf, VrfTable};

/////////////////////////////////////////////////////////////////////////////////////////
/// An operation to set / unset a  [`Vni`] to / from a [`Vrf`]
/////////////////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
enum VniOp {
    Add(Vni),
    Del(Vni),
}

/////////////////////////////////////////////////////////////////////////////////////////
/// An object to represent a programmed change on the [`Vni`] associated to a [`Vrf`]
/////////////////////////////////////////////////////////////////////////////////////////
#[derive(Debug)]
struct VniChange {
    vrfid: VrfId,
    op: VniOp,
}
impl VniChange {
    fn new(vrfid: VrfId, op: VniOp) -> Self {
        Self { vrfid, op }
    }
}
impl Display for VniChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.op {
            VniOp::Add(vni) => writeln!(f, " - Add vni {vni} to vrf {}", self.vrfid),
            VniOp::Del(vni) => writeln!(f, " - Remove vni {vni} from vrf {}", self.vrfid),
        }
    }
}

/////////////////////////////////////////////////////////////////////////////////////////
/// A sequence of [`VniChange`]s to be applied in a certain order
/////////////////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct VniChangePlan(VecDeque<VniChange>);
impl VniChangePlan {
    fn new() -> Self {
        Self(VecDeque::new())
    }
    fn push_front(&mut self, c: VniChange) {
        self.0.push_front(c);
    }
    fn push_back(&mut self, c: VniChange) {
        self.0.push_back(c);
    }
    fn apply(&mut self, vrftable: &mut VrfTable) -> Result<(), RouterError> {
        if self.0.is_empty() {
            debug!("No Vni reconfigurations are required");
            return Ok(());
        }
        debug!("Will apply {} Vni changes...", self.0.len());
        debug!("\n{self}");
        while let Some(change) = self.0.pop_front() {
            match change.op {
                VniOp::Add(vni) => vrftable.set_vni(change.vrfid, vni)?,
                VniOp::Del(_curr) => vrftable.unset_vni(change.vrfid)?,
            }
        }
        Ok(())
    }
}
impl Display for VniChangePlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for change in self.0.iter() {
            change.fmt(f)?;
        }
        Ok(())
    }
}
///////////////////////////////////////////////////////////////////////////////////////
/// Structure used to summarize a plan for reconfiguring [`Vrfs`] given a configuration
/// and the current set of [`Vrf`]s in the [`VrfTable`].
///////////////////////////////////////////////////////////////////////////////////////
pub(crate) struct ReconfigVrfPlan {
    to_keep: Vec<VrfId>,             /* vrfs to keep as is */
    to_delete: Vec<VrfId>,           /* vrfs to delete */
    to_change: Vec<RouterVrfConfig>, /* vrfs to change */
    to_add: Vec<RouterVrfConfig>,    /* vrfs to add */
}

impl ReconfigVrfPlan {
    ///////////////////////////////////////////////////////////////////////////////////
    /// Build a [`ReconfigVrfPlan`] given a [`RouterConfig`] and a [`VrfTable`]
    ///////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn generate(config: &RouterConfig, vrftable: &VrfTable) -> Self {
        let mut to_delete: Vec<VrfId> = vec![];
        let mut to_keep: Vec<VrfId> = vec![];
        let mut to_modify: Vec<RouterVrfConfig> = vec![];
        let mut to_add: Vec<RouterVrfConfig> = vec![];

        for vrf in vrftable.values() {
            let vrfid = vrf.vrfid;
            if let Some(cfg) = config.get_vrf(vrfid) {
                if vrf.as_config() != *cfg {
                    to_modify.push(cfg.clone());
                } else {
                    to_keep.push(vrfid);
                }
            } else if vrfid != 0 {
                // default has vrfid of 0 and should not be deleted
                // if anything, interfaces should be detached
                to_delete.push(vrfid);
            }
        }
        for cfg in config.vrfs() {
            if !vrftable.contains(cfg.vrfid) {
                to_add.push(cfg.clone());
            }
        }
        ReconfigVrfPlan {
            to_keep,
            to_delete,
            to_change: to_modify,
            to_add,
        }
    }

    #[must_use]
    fn enforce_deletions(&self, vrftable: &mut VrfTable) -> Result<(), RouterError> {
        for vrfid in &self.to_delete {
            let vrf = vrftable.get_vrf_mut(*vrfid)?;
            if vrf.status != VrfStatus::Deleted {
                vrf.set_status(VrfStatus::Deleting);
            }
            vrftable.unset_vni(*vrfid)?;
        }
        Ok(())
    }

    #[must_use]
    fn enforce_keeps(&self, vrftable: &mut VrfTable) -> Result<(), RouterError> {
        for vrfid in &self.to_keep {
            let vrf = vrftable.get_vrf_mut(*vrfid)?;
            if vrf.status != VrfStatus::Active {
                vrf.set_status(VrfStatus::Active);
            }
        }
        Ok(())
    }

    #[must_use]
    fn enforce_changes(&self, vrftable: &mut VrfTable) -> Result<(), RouterError> {
        let mut vni_changes = VniChangePlan::new();
        for cfg in &self.to_change {
            if let Ok(vrf) = vrftable.get_vrf_mut(cfg.vrfid) {
                let vrfid = vrf.vrfid;
                // update name if needed
                if vrf.name != cfg.name {
                    vrf.name = cfg.name.clone();
                }
                // update description if needed
                if vrf.description != cfg.description {
                    vrf.description = cfg.description.clone();
                }
                // update table-id id needed
                if vrf.tableid != cfg.tableid {
                    vrf.tableid = cfg.tableid;
                }
                // update vni. This is trickier since Vrfs may be swapping Vnis and there
                // can only be one Vrf with a given vni in the vrftable. Therefore, when
                // a Vrf has to have a vni, we need to make sure that no other vrf that
                // we have not yet updated (reconfigured) has it. For this reason, we need
                // to collect the changes first and apply them in a deferred fashion. The
                // recollection of vni changes is such that removals will be enforced first
                // to ensure that the vni associated to a VRF, configured later, is not in
                // use. Correctness is guaranteed by the fact that no two VPCs in the config
                // can have the same Vni.
                if vrf.vni != cfg.vni {
                    match (vrf.vni, cfg.vni) {
                        (Some(curr), Some(new)) => {
                            vni_changes.push_front(VniChange::new(vrfid, VniOp::Del(curr)));
                            vni_changes.push_back(VniChange::new(vrfid, VniOp::Add(new)));
                        }
                        (None, Some(new)) => {
                            vni_changes.push_back(VniChange::new(vrfid, VniOp::Add(new)));
                        }
                        (Some(curr), None) => {
                            vni_changes.push_front(VniChange::new(vrfid, VniOp::Del(curr)));
                        }
                        (None, None) => {}
                    }
                }
            }
        }
        // apply the required Vni changes
        vni_changes.apply(vrftable)?;
        Ok(())
    }

    #[must_use]
    fn enforce_additions(&self, vrftable: &mut VrfTable) -> Result<(), RouterError> {
        for cfg in &self.to_add {
            vrftable.add_vrf(&cfg)?;
            if let Ok(vrf) = vrftable.get_vrf_mut(cfg.vrfid) {
                if let Some(descr) = &cfg.description {
                    vrf.set_description(descr);
                } else {
                    vrf.description.take();
                }
                if let Some(tableid) = cfg.tableid {
                    vrf.set_tableid(tableid);
                } else {
                    vrf.tableid.take();
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn apply(&self, vrftable: &mut VrfTable) -> Result<(), RouterError> {
        self.enforce_deletions(vrftable)?;
        self.enforce_keeps(vrftable)?;
        self.enforce_changes(vrftable)?;
        self.enforce_additions(vrftable)?;
        debug!("Successfully applied VRF configurations");
        Ok(())
    }
}

impl Vrf {
    ///////////////////////////////////////////////////////////////////////////////////////////
    /// Build the [`RouterVrfConfig`] object that would lead to having a certain [`Vrf`]
    /// in its current state.
    ///////////////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn as_config(&self) -> RouterVrfConfig {
        RouterVrfConfig {
            vrfid: self.vrfid,
            name: self.name.to_owned(),
            description: self.description.to_owned(),
            tableid: self.tableid,
            vni: self.vni,
        }
    }
}
