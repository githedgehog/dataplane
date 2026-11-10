// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router interface configuration

use crate::RouterError;
use crate::interfaces::iftable::IfTable;
use net::interface::InterfaceIndex;
use std::collections::BTreeMap;
#[allow(unused)]
use tracing::debug;

use crate::interfaces::iftablerw::{IfTableWriter, IfUpdate};
use crate::interfaces::interface::{AttachConfig, Attachment};
use crate::interfaces::interface::{Interface, RouterInterfaceConfig};
use crate::rib::VrfTable;
///////////////////////////////////////////////////////////////////////////////////////
/// Structure used to summarize a plan for reconfiguring [`Interface`]s
///////////////////////////////////////////////////////////////////////////////////////
pub(crate) struct ReconfigInterfacePlan {
    #[allow(unused)]
    to_keep: Vec<InterfaceIndex>, /* interfaces to keep as is */
    to_delete: Vec<InterfaceIndex>,        /* interfaces to delete */
    to_modify: Vec<RouterInterfaceConfig>, /* interfaces to change */
    to_add: Vec<RouterInterfaceConfig>,    /* interfaces to add */
}

impl ReconfigInterfacePlan {
    ///////////////////////////////////////////////////////////////////////////////////
    /// Build a [`ReconfigInterfacePlan`] given the interfaces a [`RouterConfig`] requires and an
    /// [`IfTable`]
    ///////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn generate(
        config: &BTreeMap<InterfaceIndex, RouterInterfaceConfig>,
        iftable: &IfTable,
    ) -> Self {
        let mut to_delete: Vec<InterfaceIndex> = vec![];
        let mut to_keep: Vec<InterfaceIndex> = vec![];
        let mut to_modify: Vec<RouterInterfaceConfig> = vec![];
        let mut to_add: Vec<RouterInterfaceConfig> = vec![];

        for iface in iftable.values() {
            let ifindex = iface.ifindex;
            if let Some(cfg) = config.get(&ifindex) {
                if iface.as_config() == *cfg {
                    to_keep.push(ifindex);
                } else {
                    to_modify.push(cfg.clone());
                }
            } else {
                to_delete.push(ifindex);
            }
        }
        for cfg in config.values() {
            if !iftable.contains(cfg.ifindex) {
                to_add.push(cfg.clone());
            }
        }
        ReconfigInterfacePlan {
            to_keep,
            to_delete,
            to_modify,
            to_add,
        }
    }

    /// What this plan changes in the link state of interfaces already in `iftable`.
    pub(crate) fn link_changes(&self, iftable: &IfTable) -> Vec<IfUpdate> {
        let mut changes = vec![];
        for new in &self.to_modify {
            let Some(old) = iftable.get_interface(new.ifindex) else {
                continue;
            };
            let mut update = IfUpdate::new(new.ifindex, &new.name)
                .check_ifname(&old.name, &new.name)
                .check_adm_state(old.admin_state, new.admin_state);
            if let (Some(old_mac), Some(new_mac)) = (old.get_mac(), new.iftype.get_mac()) {
                update = update.check_mac(old_mac, new_mac);
            }
            changes.push(update);
        }
        changes
    }

    fn enforce_deletions(&self, iftw: &mut IfTableWriter) {
        for ifindex in &self.to_delete {
            let _ = iftw.del_interface(*ifindex);
        }
    }
    fn enforce_additions(
        &self,
        iftw: &mut IfTableWriter,
        vrftable: &VrfTable,
    ) -> Result<(), RouterError> {
        for ifconfig in &self.to_add {
            iftw.add_interface(ifconfig.clone())?;
            // attach
            match ifconfig.attach_cfg {
                Some(AttachConfig::Vrf(vrfid)) => {
                    iftw.attach_interface_to_vrf(ifconfig.ifindex, vrfid, vrftable)?;
                }
                Some(AttachConfig::BridgeDomain) => todo!(),
                _ => {}
            }
        }
        Ok(())
    }
    fn enforce_changes(
        &self,
        iftw: &mut IfTableWriter,
        vrftable: &VrfTable,
    ) -> Result<(), RouterError> {
        for ifconfig in &self.to_modify {
            debug!("Interface w/ ifindex {} requires changes", ifconfig.ifindex);
            iftw.mod_interface(ifconfig.clone())?;
            // attach / re-attach / detach
            match ifconfig.attach_cfg {
                None => {
                    let _ = iftw.detach_interface(ifconfig.ifindex);
                }
                Some(AttachConfig::Vrf(vrfid)) => {
                    iftw.attach_interface_to_vrf(ifconfig.ifindex, vrfid, vrftable)?;
                }
                Some(AttachConfig::BridgeDomain) => todo!(),
            }
        }
        Ok(())
    }

    pub(crate) fn apply(
        &self,
        iftw: &mut IfTableWriter,
        vrftable: &VrfTable,
    ) -> Result<(), RouterError> {
        self.enforce_deletions(iftw);
        self.enforce_changes(iftw, vrftable)?;
        self.enforce_additions(iftw, vrftable)?;
        debug!("Successfully applied interface configurations");
        Ok(())
    }
}

impl Interface {
    ///////////////////////////////////////////////////////////////////////////////////////////
    /// Build the [`RouterInterfaceConfig`] object that would lead to having a certain [`Interface`]
    /// in its current state.
    ///////////////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn as_config(&self) -> RouterInterfaceConfig {
        RouterInterfaceConfig {
            ifindex: self.ifindex,
            name: self.name.clone(),
            description: self.description.clone(),
            iftype: self.iftype.clone(),
            admin_state: self.admin_state,
            mtu: self.mtu,
            attach_cfg: self.attachment.as_ref().map(Attachment::as_config),
        }
    }
}

impl Attachment {
    #[must_use]
    pub(crate) fn as_config(&self) -> AttachConfig {
        match self {
            Attachment::Vrf(vrfid) => AttachConfig::Vrf(*vrfid),
            Attachment::BridgeDomain => AttachConfig::BridgeDomain,
        }
    }
}
