// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router interface configuration

use crate::RouterError;
use crate::config::RouterConfig;
use crate::interfaces::iftable::IfTable;
use net::interface::InterfaceIndex;
#[allow(unused)]
use tracing::debug;

use crate::interfaces::iftablerw::IfTableWriter;
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
    /// Build a [`ReconfigInterfacePlan`] given a [`RouterConfig`] and an [`IfTable`]
    ///////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    pub(crate) fn generate(config: &RouterConfig, iftable: &IfTable) -> Self {
        let mut to_delete: Vec<InterfaceIndex> = vec![];
        let mut to_keep: Vec<InterfaceIndex> = vec![];
        let mut to_modify: Vec<RouterInterfaceConfig> = vec![];
        let mut to_add: Vec<RouterInterfaceConfig> = vec![];

        for iface in iftable.values() {
            let ifindex = iface.ifindex;
            if let Some(cfg) = config.get_interface(ifindex) {
                if iface.as_config() != *cfg {
                    to_modify.push(cfg.clone());
                } else {
                    to_keep.push(ifindex);
                }
            } else {
                to_delete.push(ifindex);
            }
        }
        for cfg in config.interfaces() {
            if !iftable.contains(cfg.ifindex.into()) {
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

    fn enforce_deletions(&self, iftw: &mut IfTableWriter) -> Result<(), RouterError> {
        for ifindex in &self.to_delete {
            iftw.del_interface((*ifindex).into());
        }
        Ok(())
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
                Some(AttachConfig::VRF(vrfid)) => {
                    iftw.attach_interface_to_vrf(ifconfig.ifindex, vrfid, vrftable)?
                }
                Some(AttachConfig::BD) => todo!(),
                _ => {}
            };
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
                None => iftw.detach_interface(ifconfig.ifindex),
                Some(AttachConfig::VRF(vrfid)) => {
                    iftw.attach_interface_to_vrf(ifconfig.ifindex, vrfid, vrftable)?
                }
                Some(AttachConfig::BD) => todo!(),
            };
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn apply(
        &self,
        iftw: &mut IfTableWriter,
        vrftable: &VrfTable,
    ) -> Result<(), RouterError> {
        self.enforce_deletions(iftw)?;
        self.enforce_changes(iftw, vrftable)?;
        self.enforce_additions(iftw, vrftable)?;
        debug!("Successfully applied Interface configurations");
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
            description: self.description.to_owned(),
            iftype: self.iftype.clone(),
            admin_state: self.admin_state,
            mtu: self.mtu,
            attach_cfg: self
                .attachment
                .as_ref()
                .map(|attachment| attachment.as_config()),
        }
    }
}

impl Attachment {
    #[must_use]
    pub(crate) fn as_config(&self) -> AttachConfig {
        match self {
            // FIXME: this should always be FibKey::Id
            Attachment::VRF(fibkey) => AttachConfig::VRF(fibkey.as_u32()),
            Attachment::BD => AttachConfig::BD,
        }
    }
}
