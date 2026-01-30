// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane External/API configuration model. This model is the model assumed by the RPC.

pub mod communities;
pub mod gwgroup;
pub mod overlay;
pub mod underlay;

use crate::internal::device::DeviceConfig;
use crate::{ConfigError, ConfigResult};
use communities::PriorityCommunityTable;
use derive_builder::Builder;
use gwgroup::GwGroupTable;
use overlay::Overlay;
use overlay::vpc::Peering;
use tracing::debug;
use underlay::Underlay;

/// Alias for a config generation number
pub type GenId = i64;

/// The configuration object as seen by the gRPC server
#[derive(Builder, Clone, Debug)]
pub struct ExternalConfig {
    pub gwname: String,                      /* name of gateway */
    pub genid: GenId,                        /* configuration generation id (version) */
    pub device: DeviceConfig,                /* goes as-is into the internal config */
    pub underlay: Underlay,                  /* goes as-is into the internal config */
    pub overlay: Overlay, /* VPCs and peerings -- get highly developed in internal config */
    pub gwgroups: GwGroupTable, /* gateway group table */
    pub communities: PriorityCommunityTable, /* priority-to-community table */
}
impl ExternalConfig {
    pub const BLANK_GENID: GenId = 0;

    #[allow(clippy::new_without_default)]
    #[must_use]
    pub fn new(gwname: &str) -> Self {
        Self {
            gwname: gwname.to_owned(),
            genid: Self::BLANK_GENID,
            device: DeviceConfig::new(),
            underlay: Underlay::default(),
            overlay: Overlay::default(),
            gwgroups: GwGroupTable::new(),
            communities: PriorityCommunityTable::new(),
        }
    }

    /// Check the gateway group for a peering
    fn check_peering_gwgroup(&self, peering: &Peering) -> ConfigResult {
        let gwname = &self.gwname;
        let peering_name = &peering.name;
        let gwgroups = &self.gwgroups;
        let comtable = &self.communities;

        // check that peering refers to a group
        let group_name = peering
            .gwgroup
            .as_ref()
            .ok_or(ConfigError::Incomplete(format!(
                "Peering {} is not mapped to any gateway group",
                peering.name
            )))?;

        // check that such a group exists
        let group = gwgroups
            .get_group(group_name)
            .ok_or_else(|| ConfigError::NoSuchGroup(group_name.to_owned()))?;

        // sort out members
        let group = group.sorted();

        // lookup ourselves in the group
        let Some(rank) = group.get_member_pos(gwname) else {
            // We may not be part of the group serving a peering, which is fine
            return Ok(());
        };

        // we're part of the group. What's our community?
        comtable
            .get_community(rank)
            .ok_or(ConfigError::NoCommunityAvailable(peering_name.clone()))?;

        Ok(())
    }

    fn validate_peering_gw_groups(&self) -> ConfigResult {
        for peering in self.overlay.vpc_table.peerings() {
            self.check_peering_gwgroup(peering)?;
        }
        Ok(())
    }
    pub fn validate(&mut self) -> ConfigResult {
        self.device.validate()?;
        self.underlay.validate()?;
        self.overlay.validate()?;
        self.validate_peering_gw_groups()?;

        // if there are vpcs configured, there MUST be a vtep configured
        if !self.overlay.vpc_table.is_empty() && self.underlay.vtep.is_none() {
            return Err(ConfigError::MissingParameter(
                "Vtep interface configuration",
            ));
        }
        debug!("Community table mappings:\n{}", self.communities);
        debug!("Gateway-groups are:\n{}", self.gwgroups);
        Ok(())
    }
}
