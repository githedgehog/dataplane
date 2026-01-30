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
use tracing::{debug, info};
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
    fn check_peering_gwgroup(
        gwname: &str,
        gwgroup: &str,
        peering_name: &str,
        gwgroups: &GwGroupTable,
        comtable: &PriorityCommunityTable,
    ) -> Result<Option<String>, ConfigError> {
        debug!("Peering {peering_name} is mapped to gateway group '{gwgroup}'",);

        let group = gwgroups
            .get_group(gwgroup)
            .ok_or_else(|| ConfigError::NoSuchGroup(gwgroup.to_owned()))?;

        // sort out the group. Can't do in place because we don't want to modify the
        // external config received
        let group = group.sorted();

        // lookup ourselves in the group; we care about our position (ranking) in the
        // group and not about the priority whose absolute value is meaningless.
        let Some(pos) = group.get_member_pos(gwname) else {
            info!(
                "Gateway {gwname} is NOT part of group {} to which peering {peering_name} is mapped",
                group.name()
            );
            return Ok(None);
        };
        if pos == 0 {
            info!("This gateway ({gwname}) gateway will serve peering {peering_name}");
        } else {
            info!(
                "This gateway will serve peering {peering_name} if gateway {} fails",
                group
                    .get_member_at(pos - 1)
                    .unwrap_or_else(|| unreachable!())
            );
        }
        let community = comtable
            .get_community(pos)
            .ok_or(ConfigError::NoCommunityAvailable(peering_name.to_string()))?;
        debug!(
            "Will advertise prefixes for peering {} with community {}",
            peering_name, community
        );

        Ok(Some(community.clone()))
    }

    fn validate_peering_gw_groups(&mut self) -> ConfigResult {
        let gwname = &self.gwname;
        let gwgroups = &self.gwgroups;
        let comtable = &self.communities;

        for peering in self.overlay.vpc_table.peerings_mut() {
            let Some(gwgroup) = &peering.gwgroup else {
                return Err(ConfigError::Incomplete(format!(
                    "Peering {} is not mapped to any gateway group",
                    peering.name
                )));
            };
            let opt_community =
                Self::check_peering_gwgroup(gwname, gwgroup, &peering.name, gwgroups, comtable)?;
            if let Some(community) = opt_community {
                debug!(
                    "Assigned community {community} to peering {}",
                    &peering.name
                );
            }
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
