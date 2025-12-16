// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane External/API configuration model. This model is the model assumed by the RPC.

pub mod communities;
pub mod gwgroup;
pub mod overlay;
pub mod underlay;

use crate::internal::device::DeviceConfig;
use crate::internal::device::settings::DeviceSettings;
use crate::{ConfigError, ConfigResult};
use communities::PriorityCommunityTable;
use derive_builder::Builder;
use gwgroup::GwGroupTable;
use gwname::get_gw_name;
use overlay::Overlay;
use tracing::{debug, warn};
use underlay::Underlay;

/// Alias for a config generation number
pub type GenId = i64;

/// The configuration object as seen by the gRPC server
#[derive(Builder, Clone, Debug)]
pub struct ExternalConfig {
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
    pub fn new() -> Self {
        Self {
            genid: Self::BLANK_GENID,
            device: DeviceConfig::new(DeviceSettings::new("Unset")),
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
        debug!("Peering {peering_name} is to be handled by gateway group '{gwgroup}'",);

        // lookup group referred by peering: it must exist
        let group = gwgroups
            .get_group(gwgroup)
            .ok_or_else(|| ConfigError::NoSuchGroup(gwgroup.to_owned()))?;

        // sort out the group. Can't do in place because we don't want to modify the
        // external config received
        let group = group.sorted();

        // lookup ourselves in the group; we care about our position (ranking) in the
        // group and not about the priority whose absolute value is meaningless.
        let Some(pos) = group.get_member_pos(gwname) else {
            warn!("Gateway {gwname} is NOT part of group {}", group.name());
            return Ok(None);
        };
        // need conversion to u32 as that is the key for the community table
        let pos = u32::try_from(pos).map_err(|e| ConfigError::InternalFailure(e.to_string()))?;

        // We should be serving this peering.
        debug!("Gateway {gwname} is at position {pos} of {}", group.name());

        // Get the community corresponding to the position/ordering of this gateway in the group.
        // If no community exist for that position, we should fail, although we don't now since
        // the community table may not be populated.
        // To guarantee that we can always tag with a community in the set of |C| communities,
        // the size of a group |G| must be no larger than |C|.
        if let Ok(community) = comtable.get_community(pos) {
            Ok(Some(community.clone()))
        } else {
            warn!("No community found for preference {pos}");
            Ok(None)
        }
    }

    fn validate_peering_gw_groups(&mut self) -> ConfigResult {
        let gwname = get_gw_name().unwrap_or_else(|| unreachable!());
        let gwgroups = &self.gwgroups;
        let comtable = &self.communities;
        for vpc in self.overlay.vpc_table.values_mut() {
            for peering in &mut vpc.peerings {
                if let Some(gwgroup) = &peering.gwgroup
                    && let Some(community) = Self::check_peering_gwgroup(
                        gwname,
                        gwgroup,
                        &peering.name,
                        gwgroups,
                        comtable,
                    )?
                {
                    debug!(
                        "Assigned community {community} to peering {}",
                        &peering.name
                    );
                    peering.adv_communities.push(community.clone());
                }
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
