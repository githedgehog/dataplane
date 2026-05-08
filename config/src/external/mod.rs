// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane External/API configuration model. This model is the model assumed by the RPC.

pub mod communities;
pub mod gwgroup;
pub mod overlay;
pub mod underlay;

use std::num::NonZero;

use crate::internal::device::DeviceConfig;
use crate::{ConfigError, ConfigResult};
use communities::PriorityCommunityTable;
use derive_builder::Builder;
use gwgroup::GwGroupTable;
use overlay::vpc::Peering;
use overlay::{Overlay, ValidatedOverlay};
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
    #[builder(default)]
    pub flow_table_capacity: Option<NonZero<usize>>, /* optional hard cap of flow table */
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
            flow_table_capacity: None,
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
    /// Validate the external configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if validation fails.
    pub fn validate(&self) -> Result<ValidatedExternalConfig, ConfigError> {
        self.device.validate()?;
        let validated_underlay = self.underlay.validate()?;
        let validated_overlay = self.overlay.validate()?;
        self.validate_peering_gw_groups()?;

        // if there are vpcs configured, there MUST be a vtep configured
        if !validated_overlay.vpc_table().is_empty() && validated_underlay.vtep.is_none() {
            return Err(ConfigError::MissingParameter(
                "Vtep interface configuration",
            ));
        }
        debug!("Community table mappings:\n{}", self.communities);
        debug!("Gateway-groups are:\n{}", self.gwgroups);
        Ok(ValidatedExternalConfig {
            gwname: self.gwname.clone(),
            genid: self.genid,
            device: self.device.clone(),
            underlay: validated_underlay,
            overlay: validated_overlay,
            gwgroups: self.gwgroups.clone(),
            communities: self.communities.clone(),
            flow_table_capacity: self.flow_table_capacity,
        })
    }

    /// FOR TESTS ONLY. Fake validation for the external config.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    ///
    /// # Panics
    ///
    /// May panic if the underlay validation fails.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_validated_external_for_tests(self) -> ValidatedExternalConfig {
        #[allow(clippy::unwrap_used)]
        let validated_underlay = self.underlay.validate().unwrap();
        let fake_valid_overlay = unsafe { self.overlay.fake_validated_overlay_for_tests() };
        ValidatedExternalConfig {
            gwname: self.gwname,
            genid: self.genid,
            device: self.device,
            underlay: validated_underlay,
            overlay: fake_valid_overlay,
            gwgroups: self.gwgroups,
            communities: self.communities,
            flow_table_capacity: self.flow_table_capacity,
        }
    }
}

#[derive(Debug)]
pub struct ValidatedExternalConfig {
    gwname: String,                              /* name of gateway */
    genid: GenId,                                /* configuration generation id (version) */
    device: DeviceConfig,                        /* goes as-is into the internal config */
    underlay: Underlay,                          /* goes as-is into the internal config */
    overlay: ValidatedOverlay, /* VPCs and peerings -- get highly developed in internal config */
    gwgroups: GwGroupTable,    /* gateway group table */
    communities: PriorityCommunityTable, /* priority-to-community table */
    flow_table_capacity: Option<NonZero<usize>>, /* optional hard cap of flow table */
}

impl ValidatedExternalConfig {
    #[must_use]
    pub(crate) fn blank() -> Self {
        Self {
            gwname: String::new(),
            genid: ExternalConfig::BLANK_GENID,
            device: DeviceConfig::new(),
            underlay: Underlay::default(),
            overlay: ValidatedOverlay::blank(),
            gwgroups: GwGroupTable::new(),
            communities: PriorityCommunityTable::new(),
            flow_table_capacity: None,
        }
    }

    #[must_use]
    pub fn gwname(&self) -> &str {
        &self.gwname
    }

    #[must_use]
    pub fn genid(&self) -> GenId {
        self.genid
    }

    #[must_use]
    pub fn device(&self) -> &DeviceConfig {
        &self.device
    }

    #[must_use]
    pub fn underlay(&self) -> &Underlay {
        &self.underlay
    }

    #[must_use]
    pub fn overlay(&self) -> &ValidatedOverlay {
        &self.overlay
    }

    #[must_use]
    pub fn gwgroups(&self) -> &GwGroupTable {
        &self.gwgroups
    }

    #[must_use]
    pub fn communities(&self) -> &PriorityCommunityTable {
        &self.communities
    }

    #[must_use]
    pub fn flow_table_capacity(&self) -> Option<&NonZero<usize>> {
        self.flow_table_capacity.as_ref()
    }
}
