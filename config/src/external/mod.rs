// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane External/API configuration model. This model is the model assumed by the RPC.

pub mod communities;
pub mod gwgroup;
pub mod overlay;
pub mod underlay;

use crate::external::overlay::vpc::Peering;
use crate::internal::device::DeviceConfig;
use crate::{ConfigError, ConfigResult};
use communities::PriorityCommunityTable;
use derive_builder::Builder;
use gwgroup::GwGroupTable;
use overlay::Overlay;
use std::collections::HashSet;
use std::num::NonZero;
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
            device: DeviceConfig::default(),
            underlay: Underlay::default(),
            overlay: Overlay::default(),
            gwgroups: GwGroupTable::default(),
            communities: PriorityCommunityTable::default(),
            flow_table_capacity: None,
        }
    }

    fn validate_gw_groups(&mut self) -> ConfigResult {
        // sort the groups
        self.gwgroups.sort();

        // check that for each group position, a community exists
        for group in self.gwgroups.iter() {
            for member in group.iter() {
                let rank = group
                    .get_member_pos(&member.name)
                    .unwrap_or_else(|| unreachable!());

                self.communities
                    .get_community(rank)
                    .ok_or(ConfigError::NoCommunityAvailable(rank))?;
            }
        }
        Ok(())
    }

    fn check_peering_gwgroups_exist(&self) -> ConfigResult {
        // collect all distinct group names across all peerings
        // Note: this would be faster using the overlay peering table, but
        // we extract the peerings from the vpcs themselves
        let groups: HashSet<_> = self
            .overlay
            .vpc_table()
            .peerings()
            .map(Peering::gwgroup)
            .collect();
        /*
               let groups: HashSet<_> = self
                   .overlay
                   .peering_table
                   .values()
                   .map(|p| p.gwgroup.clone())
                   .collect();
        */
        // check that they are present in the group table
        for group_name in groups {
            self.gwgroups
                .get_group(group_name)
                .ok_or_else(|| ConfigError::NoSuchGroup(group_name.to_owned()))?;
        }
        Ok(())
    }

    /// Validate and enrich the external configuration in place (validating the underlay and
    /// overlay and collecting peerings into each VPC).
    ///
    /// To obtain the runtime [`GwConfig`], validate then wrap: `cfg.validate()?; GwConfig::new(cfg)`.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if validation fails.
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating external config with genid {} ..", self.genid);
        self.device.validate()?;
        self.validate_gw_groups()?;
        self.underlay.validate()?;
        self.overlay.validate()?;
        self.check_peering_gwgroups_exist()?;

        // if there are vpcs configured, there MUST be a vtep configured
        if !self.overlay.vpc_table().is_empty() && self.underlay.vtep.is_none() {
            return Err(ConfigError::MissingParameter(
                "Vtep interface configuration",
            ));
        }
        debug!("Community table:\n{}", self.communities);
        debug!("Gateway-groups are:\n{}", self.gwgroups);
        Ok(())
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
    pub unsafe fn fake_validated_external_for_tests(mut self) -> ExternalConfig {
        #[allow(clippy::unwrap_used)]
        self.underlay.validate().unwrap();
        self.overlay = unsafe { self.overlay.fake_validated_overlay_for_tests() };
        self
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
    pub fn overlay(&self) -> &Overlay {
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
