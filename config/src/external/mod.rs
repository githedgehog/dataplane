// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane External/API configuration model. This model is the model assumed by the RPC.

pub mod communities;
pub mod gwgroup;
pub mod overlay;
pub mod underlay;

use crate::ValidatedGwConfig;
use crate::external::overlay::vpc::ValidatedPeering;
use crate::internal::device::DeviceConfig;
use crate::{ConfigError, ConfigResult};
use communities::PriorityCommunityTable;
use derive_builder::Builder;
use gwgroup::GwGroupTable;
use overlay::{Overlay, ValidatedOverlay};
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
            device: DeviceConfig::new(),
            underlay: Underlay::default(),
            overlay: Overlay::default(),
            gwgroups: GwGroupTable::new(),
            communities: PriorityCommunityTable::new(),
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

    fn check_peering_gwgroups_exist<'a>(
        &self,
        peerings: impl Iterator<Item = &'a ValidatedPeering>,
    ) -> ConfigResult {
        // collect all distinct group names across all peerings
        let groups: HashSet<_> = peerings
            .into_iter()
            .map(ValidatedPeering::gwgroup)
            .collect();

        // check that they are present in the group table
        for group_name in groups {
            self.gwgroups
                .get_group(group_name)
                .ok_or_else(|| ConfigError::NoSuchGroup(group_name.to_owned()))?;
        }
        Ok(())
    }

    /// Refuse a peering *this* gateway would have to render and cannot.
    ///
    /// The routing configuration built from a peering is IPv4-only: its prefix lists and
    /// route-maps are `IpVer::V4` throughout and nothing in the builder has a v6
    /// counterpart. `build_internal_config` used to be where that was discovered, which
    /// made it a refusal at apply time: the configuration was accepted, reported good to
    /// whoever submitted it, and then rejected as a whole when it was applied, taking its
    /// IPv4 vpcs with it. Anything accepted here has to apply cleanly, so the refusal
    /// belongs here.
    ///
    /// The predicate has to be the builder's, though, and not "any IPv6 peering
    /// anywhere". `build_routing_config` renders a peering only when this gateway is a
    /// member of the group the peering names and a community exists for its rank, and
    /// `build_internal_config` skips the overlay entirely when the underlay carries no
    /// BGP. A peering outside all of that is never rendered, so it cannot fail to render,
    /// and refusing it would reject a configuration over an IPv6 peering some *other*
    /// gateway is responsible for -- taking this gateway's own IPv4 peerings down with
    /// it, for a configuration that built perfectly well before.
    ///
    /// It belongs here, and not on `Peering` or `Overlay`, for a related reason: the
    /// limitation is the gateway's and not the overlay model's. The ACL filter builds
    /// from a `ValidatedOverlay` and handles IPv6 perfectly well, and twelve of its tests
    /// say so.
    ///
    /// `Peering::validate` has already established that a peering's two manifests agree
    /// on their IP version, so `is_v4` speaks for the whole peering.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Unsupported`] if a peering this gateway renders carries
    /// IPv6 prefixes.
    fn check_rendered_peerings_are_ipv4(
        gwname: &str,
        overlay: &ValidatedOverlay,
        underlay: &Underlay,
        gwgroups: &GwGroupTable,
        communities: &PriorityCommunityTable,
    ) -> ConfigResult {
        if underlay.vrf.bgp.is_none() {
            // No underlay BGP means no overlay routing configuration is built at all.
            return Ok(());
        }
        let renders = |peering: &ValidatedPeering| {
            gwgroups
                .get_group_member_rank(peering.gwgroup(), gwname)
                .is_some_and(|rank| communities.get_community(rank).is_some())
        };
        if overlay
            .vpc_table()
            .peerings()
            .filter(|peering| renders(peering))
            .all(ValidatedPeering::is_v4)
        {
            return Ok(());
        }
        Err(ConfigError::Unsupported(
            "IPv6 prefixes in a vpc peering: the routing configuration built from a peering is \
             IPv4-only, so such a peering cannot be rendered",
        ))
    }

    /// Validate the external configuration.
    /// This method consumes `ExternalConfig` and outputs a `ValidatedGwConfig` on success.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if validation fails.
    pub fn validate(mut self) -> Result<ValidatedGwConfig, ConfigError> {
        debug!("Validating external config with genid {} ..", self.genid);
        self.device.validate()?;
        self.validate_gw_groups()?;
        let underlay = self.underlay.validate()?;
        let overlay = self.overlay.validate()?;
        let peerings = overlay.vpc_table().peerings();
        self.check_peering_gwgroups_exist(peerings)?;
        Self::check_rendered_peerings_are_ipv4(
            &self.gwname,
            &overlay,
            &underlay,
            &self.gwgroups,
            &self.communities,
        )?;

        // if there are vpcs configured, there MUST be a vtep configured
        if !overlay.vpc_table().is_empty() && underlay.vtep.is_none() {
            return Err(ConfigError::MissingParameter(
                "Vtep interface configuration",
            ));
        }
        let validated_external = ValidatedExternalConfig {
            gwname: self.gwname,
            genid: self.genid,
            device: self.device,
            underlay,
            overlay,
            gwgroups: self.gwgroups,
            communities: self.communities,
            flow_table_capacity: self.flow_table_capacity,
        };
        debug!("Community table:\n{}", validated_external.communities());
        debug!("Gateway-groups are:\n{}", validated_external.gwgroups);
        Ok(ValidatedGwConfig::new(validated_external))
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
            overlay: ValidatedOverlay::default(),
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
