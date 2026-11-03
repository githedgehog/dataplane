// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod acl;
#[cfg(any(test, feature = "bolero"))]
pub mod algebra;
#[cfg(test)]
mod completeness;
pub mod ingress;
pub mod ratelimit;
pub mod tests;
pub mod validation_tests;
pub mod vpc;
pub mod vpcpeering;
pub mod vpcrouting;

use crate::{ConfigError, ConfigResult};
use ingress::{IngressPolicy, ValidatedIngressPolicy};
use ratelimit::{RateLimitTables, ValidatedRateLimitTables};
use tracing::{debug, error};
use vpc::{ValidatedVpcTable, VpcTable};
use vpcpeering::{VpcManifest, VpcPeeringTable};

#[derive(Clone, Debug, Default)]
pub struct Overlay {
    pub vpc_table: VpcTable,
    pub peering_table: VpcPeeringTable,
    pub rate_limits: RateLimitTables,
    /// Gateway-wide rules on traffic as it arrives from a VPC, ahead of everything else.
    pub ingress: IngressPolicy,
    /// Keep the gateway's policy out of its NICs: enforce everything in software alone. Off, a
    /// capable NIC enforces what it can of the policy in front of software.
    pub disable_offloads: bool,
}

impl Overlay {
    #[must_use]
    pub fn new(vpc_table: VpcTable, peering_table: VpcPeeringTable) -> Self {
        Self {
            vpc_table,
            peering_table,
            rate_limits: RateLimitTables::default(),
            ingress: IngressPolicy::default(),
            disable_offloads: false,
        }
    }

    /// The same overlay, with `rate_limits`.
    #[must_use]
    pub fn with_rate_limits(self, rate_limits: RateLimitTables) -> Self {
        Self {
            rate_limits,
            ..self
        }
    }

    /// The same overlay, with `ingress`.
    #[must_use]
    pub fn with_ingress(self, ingress: IngressPolicy) -> Self {
        Self { ingress, ..self }
    }

    /// The same overlay, with NIC offload turned off if `disabled`.
    #[must_use]
    pub fn with_offloads_disabled(self, disabled: bool) -> Self {
        Self {
            disable_offloads: disabled,
            ..self
        }
    }

    /// Check if a `Vpc` referred in a peering exists
    fn check_peering_vpc(&self, peering: &str, manifest: &VpcManifest) -> ConfigResult {
        self.vpc_table.get_vpc(&manifest.name).ok_or_else(|| {
            error!("peering '{}': unknown VPC '{}'", peering, manifest.name);
            ConfigError::NoSuchVpc(manifest.name.clone())
        })?;
        Ok(())
    }

    /// Validate all peerings: check if the VPCs they refer to exist in vpc table
    fn validate_peering_vpcs(&self) -> ConfigResult {
        debug!("Validating VPC peerings...");
        for peering in self.peering_table.values() {
            self.check_peering_vpc(&peering.name, &peering.left)?;
            self.check_peering_vpc(&peering.name, &peering.right)?;
        }
        Ok(())
    }

    /// Validate the overlay configuration, returning a `ValidatedOverlay` if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the overlay configuration is invalid.
    pub fn validate(&self) -> Result<ValidatedOverlay, ConfigError> {
        debug!("Validating overlay configuration...");

        // validate peerings:
        self.validate_peering_vpcs()?;

        // Collect peerings for every VPC and validate the table
        let vpc_table = self
            .vpc_table
            .collect_peerings(&self.peering_table)
            .validate()?;

        let rate_limits = self.rate_limits.validate(&vpc_table)?;
        let ingress = self.ingress.validate(&vpc_table)?;

        let validated_overlay = ValidatedOverlay {
            vpc_table,
            rate_limits,
            ingress,
            disable_offloads: self.disable_offloads,
        };

        let peering_table = &self.peering_table;
        debug!("Overlay configuration is VALID:\n{validated_overlay}\n{peering_table}");
        Ok(validated_overlay)
    }
}

#[derive(Debug, Default)]
pub struct ValidatedOverlay {
    vpc_table: ValidatedVpcTable,
    rate_limits: ValidatedRateLimitTables,
    ingress: ValidatedIngressPolicy,
    disable_offloads: bool,
}

impl ValidatedOverlay {
    #[must_use]
    pub fn vpc_table(&self) -> &ValidatedVpcTable {
        &self.vpc_table
    }

    #[must_use]
    pub fn rate_limits(&self) -> &ValidatedRateLimitTables {
        &self.rate_limits
    }

    #[must_use]
    pub fn ingress(&self) -> &ValidatedIngressPolicy {
        &self.ingress
    }

    /// Whether the gateway's policy stays out of its NICs.
    #[must_use]
    pub fn offloads_disabled(&self) -> bool {
        self.disable_offloads
    }
}
