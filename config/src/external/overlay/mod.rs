// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod tests;
pub mod validation_tests;
pub mod vpc;
pub mod vpcpeering;
pub mod vpcrouting;

use crate::{ConfigError, ConfigResult};
use tracing::{debug, error};
use vpc::VpcTable;
use vpcpeering::{VpcManifest, VpcPeeringTable};

#[derive(Clone, Debug, Default)]
pub struct Overlay {
    pub vpc_table: VpcTable,
    pub peering_table: VpcPeeringTable,
}

impl Overlay {
    #[must_use]
    pub fn new(vpc_table: VpcTable, peering_table: VpcPeeringTable) -> Self {
        Self {
            vpc_table,
            peering_table,
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

    /// Validate the overlay configuration, returning it with the VPC table validated and the
    /// peerings collected into each VPC.
    ///
    /// # Errors
    ///
    /// Returns an error if the overlay configuration is invalid.
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating overlay configuration...");

        // validate peerings:
        self.validate_peering_vpcs()?;

        // Collect peerings for every VPC and validate the table
        let mut vpc_table = self.vpc_table.collect_peerings(&self.peering_table);
        vpc_table.validate()?;
        self.vpc_table = vpc_table;

        debug!("Overlay configuration is VALID:\n{self}");
        Ok(())
    }

    /// FOR TESTS ONLY. Fake validation for the overlay.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_validated_overlay_for_tests(&self) -> Overlay {
        let vpc_table = self.vpc_table.collect_peerings(&self.peering_table);
        let fake_valid_vpc_table = unsafe { vpc_table.fake_validated_vpc_table_for_tests() };
        Overlay {
            vpc_table: fake_valid_vpc_table,
            peering_table: self.peering_table.clone(),
        }
    }

    #[must_use]
    pub fn vpc_table(&self) -> &VpcTable {
        &self.vpc_table
    }
}
