// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod tests;
pub mod validation_tests;
pub mod vpc;
pub mod vpcpeering;

use crate::{ConfigError, ConfigResult};
use tracing::{debug, error};
use vpc::{ValidatedVpcTable, VpcIdMap, VpcTable};
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

    /// Validate all peerings, checking if the VPCs they refer to exist in vpc table
    ///
    /// # Errors
    ///
    /// Returns an error if a peering references a VPC that does not exist in the VPC table.
    pub fn validate_peerings(&self) -> ConfigResult {
        debug!("Validating VPC peerings...");
        for peering in self.peering_table.values() {
            self.check_peering_vpc(&peering.name, &peering.left)?;
            self.check_peering_vpc(&peering.name, &peering.right)?;
        }
        Ok(())
    }

    /// Build a `VpcIdMap`. We have already checked that all VPC Ids are distinct
    #[must_use]
    pub(crate) fn vpcid_map(&self) -> VpcIdMap {
        let id_map: VpcIdMap = self
            .vpc_table
            .values()
            .map(|vpc| (vpc.name.clone(), vpc.id.clone()))
            .collect();
        id_map
    }

    /// Validate the overlay configuration, returning a `ValidatedOverlay` if successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the overlay configuration is invalid.
    pub fn validate(&self) -> Result<ValidatedOverlay, ConfigError> {
        debug!("Validating overlay configuration...");

        self.validate_peerings()?;

        // Collect peerings for every VPC and validate the table
        let validated_vpc_table = self.collect_peerings().validate()?;

        let validated_overlay = ValidatedOverlay {
            vpc_table: validated_vpc_table,
            peering_table: self.peering_table.clone(),
        };

        debug!("Overlay configuration is VALID:\n{validated_overlay}");
        Ok(validated_overlay)
    }

    /// Collect peerings from the peering table for every VPC.
    ///
    /// Should only be called in `validate`, or in tests.
    pub(crate) fn collect_peerings(&self) -> VpcTable {
        let id_map = self.vpcid_map();
        self.vpc_table
            .collect_peerings(&self.peering_table, &id_map)
    }

    /// FOR TESTS ONLY. Fake validation for the overlay.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_validated_overlay_for_tests(&self) -> ValidatedOverlay {
        let vpc_table = self.collect_peerings();
        let fake_valid_vpc_table = unsafe { vpc_table.fake_validated_vpc_table_for_tests() };
        ValidatedOverlay {
            vpc_table: fake_valid_vpc_table,
            peering_table: self.peering_table.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedOverlay {
    vpc_table: ValidatedVpcTable,
    // Note: unlike the vpc_table, the peering_table is not changed to a `Validated*` new type. A
    // VpcPeering is symmetric (no local/remote distinction), and per-side validation is performed
    // only on the asymmetric Peering copies held by the VPCs, in the vpc_table. Since the peering
    // table is not validated independently, it is exposed as-is.
    peering_table: VpcPeeringTable,
}

impl ValidatedOverlay {
    #[must_use]
    pub(crate) fn blank() -> Self {
        Self {
            vpc_table: ValidatedVpcTable::blank(),
            peering_table: VpcPeeringTable::default(),
        }
    }

    #[must_use]
    pub fn vpc_table(&self) -> &ValidatedVpcTable {
        &self.vpc_table
    }

    #[must_use]
    pub fn peering_table(&self) -> &VpcPeeringTable {
        &self.peering_table
    }
}
