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
    pub fn vpcid_map(&self) -> VpcIdMap {
        let id_map: VpcIdMap = self
            .vpc_table
            .values()
            .map(|vpc| (vpc.name.clone(), vpc.id.clone()))
            .collect();
        id_map
    }

    /// Top most validation function for `Overlay` configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the overlay configuration is invalid.
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating overlay configuration...");

        self.validate_peerings()?;

        // collect peerings for every vpc.
        self.collect_peerings();

        self.vpc_table.validate()?;

        debug!("Overlay configuration is VALID:\n{self}");
        Ok(())
    }

    /// Consume `self` and produce a [`ValidatedOverlay`] if it passes validation.
    ///
    /// # Errors
    ///
    /// Returns an error if the overlay configuration is invalid.
    pub fn validated(mut self) -> Result<ValidatedOverlay, ConfigError> {
        self.validate()?;
        Ok(ValidatedOverlay(self))
    }

    /// Collect peerings from the peering table for every VPC.
    ///
    /// Should only be called in `validate`, or in tests.
    pub fn collect_peerings(&mut self) {
        let id_map = self.vpcid_map();
        self.vpc_table
            .collect_peerings(&self.peering_table, &id_map);
    }

    /// FOR TESTS ONLY. Fake validation for the VPC peering manifests.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    pub(crate) unsafe fn fake_manifest_validation_for_tests(&mut self) {
        for peering in self.peering_table.values_mut() {
            for manifest in [&mut peering.left, &mut peering.right] {
                unsafe {
                    manifest.fake_expose_validation_for_tests();
                }
            }
        }
        self.collect_peerings();
    }

    /// FOR TESTS ONLY. Fake validation for the overlay.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_validated_overlay_for_tests(mut self) -> ValidatedOverlay {
        unsafe {
            self.fake_manifest_validation_for_tests();
        }
        ValidatedOverlay(self)
    }
}

#[repr(transparent)]
#[derive(Clone, Debug)]
pub struct ValidatedOverlay(Overlay);

impl ValidatedOverlay {
    #[must_use]
    pub fn vpc_table(&self) -> &ValidatedVpcTable {
        // SAFETY: ValidatedVpcTable is #[repr(transparent)] over VpcTable. A ValidatedOverlay is
        // only ever obtained from `Overlay::validated`, which validates the underlying table.
        #[allow(unsafe_code)]
        unsafe {
            &*(&raw const self.0.vpc_table).cast::<ValidatedVpcTable>()
        }
    }

    /// Return the peering table.
    ///
    /// Note: unlike the other fields exposed on [`ValidatedOverlay`], the peering table is not
    /// wrapped in a `Validated*` newtype. A [`crate::external::overlay::vpcpeering::VpcPeering`]
    /// is symmetric (no local/remote distinction), and per-side validation is performed only on
    /// the asymmetric [`crate::external::overlay::vpc::Peering`] copies that
    /// [`Overlay::collect_peerings`] places on each VPC. Validating the peering table itself
    /// would not provide useful guarantees on top of that, so consumers see the raw type.
    #[must_use]
    pub fn peering_table(&self) -> &VpcPeeringTable {
        &self.0.peering_table
    }
}
