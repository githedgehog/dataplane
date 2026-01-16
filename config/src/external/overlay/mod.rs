// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod tests;
pub mod vpc;
pub mod vpcpeering;

use crate::{ConfigError, ConfigResult};
use tracing::{debug, error};
use vpc::VpcIdMap;
use vpc::VpcTable;
use vpcpeering::VpcManifest;
use vpcpeering::VpcPeeringTable;

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
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating overlay configuration...");

        self.validate_peerings()?;
        let id_map = self.vpcid_map();

        // collect peerings for every vpc.
        self.vpc_table
            .collect_peerings(&self.peering_table, &id_map);

        self.vpc_table.validate()?;

        debug!("Overlay configuration is VALID:\n{self}");
        Ok(())
    }
}
