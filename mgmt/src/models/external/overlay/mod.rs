// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod display;
pub mod tests;
pub mod vpc;
pub mod vpcpeering;

use crate::models::external::overlay::vpc::VpcIdMap;
use crate::models::external::overlay::vpc::VpcTable;
use crate::models::external::overlay::vpcpeering::VpcManifest;
use crate::models::external::overlay::vpcpeering::VpcPeeringTable;

use tracing::{debug, error};

use super::{ConfigError, ConfigResult};

#[derive(Clone, Debug, Default)]
pub struct Overlay {
    pub vpc_table: VpcTable,
    pub peering_table: VpcPeeringTable,
}

impl Overlay {
    pub fn new(vpc_table: VpcTable, peering_table: VpcPeeringTable) -> Self {
        Self {
            vpc_table,
            peering_table,
        }
    }
    fn check_peering_vpc(&self, peering: &str, manifest: &VpcManifest) -> ConfigResult {
        if self.vpc_table.get_vpc(&manifest.name).is_none() {
            error!("peering '{}': unknown VPC '{}'", peering, manifest.name);
            return Err(ConfigError::NoSuchVpc(manifest.name.clone()));
        }
        Ok(())
    }
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating overlay configuration...");

        /* validate peerings and check if referred VPCs exist */
        for peering in self.peering_table.values() {
            peering.validate()?;
            self.check_peering_vpc(&peering.name, &peering.left)?;
            self.check_peering_vpc(&peering.name, &peering.right)?;
        }

        /* temporary map of vpc names and ids */
        let id_map: VpcIdMap = self
            .vpc_table
            .values()
            .map(|vpc| (vpc.name.clone(), vpc.id.clone()))
            .collect();

        /* collect peerings of every VPC */
        self.vpc_table
            .collect_peerings(&self.peering_table, &id_map);

        /* empty peering table: we no longer need it since we have collected
        all of the peerings and added them to the corresponding VPCs */
        self.peering_table.clear();

        debug!("Overlay configuration is VALID");
        Ok(())
    }
}
