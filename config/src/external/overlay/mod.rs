// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod tests;
pub mod vpc;
pub mod vpcpeering;

use crate::external::overlay::vpc::VpcIdMap;
use crate::external::overlay::vpc::VpcTable;
use crate::external::overlay::vpcpeering::VpcManifest;
use crate::external::overlay::vpcpeering::VpcPeeringTable;
use crate::{ConfigError, ConfigResult};
use tracing::{debug, error};

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
        self.vpc_table.validate()?;

        debug!(
            "Overlay configuration is VALID and looks as:\n{}\n{}",
            self.vpc_table, self.peering_table
        );

        /* empty peering table: we no longer need it since we have collected
        all of the peerings and added them to the corresponding VPCs */
        self.peering_table.clear();

        /* empty collections used for validation */
        self.vpc_table.clear_vnis();

        Ok(())
    }
}
