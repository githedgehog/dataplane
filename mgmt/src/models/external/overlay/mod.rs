// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod display;
pub mod tests;
pub mod vpc;
pub mod vpcpeering;

use crate::models::external::overlay::vpc::MultiIndexVpcMap;
use crate::models::external::overlay::vpcpeering::VpcManifest;
use crate::models::external::overlay::vpcpeering::VpcPeeringTable;

use tracing::{debug, error};

use super::{ConfigError, ConfigResult};

#[derive(Clone, Debug, Default)]
pub struct Overlay {
    pub vpc_table: MultiIndexVpcMap,
    pub peering_table: VpcPeeringTable,
}

impl Overlay {
    pub fn new(vpc_table: MultiIndexVpcMap, peering_table: VpcPeeringTable) -> Self {
        Self {
            vpc_table,
            peering_table,
        }
    }
    fn check_peering_vpc(&self, peering: &str, manifest: &VpcManifest) -> ConfigResult {
        if self.vpc_table.get_by_name(&manifest.name).is_none() {
            error!("peering '{}': unknown VPC '{}'", peering, manifest.name);
            return Err(ConfigError::NoSuchVpc(manifest.name.clone()));
        }
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip(self))]
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating overlay configuration...");
        /* check if the VPCs referred in a peering exist */
        for peering in self.peering_table.values() {
            self.check_peering_vpc(&peering.name, &peering.left)?;
            self.check_peering_vpc(&peering.name, &peering.right)?;
        }

        // TODO: why do we need to mutate in the validate function?
        // /* collect peerings of every VPC */
        // self.vpc_table.collect_peerings(&self.peering_table);

        debug!("Overlay configuration is VALID");
        Ok(())
    }
}
