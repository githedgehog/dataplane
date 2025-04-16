// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod display;
pub mod tests;
pub mod vpc;
pub mod vpcpeering;

use crate::rpc::overlay::vpc::VpcTable;
use crate::rpc::overlay::vpcpeering::VpcManifest;
use crate::rpc::overlay::vpcpeering::VpcPeeringTable;
use tracing::{debug, error};

use super::{ApiError, ApiResult};

#[derive(Debug)]
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
    fn check_peering_vpc(&self, peering: &str, manifest: &VpcManifest) -> ApiResult {
        if self.vpc_table.get_vpc(&manifest.name).is_none() {
            error!("peering '{}': unknown VPC '{}'", peering, manifest.name);
            return Err(ApiError::NoSuchVpc(manifest.name.clone()));
        }
        Ok(())
    }
    pub fn validate(&self) -> ApiResult {
        debug!("Validating overlay configuration");
        /* Vpc peerings are validated on insertion: there, we check that the peering
        has a unique name and that it refers to two VPCs. Here we validate that the
        referred-to VPCs do actually exist in the VPC table. */
        for peering in self.peering_table.values() {
            self.check_peering_vpc(&peering.name, &peering.left)?;
            self.check_peering_vpc(&peering.name, &peering.right)?;
        }
        Ok(())
    }
}
