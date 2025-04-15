// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration

pub mod tests;
pub mod vpc;
pub mod vpcpeering;

use crate::rpc::overlay::vpc::VpcTable;
use crate::rpc::overlay::vpcpeering::VpcManifest;
use crate::rpc::overlay::vpcpeering::VpcPeeringTable;
use tracing::error;

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
    fn check_peering_vpc(&self, peering: &str, manifest: &Option<VpcManifest>) -> ApiResult {
        if let Some(vpc) = manifest {
            if self.vpc_table.get_vpc(&vpc.name).is_none() {
                error!("peering '{}': unknown VPC '{}'", peering, vpc.name);
                return Err(ApiError::NoSuchVpc(vpc.name.clone()));
            }
        } else {
            // should never happen
            return Err(ApiError::IncompletePeeringData(peering.to_owned()));
        }
        Ok(())
    }
    pub fn validate(&self) -> ApiResult {
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
