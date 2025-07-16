// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;

use tracing::error;

use crate::external::overlay::Overlay;
use crate::external::overlay::vpc::{Vpc, VpcTable};
use crate::external::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};

// Overlay conversions
impl TryFrom<&gateway_config::Overlay> for Overlay {
    type Error = String;

    fn try_from(overlay: &gateway_config::Overlay) -> Result<Self, Self::Error> {
        // Create VPC table
        let mut vpc_table = VpcTable::new();

        // Add VPCs
        for vpc_grpc in &overlay.vpcs {
            // Convert VPC
            let vpc = Vpc::try_from(vpc_grpc)?;

            vpc_table.add(vpc).map_err(|e| {
                let msg = format!("Failed to add VPC {}: {e}", vpc_grpc.name);
                error!("{msg}");
                msg
            })?;
        }

        // Create peering table
        let mut peering_table = VpcPeeringTable::new();

        // Add peerings
        for peering_grpc in &overlay.peerings {
            // Convert peering
            let peering = VpcPeering::try_from(peering_grpc)?;

            // Add to table
            peering_table
                .add(peering)
                .map_err(|e| format!("Failed to add peering {}: {e}", peering_grpc.name))?;
        }

        // Create overlay with the tables
        Ok(Overlay::new(vpc_table, peering_table))
    }
}

impl TryFrom<&Overlay> for gateway_config::Overlay {
    type Error = String;

    fn try_from(overlay: &Overlay) -> Result<Self, Self::Error> {
        let mut vpcs = Vec::new();
        let mut peerings = Vec::new();

        // Convert VPCs
        for vpc in overlay.vpc_table.values() {
            let grpc_vpc = gateway_config::Vpc::try_from(vpc)?;
            vpcs.push(grpc_vpc);
        }

        // Convert peerings
        for peering in overlay.peering_table.values() {
            let grpc_peering = gateway_config::VpcPeering::try_from(peering)?;
            peerings.push(grpc_peering);
        }

        Ok(gateway_config::Overlay { vpcs, peerings })
    }
}
