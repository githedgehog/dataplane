// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;
use std::convert::TryFrom;

use crate::external::overlay::vpc::Vpc;
use crate::internal::interfaces::interface::InterfaceConfig;

impl TryFrom<&gateway_config::Vpc> for Vpc {
    type Error = String;

    fn try_from(vpc_grpc: &gateway_config::Vpc) -> Result<Self, Self::Error> {
        // Create a new VPC with name and VNI
        let mut vpc = Vpc::new(&vpc_grpc.name, &vpc_grpc.id, vpc_grpc.vni)
            .map_err(|e| format!("Failed to create VPC: {e}"))?;

        // Convert and add interfaces if any
        // SMATOV: TODO: We will add this handling later. TBD
        if !vpc_grpc.interfaces.is_empty() {
            // For each interface from gRPC
            for iface in &vpc_grpc.interfaces {
                let interface = InterfaceConfig::try_from(iface)?;
                vpc.add_interface_config(interface);
            }
        }

        Ok(vpc)
    }
}

impl TryFrom<&Vpc> for gateway_config::Vpc {
    type Error = String;

    fn try_from(vpc: &Vpc) -> Result<Self, Self::Error> {
        // Convert VPC interfaces
        let interfaces = vpc
            .interfaces
            .values()
            .map(gateway_config::Interface::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(gateway_config::Vpc {
            name: vpc.name.clone(),
            id: vpc.id.to_string(),
            vni: vpc.vni.as_u32(),
            interfaces,
        })
    }
}
