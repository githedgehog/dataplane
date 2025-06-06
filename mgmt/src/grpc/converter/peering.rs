// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;

use crate::models::external::overlay::vpcpeering::VpcExpose;
use crate::models::external::overlay::vpcpeering::VpcManifest;
use crate::models::external::overlay::vpcpeering::VpcPeering;

// VPC Peering conversions
impl TryFrom<&gateway_config::VpcPeering> for VpcPeering {
    type Error = String;

    fn try_from(peering: &gateway_config::VpcPeering) -> Result<Self, Self::Error> {
        let (vpc1_manifest, vpc2_manifest) = match peering.r#for.as_slice() {
            [vpc1, vpc2] => {
                let vpc1_manifest = VpcManifest::try_from(vpc1)?;
                let vpc2_manifest = VpcManifest::try_from(vpc2)?;
                Ok((vpc1_manifest, vpc2_manifest))
            }
            _ => Err(format!(
                "VPC peering {} must have exactly two VPCs",
                peering.name
            )),
        }?;

        // Create the peering using the constructor
        Ok(VpcPeering::new(&peering.name, vpc1_manifest, vpc2_manifest))
    }
}

impl TryFrom<&VpcPeering> for gateway_config::VpcPeering {
    type Error = String;

    fn try_from(peering: &VpcPeering) -> Result<Self, Self::Error> {
        // Convert the left and right VPC manifests
        let left_for = gateway_config::PeeringEntryFor::try_from(&peering.left)?;
        let right_for = gateway_config::PeeringEntryFor::try_from(&peering.right)?;

        Ok(gateway_config::VpcPeering {
            name: peering.name.clone(),
            r#for: vec![left_for, right_for],
        })
    }
}

// VPC Manifest conversions
impl TryFrom<&gateway_config::PeeringEntryFor> for VpcManifest {
    type Error = String;

    fn try_from(entry: &gateway_config::PeeringEntryFor) -> Result<Self, Self::Error> {
        // Create a new VPC manifest with the VPC name
        let mut manifest = VpcManifest::new(&entry.vpc);

        // Process each expose rule
        for expose_grpc in &entry.expose {
            let expose = VpcExpose::try_from(expose_grpc)?;
            manifest.add_expose(expose).map_err(|e| {
                format!(
                    "Failed to add expose to manifest for VPC {}: {e}",
                    entry.vpc
                )
            })?;
        }

        Ok(manifest)
    }
}

impl TryFrom<&VpcManifest> for gateway_config::PeeringEntryFor {
    type Error = String;

    fn try_from(manifest: &VpcManifest) -> Result<Self, Self::Error> {
        let mut expose_rules = Vec::new();

        // Convert each expose rule
        for expose in &manifest.exposes {
            let grpc_expose = gateway_config::Expose::try_from(expose)?;
            expose_rules.push(grpc_expose);
        }

        Ok(gateway_config::PeeringEntryFor {
            vpc: manifest.name.clone(),
            expose: expose_rules,
        })
    }
}
