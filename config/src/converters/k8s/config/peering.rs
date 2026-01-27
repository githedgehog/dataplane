// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_intf::gateway_agent_crd::{GatewayAgentPeerings, GatewayAgentPeeringsPeering};

use crate::converters::k8s::FromK8sConversionError;
use crate::converters::k8s::config::{SubnetMap, VpcSubnetMap};
use crate::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering};

impl TryFrom<(&SubnetMap, &str, &GatewayAgentPeeringsPeering)> for VpcManifest {
    type Error = FromK8sConversionError;

    fn try_from(
        (subnets, vpc_name, peering): (&SubnetMap, &str, &GatewayAgentPeeringsPeering),
    ) -> Result<Self, Self::Error> {
        let mut manifest = VpcManifest::new(vpc_name);
        for expose in peering.expose.as_ref().unwrap_or(&vec![]) {
            manifest.add_expose(VpcExpose::try_from((subnets, expose))?);
        }
        Ok(manifest)
    }
}

impl TryFrom<(&VpcSubnetMap, &str, &GatewayAgentPeerings)> for VpcPeering {
    type Error = FromK8sConversionError;

    fn try_from(
        (vpc_subnets, peering_name, peering): (&VpcSubnetMap, &str, &GatewayAgentPeerings),
    ) -> Result<Self, Self::Error> {
        let gwgroup = peering.gateway_group.clone(); // we don't fail atm if not set
        if let Some(peering) = peering.peering.as_ref() {
            let num_peerings = peering.len();
            if peering.len() != 2 {
                return Err(FromK8sConversionError::MissingData(format!(
                    "Peering must be between 2 VPCs, found {num_peerings}"
                )));
            }
            let mut manifests = peering
                .iter()
                .map(|(vpc_name, peering_side)| {
                    let empty_map = SubnetMap::new();
                    // Should we require a subnet map for each VPC?  We will error out if the VPC references a subnet that does not exist regardless.
                    let subnets = vpc_subnets.get(vpc_name).unwrap_or(&empty_map);
                    VpcManifest::try_from((subnets, vpc_name.as_str(), peering_side))
                })
                .collect::<Result<Vec<_>, _>>()?;

            let right = manifests.pop().unwrap_or_else(|| unreachable!());
            let left = manifests.pop().unwrap_or_else(|| unreachable!());

            Ok(VpcPeering::new(peering_name, left, right, gwgroup))
        } else {
            Err(FromK8sConversionError::Invalid(
                "Missing peering".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use k8s_intf::bolero::peering::{
        LegalValuePeeringsGenerator, LegalValuePeeringsPeeringGenerator,
    };
    use lpm::prefix::Prefix;

    use crate::converters::k8s::config::{SubnetMap, VpcSubnetMap};

    #[test]
    fn test_vpc_manifest_conversion() {
        let subnets = SubnetMap::new(); // Let this be empty since we are test subnet conversion elsewhere
        let generator = LegalValuePeeringsPeeringGenerator::new(&subnets);
        bolero::check!()
            .with_generator(generator)
            .for_each(|peering| {
                let vpc_name = "test-vpc";
                let manifest = VpcManifest::try_from((&subnets, vpc_name, peering)).unwrap();
                assert_eq!(manifest.name, vpc_name);
                // We just need to check the sizes here since the actual conversion for the expose is tested elsewhere
                assert_eq!(
                    manifest.exposes.len(),
                    peering.expose.as_ref().unwrap_or(&vec![]).len()
                );
            });
    }

    #[test]
    fn test_vpc_peering_conversion() {
        let subnets = VpcSubnetMap::from([
            (
                "vpc0".to_string(),
                SubnetMap::from([
                    (
                        "subnet-1".to_string(),
                        "1.2.3.4/32".parse::<Prefix>().unwrap(),
                    ),
                    (
                        "subnet-2".to_string(),
                        "1.2.3.4/32".parse::<Prefix>().unwrap(),
                    ),
                ]),
            ),
            (
                "vpc1".to_string(),
                SubnetMap::from([
                    (
                        "subnet-1".to_string(),
                        "2.2.3.4/32".parse::<Prefix>().unwrap(),
                    ),
                    (
                        "subnet-2".to_string(),
                        "2.2.3.4/32".parse::<Prefix>().unwrap(),
                    ),
                ]),
            ),
            (
                "vpc2".to_string(),
                SubnetMap::from([
                    (
                        "subnet-1".to_string(),
                        "3.2.3.4/32".parse::<Prefix>().unwrap(),
                    ),
                    (
                        "subnet-2".to_string(),
                        "3.2.3.4/32".parse::<Prefix>().unwrap(),
                    ),
                ]),
            ),
            (
                "vpc3".to_string(),
                SubnetMap::from([
                    (
                        "subnet-1".to_string(),
                        "4.2.3.4/32".parse::<Prefix>().unwrap(),
                    ),
                    (
                        "subnet-2".to_string(),
                        "4.2.3.4/32".parse::<Prefix>().unwrap(),
                    ),
                ]),
            ),
        ]);
        let generator = LegalValuePeeringsGenerator::new(&subnets).unwrap();
        bolero::check!()
            .with_generator(generator)
            .for_each(|peering| {
                let peering_name = "test-peering";
                let peering = VpcPeering::try_from((&subnets, peering_name, peering)).unwrap();
                assert_eq!(peering.name, peering_name);
                // Rest of the assertions come from the types and the unwrap in the conversion above
            });
    }
}
