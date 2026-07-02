// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::expose::VpcExposes;
use k8s_intf::gateway_agent_crd::{GatewayAgentPeerings, GatewayAgentPeeringsPeering};

use crate::converters::k8s::FromK8sConversionError;
use crate::converters::k8s::config::{SubnetMap, VpcSubnetMap};
use crate::external::overlay::acl::Acl;
use crate::external::overlay::vpcpeering::{VpcManifest, VpcPeering};

impl TryFrom<(&SubnetMap, &str, &GatewayAgentPeeringsPeering)> for VpcManifest {
    type Error = FromK8sConversionError;

    fn try_from(
        (subnets, vpc_name, peering): (&SubnetMap, &str, &GatewayAgentPeeringsPeering),
    ) -> Result<Self, Self::Error> {
        let mut manifest = VpcManifest::new(vpc_name);
        if let Some(peering_exposes) = peering.expose.as_ref() {
            for expose in peering_exposes {
                manifest.add_exposes(VpcExposes::try_from((subnets, expose))?);
            }
        } else {
            return Err(Self::Error::MissingData(format!(
                "VPC {vpc_name} has a peering with no exposes"
            )));
        }
        Ok(manifest)
    }
}

impl TryFrom<(&VpcSubnetMap, &str, &GatewayAgentPeerings)> for VpcPeering {
    type Error = FromK8sConversionError;

    fn try_from(
        (vpc_subnets, peering_name, peering): (&VpcSubnetMap, &str, &GatewayAgentPeerings),
    ) -> Result<Self, Self::Error> {
        let gwgroup = peering
            .gateway_group
            .as_ref()
            .ok_or(FromK8sConversionError::MissingData(format!(
                "Peering {peering_name} is not mapped to any gateway group",
            )))?
            .clone();

        let acl_spec = peering.acl.as_ref();
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

            let mut vpc_peering = VpcPeering::new(peering_name, left, right, gwgroup);
            if let Some(acl) = acl_spec {
                let acl = Acl::try_from((
                    vpc_subnets,
                    vpc_peering.left.name.as_str(),
                    vpc_peering.right.name.as_str(),
                    acl,
                ))?;
                vpc_peering.acl = Some(acl);
            }

            Ok(vpc_peering)
        } else {
            Err(FromK8sConversionError::MissingData(
                "Vpc reference in peering".to_string(),
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

    #[test]
    fn test_vpc_peering_conversion_acl() {
        use k8s_intf::gateway_agent_crd::{
            GatewayAgentPeeringsAcl, GatewayAgentPeeringsAclDefault, GatewayAgentPeeringsAclRules,
            GatewayAgentPeeringsAclRulesAction,
        };
        use std::collections::BTreeMap;

        let subnets = VpcSubnetMap::from([
            ("vpc0".to_string(), SubnetMap::new()),
            ("vpc1".to_string(), SubnetMap::new()),
        ]);

        let peering_side = GatewayAgentPeeringsPeering {
            expose: Some(vec![]),
        };
        let peerings_map = BTreeMap::from([
            ("vpc0".to_string(), peering_side.clone()),
            ("vpc1".to_string(), peering_side),
        ]);

        let acl = GatewayAgentPeeringsAcl {
            default: GatewayAgentPeeringsAclDefault::Deny,
            rules: Some(vec![GatewayAgentPeeringsAclRules {
                action: GatewayAgentPeeringsAclRulesAction::Allow,
                from: Some("vpc0".to_string()),
                to: Some("vpc1".to_string()),
                log: None,
                r#match: None,
                name: Some("allow-all".to_string()),
                scope: None,
            }]),
        };

        let k8s_peering = GatewayAgentPeerings {
            gateway_group: Some("default".to_string()),
            peering: Some(peerings_map),
            acl: Some(acl),
        };

        let vpc_peering = VpcPeering::try_from((&subnets, "test-peering", &k8s_peering)).unwrap();
        let converted_acl = vpc_peering.acl.expect("acl should be present");
        assert_eq!(converted_acl.rules().len(), 1);

        let mut k8s_peering_no_acl = k8s_peering;
        k8s_peering_no_acl.acl = None;
        let vpc_peering_no_acl =
            VpcPeering::try_from((&subnets, "test-peering", &k8s_peering_no_acl)).unwrap();
        assert!(vpc_peering_no_acl.acl.is_none());
    }
}
