// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;

use k8s_intf::gateway_agent_crd::{GatewayAgentPeerings, GatewayAgentSpec, GatewayAgentVpcs};
use lpm::prefix::Prefix;

use crate::converters::k8s::FromK8sConversionError;
use crate::converters::k8s::config::{SubnetMap, VpcSubnetMap};
use crate::external::overlay::Overlay;
use crate::external::overlay::vpc::{Vpc, VpcTable};
use crate::external::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};

fn extract_subnets(
    vpcs: &BTreeMap<String, GatewayAgentVpcs>,
) -> Result<VpcSubnetMap, FromK8sConversionError> {
    let mut vpc_subnets = VpcSubnetMap::new();
    for (vpc_name, vpc) in vpcs {
        let mut subnets = SubnetMap::new();
        for (subnet_name, subnet) in vpc.subnets.as_ref().unwrap_or(&BTreeMap::new()) {
            let Some(cidr) = subnet.cidr.as_ref() else {
                continue;
            };
            let prefix = cidr.parse::<Prefix>().map_err(|e| {
                FromK8sConversionError::InvalidData(format!(
                    "vpc subnet CIDR {cidr} for vpc {vpc_name}: {e}"
                ))
            })?;
            subnets.insert(subnet_name.clone(), prefix);
        }
        vpc_subnets.insert(vpc_name.clone(), subnets);
    }
    Ok(vpc_subnets)
}

fn make_vpc_table(
    vpcs: &BTreeMap<String, GatewayAgentVpcs>,
) -> Result<VpcTable, FromK8sConversionError> {
    let mut vpc_table = VpcTable::new();
    for (vpc_name, k8s_vpc) in vpcs {
        let vpc = Vpc::try_from((vpc_name.as_str(), k8s_vpc))?;
        vpc_table.add(vpc).map_err(|e| {
            FromK8sConversionError::InternalError(format!("Cannot add vpc {vpc_name}: {e}"))
        })?;
    }
    Ok(vpc_table)
}

fn make_peering_table(
    vpc_subnets: &VpcSubnetMap,
    peerings: &BTreeMap<String, GatewayAgentPeerings>,
) -> Result<VpcPeeringTable, FromK8sConversionError> {
    let mut peering_table = VpcPeeringTable::new();
    for (peering_name, k8s_peering) in peerings {
        let peering = VpcPeering::try_from((vpc_subnets, peering_name.as_str(), k8s_peering))?;
        peering_table.add(peering).map_err(|e| {
            FromK8sConversionError::InternalError(format!("Cannot add peering {peering_name}: {e}"))
        })?;
    }
    Ok(peering_table)
}

impl TryFrom<&GatewayAgentSpec> for Overlay {
    type Error = FromK8sConversionError;

    fn try_from(spec: &GatewayAgentSpec) -> Result<Self, Self::Error> {
        match (spec.vpcs.as_ref(), spec.peerings.as_ref()) {
            (None, None) => Ok(Overlay::new(VpcTable::new(), VpcPeeringTable::new())),
            (None, Some(peerings)) => Err(FromK8sConversionError::NotAllowed(format!(
                "Found 0 vpcs but {} peerings",
                peerings.len()
            ))),
            (Some(vpcs), None) => {
                let vpc_table = make_vpc_table(vpcs)?;
                let overlay = Overlay::new(vpc_table, VpcPeeringTable::new());
                Ok(overlay)
            }
            (Some(vpcs), Some(peerings)) => {
                let vpc_table = make_vpc_table(vpcs)?;
                let vpc_subnets = extract_subnets(vpcs)?;
                let peering_table = make_peering_table(&vpc_subnets, peerings)?;
                let overlay = Overlay::new(vpc_table, peering_table);
                Ok(overlay)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use k8s_intf::bolero::LegalValue;

    #[test]
    // Neither I (manish) nor AI can figure out the correct syntax to replace the closure with BTreeMap<String, GatewayAgentPeerings>::len and BTreeMap<String, GatewayAgentVpcs>::len>
    #[allow(clippy::redundant_closure_for_method_calls)]
    fn test_overlay_conversion() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentSpec>>()
            .for_each(|spec| {
                let spec = spec.as_ref();
                let overlay = Overlay::try_from(spec).unwrap();
                assert_eq!(
                    overlay.vpc_table.len(),
                    spec.vpcs.as_ref().map_or(0, |vpcs| vpcs.len())
                );

                assert_eq!(
                    overlay.peering_table.len(),
                    spec.peerings.as_ref().map_or(0, |peerings| peerings.len())
                );
                // Other assertions are from the conversion unwrap and type system
            });
    }
}
