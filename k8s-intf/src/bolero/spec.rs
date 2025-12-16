// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use lpm::prefix::Prefix;

use crate::bolero::peering::LegalValuePeeringsGenerator;
use crate::bolero::{LegalValue, SubnetMap, VpcSubnetMap};
use crate::gateway_agent_crd::{
    GatewayAgentGateway, GatewayAgentGroups, GatewayAgentSpec, GatewayAgentVpcs,
};

fn extract_subnets(vpcs: &BTreeMap<String, GatewayAgentVpcs>) -> VpcSubnetMap {
    let mut vpc_subnets = VpcSubnetMap::new();
    for (vpc_name, vpc) in vpcs {
        let mut subnets = SubnetMap::new();
        for (subnet_name, subnet) in vpc.subnets.as_ref().unwrap_or(&BTreeMap::new()) {
            let Some(cidr) = subnet.cidr.as_ref() else {
                continue;
            };
            let prefix = cidr.parse::<Prefix>().unwrap();
            subnets.insert(subnet_name.clone(), prefix);
        }
        vpc_subnets.insert(vpc_name.clone(), subnets);
    }
    vpc_subnets
}

/// Generate a random legal `GatewayAgentSpec`
///
/// This does not cover all legal `GatewayAgentSpecs`,
/// it is limited by the underlying generators and it generates
/// vpcs and peerings with a fixed name pattern.
impl TypeGenerator for LegalValue<GatewayAgentSpec> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let num_vpcs = d.gen_usize(Bound::Included(&0), Bound::Included(&16))?;
        let num_peerings = if num_vpcs > 1 {
            d.gen_usize(Bound::Included(&0), Bound::Included(&16))?
        } else {
            0
        };

        let mut vpcs = BTreeMap::new();
        for i in 0..num_vpcs {
            vpcs.insert(
                format!("vpc{i}"),
                d.produce::<LegalValue<GatewayAgentVpcs>>()?.take(),
            );
        }

        let vpc_subnet_map = extract_subnets(&vpcs);

        let mut peerings = BTreeMap::new();
        if num_peerings > 0 {
            let peering_gen = LegalValuePeeringsGenerator::new(&vpc_subnet_map).unwrap();
            for i in 0..num_peerings {
                peerings.insert(format!("peering{i}"), peering_gen.generate(d)?);
            }
        }

        let num_groups = d.gen_usize(Bound::Included(&0), Bound::Included(&6))?;
        let mut groups = BTreeMap::new();
        for i in 0..=num_groups {
            groups.insert(format!("gwgroup-{i}"), d.produce::<GatewayAgentGroups>()?);
        }

        let num_communities = d.gen_usize(Bound::Included(&0), Bound::Included(&9))?;
        let mut communities = BTreeMap::new();
        for i in 0..=num_communities {
            let community = format!("65000:{}", 100 + i);
            communities.insert(i.to_string(), community);
        }

        Some(LegalValue(GatewayAgentSpec {
            agent_version: None,
            groups: Some(groups),
            communities: Some(communities),
            gateway: Some(d.produce::<LegalValue<GatewayAgentGateway>>()?.take()),
            vpcs: Some(vpcs).filter(|v| !v.is_empty()),
            peerings: Some(peerings).filter(|p| !p.is_empty()),
        }))
    }
}
