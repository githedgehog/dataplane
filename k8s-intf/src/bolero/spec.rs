// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use lpm::prefix::Prefix;

use crate::bolero::peering::LegalValuePeeringsGenerator;
use crate::bolero::{AddressFamily, LegalValue, NatFlavour, SubnetMap, VpcSubnetMap};
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

fn increment_string(s: &mut str) {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let bytes = unsafe { s.as_bytes_mut() }; // Safe, we only manipulate ASCII characters
    for byte in bytes.iter_mut().rev() {
        let index = CHARS.iter().position(|&x| x == *byte).unwrap();
        *byte = CHARS[(index + 1) % CHARS.len()];
        // If we looped over available characters, also increment the previous character; otherwise,
        // we're done.
        if *byte != CHARS[0] {
            break;
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpecBuilder {
    max_vpcs: u8,
    max_peerings: u8,
    max_exposes: u8,
    max_subnets: u8,
    flavours: Vec<NatFlavour>,
    families: Vec<AddressFamily>,
}

impl Default for SpecBuilder {
    fn default() -> Self {
        Self {
            max_vpcs: 4,
            max_peerings: 3,
            max_exposes: 2,
            max_subnets: 3,
            flavours: NatFlavour::all(),
            families: AddressFamily::all(),
        }
    }
}

impl SpecBuilder {
    #[must_use]
    pub fn max_vpcs(mut self, max: u8) -> Self {
        self.max_vpcs = max;
        self
    }

    #[must_use]
    pub fn max_peerings(mut self, max: u8) -> Self {
        self.max_peerings = max;
        self
    }

    #[must_use]
    pub fn max_exposes(mut self, max: u8) -> Self {
        self.max_exposes = max;
        self
    }

    #[must_use]
    pub fn max_subnets(mut self, max: u8) -> Self {
        self.max_subnets = max;
        self
    }

    #[must_use]
    pub fn flavours(mut self, flavours: Vec<NatFlavour>) -> Self {
        if !flavours.is_empty() {
            self.flavours = flavours;
        }
        self
    }

    #[must_use]
    pub fn families(mut self, families: Vec<AddressFamily>) -> Self {
        if !families.is_empty() {
            self.families = families;
        }
        self
    }

    #[must_use]
    pub fn build(self) -> GatewayAgentSpecs {
        GatewayAgentSpecs(self)
    }
}

#[derive(Debug, Clone)]
pub struct GatewayAgentSpecs(pub(crate) SpecBuilder);

impl Default for GatewayAgentSpecs {
    fn default() -> Self {
        SpecBuilder::default().build()
    }
}

/// Generate a random legal `GatewayAgentSpec`
///
/// This does not cover all legal `GatewayAgentSpecs`,
/// it is limited by the underlying generators and it generates
/// vpcs and peerings with a fixed name pattern and not all
/// vni combinations are generated.
impl TypeGenerator for LegalValue<GatewayAgentSpec> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        Some(LegalValue(GatewayAgentSpecs::default().generate(d)?))
    }
}

impl ValueGenerator for GatewayAgentSpecs {
    type Output = GatewayAgentSpec;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let knobs = &self.0;
        let num_vpcs =
            usize::from(d.gen_u8(Bound::Included(&0), Bound::Included(&knobs.max_vpcs))?);
        let num_peerings = if num_vpcs > 1 {
            usize::from(d.gen_u8(Bound::Included(&0), Bound::Included(&knobs.max_peerings))?)
        } else {
            0
        };

        let mut vpcs = BTreeMap::new();
        let vni_base = d.gen_u32(Bound::Included(&1), Bound::Included(&1000))?;
        let mut vpc_internal_ids = HashSet::new();
        for i in 0..num_vpcs {
            let vni_offset = u32::try_from(i).expect("too many vpcs");
            let mut vpc = crate::bolero::vpc::VpcGenerator::new(knobs.max_subnets, &knobs.families)
                .generate(d)?;
            let vpc_id = vpc.internal_id.as_mut().unwrap();
            while !vpc_internal_ids.insert(vpc_id.clone()) {
                // We already have a VPC with this internal_id, "increment" the string to generate a
                // new one.
                increment_string(vpc_id);
            }
            vpc.vni = Some(vni_base + vni_offset);
            vpcs.insert(format!("vpc{i}"), vpc);
        }

        let vpc_subnet_map = extract_subnets(&vpcs);

        let num_groups = d.gen_usize(Bound::Included(&0), Bound::Included(&6))?;
        let mut groups = BTreeMap::new();
        for i in 0..=num_groups {
            groups.insert(format!("gwgroup-{i}"), d.produce::<GatewayAgentGroups>()?);
        }
        let group_names: Vec<String> = groups.keys().cloned().collect();

        let mut peerings = BTreeMap::new();
        if num_peerings > 0 {
            let peering_gen = LegalValuePeeringsGenerator::new(
                &vpc_subnet_map,
                &knobs.flavours,
                &knobs.families,
                knobs.max_exposes,
                &group_names,
            )
            .unwrap();
            let mut available = peering_gen.pairs();
            let wanted = num_peerings.min(available.len());
            for i in 0..wanted {
                let choice = d.gen_usize(Bound::Included(&0), Bound::Excluded(&available.len()))?;
                let pair = available.swap_remove(choice);
                peerings.insert(format!("peering{i}"), peering_gen.generate_for(d, pair)?);
            }
        }

        let num_communities = d.gen_usize(Bound::Included(&0), Bound::Included(&9))?;
        let mut communities = BTreeMap::new();
        for i in 0..=num_communities {
            let community = format!("65000:{}", 100 + i);
            communities.insert(i.to_string(), community);
        }

        Some(GatewayAgentSpec {
            agent_version: None,
            config: None,
            groups: Some(groups),
            communities: Some(communities),
            gateway: Some(d.produce::<LegalValue<GatewayAgentGateway>>()?.take()),
            vpcs: Some(vpcs).filter(|v| !v.is_empty()),
            peerings: Some(peerings).filter(|p| !p.is_empty()),
        })
    }
}
