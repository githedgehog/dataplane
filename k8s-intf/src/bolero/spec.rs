// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::{BTreeMap, HashSet};
use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use lpm::prefix::Prefix;

use crate::bolero::gwgroups::{LegalValueGroupsTableGenerator, MAX_GROUP_MEMBERS};
use crate::bolero::peering::LegalValuePeeringsGenerator;
use crate::bolero::support::{K8sName, PrefixPool};
use crate::bolero::{LegalValue, SubnetMap, VpcSubnetMap};
use crate::gateway_agent_crd::{
    GatewayAgentConfig, GatewayAgentGateway, GatewayAgentSpec, GatewayAgentVpcs,
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

/// Generate a random legal `GatewayAgentSpec`
///
/// "Legal" here means the spec converts *and* validates: the whole value has to hold together,
/// not just each subtree on its own.  Two cross-references make that non-local:
///
/// - a peering's `gatewayGroup` must name a group in `groups`, so the group table is generated
///   first and its names handed to the peering generator;
/// - `ExternalConfig::validate` demands a community for every member rank within a group, so the
///   community table is sized to the largest group that could be generated.
///
/// This does not cover all legal `GatewayAgentSpecs`,
/// it is limited by the underlying generators and it generates
/// vpcs and peerings with a fixed name pattern and not all
/// vni combinations are generated.
impl TypeGenerator for LegalValue<GatewayAgentSpec> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let num_vpcs = d.gen_usize(Bound::Included(&0), Bound::Included(&16))?;
        let num_peerings = if num_vpcs > 1 {
            d.gen_usize(Bound::Included(&0), Bound::Included(&16))?
        } else {
            0
        };

        let mut vpcs = BTreeMap::new();
        let vni_base = d.gen_u32(Bound::Included(&1), Bound::Included(&1000))?;
        let mut vpc_internal_ids = HashSet::new();
        for i in 0..num_vpcs {
            let vni_offset = u32::try_from(i).expect("too many vpcs");
            let lv_vpc = d.produce::<LegalValue<GatewayAgentVpcs>>()?;
            let mut vpc = lv_vpc.take();
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

        // Generate the group table first: peerings have to reference it by name.
        let num_groups = d.gen_usize(Bound::Included(&1), Bound::Included(&6))?;
        let (groups, gwgroup_names) =
            LegalValueGroupsTableGenerator::new(num_groups).generate(d)?;

        let mut peerings = BTreeMap::new();
        if num_peerings > 0 {
            // One pool for the whole spec, so no two exposes anywhere in it can overlap -- a
            // stronger invariant than validation demands, and a cheaper one to be sure of.
            let pool = PrefixPool::new(d)?;

            // A default expose reaches the route table as `0.0.0.0/0`, which overlaps every other
            // v4 destination, and `VpcRouteTable::validate` requires overlapping destinations to
            // share a gateway group.  So a spec can have default exposes or a diversity of gateway
            // groups, but not both.  Generate each shape half the time rather than dropping one.
            let allow_defaults = d.gen_bool(None)?;
            let groups_in_play: &[String] = if allow_defaults {
                let pick =
                    d.gen_usize(Bound::Included(&0), Bound::Excluded(&gwgroup_names.len()))?;
                &gwgroup_names[pick..=pick]
            } else {
                &gwgroup_names
            };

            #[allow(clippy::unwrap_used)]
            // Cannot fail: `num_peerings > 0` implies `num_vpcs > 1`, and `num_groups >= 1`.
            let peering_gen = LegalValuePeeringsGenerator::new(&vpc_subnet_map, groups_in_play)
                .unwrap()
                .validation_legal(&pool);

            // `Vpc::check_peering_count` rejects an overlay where the same pair of VPCs peers more
            // than once, so draw peerings from the set of distinct pairs without replacement.
            let names: Vec<&String> = vpc_subnet_map.keys().collect();
            let mut pairs: Vec<(usize, usize)> = (0..names.len())
                .flat_map(|a| ((a + 1)..names.len()).map(move |b| (a, b)))
                .collect();

            // A default expose on one side of a peering is a default *destination* for the other
            // side, and `VpcRouteTable::validate` allows a VPC only one of those.  Track which
            // VPCs have been offered one and refuse to offer a second.  The bookkeeping is
            // conservative: a VPC is marked when a default is *permitted*, not when one is
            // actually emitted, since that choice is the side generator's to make.
            let mut offered_default: HashSet<usize> = HashSet::new();

            for i in 0..num_peerings.min(pairs.len()) {
                let choice = d.gen_usize(Bound::Included(&0), Bound::Excluded(&pairs.len()))?;
                let (a, b) = pairs.swap_remove(choice);

                // Side 0 carrying a default targets `b`, and side 1 targets `a`.
                let mut candidates = Vec::with_capacity(2);
                if allow_defaults && !offered_default.contains(&b) {
                    candidates.push((0_usize, b));
                }
                if allow_defaults && !offered_default.contains(&a) {
                    candidates.push((1_usize, a));
                }
                let default_side = if candidates.is_empty() || d.gen_bool(None)? {
                    None
                } else {
                    let pick =
                        d.gen_usize(Bound::Included(&0), Bound::Excluded(&candidates.len()))?;
                    let (side, target) = candidates[pick];
                    offered_default.insert(target);
                    Some(side)
                };

                peerings.insert(
                    format!("peering{i}"),
                    peering_gen.generate_for_pair(d, names[a], names[b], default_side)?,
                );
            }
        }

        // A group of N members occupies ranks `0..N`, and validation requires a community at
        // every rank it finds.  Sizing the table to the largest group a generated spec can hold
        // keeps that satisfied without coupling to how many members were actually drawn.
        let mut communities = BTreeMap::new();
        for i in 0..MAX_GROUP_MEMBERS {
            communities.insert(i.to_string(), format!("65000:{}", 100 + i));
        }

        Some(LegalValue(GatewayAgentSpec {
            agent_version: d.produce::<Option<K8sName>>()?.map(K8sName::take),
            // `fabricBFD` fans out over every underlay BGP neighbor in the converter, so it is
            // worth generating rather than pinning to `None`.
            config: d
                .produce::<Option<bool>>()?
                .map(|fabric_bfd| GatewayAgentConfig {
                    fabric_bfd: Some(fabric_bfd),
                }),
            groups: Some(groups),
            communities: Some(communities),
            gateway: Some(d.produce::<LegalValue<GatewayAgentGateway>>()?.take()),
            vpcs: Some(vpcs).filter(|v| !v.is_empty()),
            peerings: Some(peerings).filter(|p| !p.is_empty()),
        }))
    }
}
