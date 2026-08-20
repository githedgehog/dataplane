// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use net::vxlan::Vni;

use crate::bolero::support::blocks;
use crate::bolero::{AddressFamily, LegalValue};
use crate::gateway_agent_crd::{GatewayAgentVpcs, GatewayAgentVpcsSubnets};

fn generate_internal_id<D: Driver>(d: &mut D) -> Option<String> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut result = String::new();
    for _ in 0..5 {
        let index = d.gen_usize(Bound::Included(&0), Bound::Excluded(&CHARS.len()))?;
        result.push(CHARS[index] as char);
    }
    Some(result)
}

/// Draws vpcs whose subnets are of the given families, and no more than `max_subnets` of each.
///
/// A vpc's subnets can be named by an expose, and a named subnet contributes its own prefix -- so
/// they are subject to the same rules as an expose's own prefixes: a subnet that overlaps a
/// special-use range makes every expose naming it invalid. Hence the mask floors from
/// [`blocks`], which is what the previous generator, drawing masks from zero, could not respect.
#[derive(Debug, Clone)]
pub struct VpcGenerator<'a> {
    /// Which vpc this is, which picks the block slot its subnets come from. A subnet may be named by
    /// an expose, so it is a prefix like any other and must not collide with another vpc's.
    vpc: u8,
    max_subnets: u8,
    families: &'a [AddressFamily],
}

impl<'a> VpcGenerator<'a> {
    #[must_use]
    pub fn new(vpc: u8, max_subnets: u8, families: &'a [AddressFamily]) -> Self {
        Self {
            vpc,
            max_subnets,
            families,
        }
    }

    fn wants(&self, family: AddressFamily) -> bool {
        self.families.contains(&family)
    }
}

impl ValueGenerator for VpcGenerator<'_> {
    type Output = GatewayAgentVpcs;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let internal_id = generate_internal_id(d)?;
        let vni = d.produce::<Vni>()?;

        let num_v4_cidrs = if self.wants(AddressFamily::V4) {
            u16::from(d.gen_u8(Bound::Included(&0), Bound::Included(&self.max_subnets))?)
        } else {
            0
        };
        let num_v6_cidrs = if self.wants(AddressFamily::V6) {
            u16::from(d.gen_u8(Bound::Included(&0), Bound::Included(&self.max_subnets))?)
        } else {
            0
        };

        // The count first, then a length the subnet region can hold that many distinct prefixes at.
        // The other order lets the region run short, and `private_run` would wrap and hand back the
        // same prefix twice -- two subnets that overlap, which the validator refuses.
        let v4_masklen = d.gen_u8(
            Bound::Included(&blocks::min_subnet_len(AddressFamily::V4, num_v4_cidrs)),
            Bound::Included(&32),
        )?;
        let v6_masklen = d.gen_u8(
            Bound::Included(&blocks::min_subnet_len(AddressFamily::V6, num_v6_cidrs)),
            Bound::Included(&128),
        )?;

        let subnets_cidrs = vec![
            blocks::private_run(d, AddressFamily::V4, self.vpc, v4_masklen, num_v4_cidrs)?,
            blocks::private_run(d, AddressFamily::V6, self.vpc, v6_masklen, num_v6_cidrs)?,
        ];
        let subnets = subnets_cidrs
            .into_iter()
            .flatten()
            .enumerate()
            .map(|(index, cidr)| {
                (
                    format!("subnet{index}"),
                    GatewayAgentVpcsSubnets { cidr: Some(cidr) },
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();

        Some(GatewayAgentVpcs {
            internal_id: Some(internal_id),
            vni: Some(vni.into()),
            subnets: Some(subnets).filter(|s| !s.is_empty()),
        })
    }
}

/// Delegates to [`VpcGenerator`] with default knobs, so existing users keep working.
///
/// Vpc zero, since a caller drawing one vpc at a time has nothing to keep it disjoint from.
impl TypeGenerator for LegalValue<GatewayAgentVpcs> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let families = AddressFamily::all();
        Some(LegalValue(VpcGenerator::new(0, 3, &families).generate(d)?))
    }
}
