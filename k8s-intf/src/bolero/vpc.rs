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

#[derive(Debug, Clone)]
pub struct VpcGenerator<'a> {
    max_subnets: u8,
    families: &'a [AddressFamily],
}

impl<'a> VpcGenerator<'a> {
    #[must_use]
    pub fn new(max_subnets: u8, families: &'a [AddressFamily]) -> Self {
        Self {
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

        let v4_masklen = d.gen_u8(Bound::Included(&blocks::MIN_V4_LEN), Bound::Included(&32))?;
        let v6_masklen = d.gen_u8(Bound::Included(&blocks::MIN_V6_LEN), Bound::Included(&128))?;
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

        let subnets_cidrs = vec![
            blocks::private_run(d, AddressFamily::V4, v4_masklen, num_v4_cidrs)?,
            blocks::private_run(d, AddressFamily::V6, v6_masklen, num_v6_cidrs)?,
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

impl TypeGenerator for LegalValue<GatewayAgentVpcs> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let families = AddressFamily::all();
        Some(LegalValue(VpcGenerator::new(3, &families).generate(d)?))
    }
}
