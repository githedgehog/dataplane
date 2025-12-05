// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use net::vxlan::Vni;

use crate::bolero::LegalValue;
use crate::bolero::support::{UniqueV4CidrGenerator, UniqueV6CidrGenerator};
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

impl TypeGenerator for LegalValue<GatewayAgentVpcs> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let internal_id = generate_internal_id(d)?;
        let vni = d.produce::<Vni>()?;

        let v4_masklen = d.gen_u8(Bound::Included(&0), Bound::Included(&32))?;
        let num_v4_cidrs = d.gen_u16(Bound::Included(&0), Bound::Included(&16))?;

        let v6_masklen = d.gen_u8(Bound::Included(&0), Bound::Included(&128))?;
        let num_v6_cidrs = d.gen_u16(Bound::Included(&0), Bound::Included(&16))?;
        let v4_gen = UniqueV4CidrGenerator::new(num_v4_cidrs, v4_masklen);
        let v6_gen = UniqueV6CidrGenerator::new(num_v6_cidrs, v6_masklen);

        let subnets_cidrs = vec![v4_gen.generate(d)?, v6_gen.generate(d)?];
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

        Some(LegalValue(GatewayAgentVpcs {
            internal_id: Some(internal_id),
            vni: Some(vni.into()),
            subnets: Some(subnets).filter(|s| !s.is_empty()),
        }))
    }
}
