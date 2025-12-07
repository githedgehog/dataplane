// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use lpm::prefix::Prefix;

use crate::bolero::LegalValue;
use crate::bolero::support::{UniqueV4CidrGenerator, UniqueV6CidrGenerator};
use crate::gateway_agent_crd::{
    GatewayAgentPeeringsPeeringExpose, GatewayAgentPeeringsPeeringExposeAs,
    GatewayAgentPeeringsPeeringExposeIps, GatewayAgentPeeringsPeeringExposeNat,
    GatewayAgentPeeringsPeeringExposeNatStateful, GatewayAgentPeeringsPeeringExposeNatStateless,
};

/// Generate a legal value for `GatewayAgentPeeringsPeeringExpose`
///
/// This is not exhaustive over all legal values due to the complexity
/// of doing this.  The cidr generators in particular are not exhaustive.
pub struct LegalValueExposeGenerator<'a> {
    subnets: &'a BTreeMap<String, Prefix>,
}

impl<'a> LegalValueExposeGenerator<'a> {
    #[must_use]
    pub fn new(subnets: &'a BTreeMap<String, Prefix>) -> Self {
        Self { subnets }
    }
}

fn generate_v4_prefixes<D: Driver>(d: &mut D, count: u16) -> Option<Vec<String>> {
    let cidr4_gen =
        UniqueV4CidrGenerator::new(count, d.gen_u8(Bound::Included(&0), Bound::Included(&32))?);
    cidr4_gen.generate(d)
}

fn generate_v6_prefixes<D: Driver>(d: &mut D, count: u16) -> Option<Vec<String>> {
    let cidr6_gen =
        UniqueV6CidrGenerator::new(count, d.gen_u8(Bound::Included(&0), Bound::Included(&128))?);
    cidr6_gen.generate(d)
}

fn generate_prefixes<D: Driver>(d: &mut D, v4_count: u16, v6_count: u16) -> Option<Vec<String>> {
    let mut prefixes = Vec::with_capacity(usize::from(v4_count) + usize::from(v6_count));
    if v4_count > 0 {
        let v4_prefixes = generate_v4_prefixes(d, v4_count)?;
        prefixes.extend(v4_prefixes);
    }
    if v6_count > 0 {
        let v6_prefixes = generate_v6_prefixes(d, v6_count)?;
        prefixes.extend(v6_prefixes);
    }
    Some(prefixes)
}

impl ValueGenerator for LegalValueExposeGenerator<'_> {
    type Output = GatewayAgentPeeringsPeeringExpose;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let num_ips = d.gen_u16(Bound::Included(&1), Bound::Included(&16))?;
        let num_nots = d.gen_u16(Bound::Included(&0), Bound::Included(&16))?;
        let num_subnets = std::cmp::max(
            self.subnets.len(),
            usize::from(d.gen_u8(Bound::Included(&0), Bound::Included(&16))?),
        );

        let num_as = d.gen_u16(Bound::Included(&0), Bound::Included(&16))?;
        let num_as_not = d.gen_u16(Bound::Included(&0), Bound::Included(&16))?;

        let num_v4_ips = d.gen_u16(Bound::Included(&0), Bound::Included(&num_ips))?;
        let num_v6_ips = num_ips - num_v4_ips;
        let num_v4_nots = d.gen_u16(Bound::Included(&0), Bound::Included(&num_nots))?;
        let num_v6_nots = num_nots - num_v4_nots;

        let num_v4_as = d.gen_u16(Bound::Included(&0), Bound::Included(&num_as))?;
        let num_v6_as = num_as - num_v4_as;
        let num_v4_not_as = d.gen_u16(Bound::Included(&0), Bound::Included(&num_as_not))?;
        let num_v6_not_as = num_as_not - num_v4_not_as;

        let ips = generate_prefixes(d, num_v4_ips, num_v6_ips)?
            .into_iter()
            .map(|p| GatewayAgentPeeringsPeeringExposeIps {
                cidr: Some(p),
                not: None,
                vpc_subnet: None,
            })
            .collect::<Vec<_>>();
        let nots = generate_prefixes(d, num_v4_nots, num_v6_nots)?
            .into_iter()
            .map(|p| GatewayAgentPeeringsPeeringExposeIps {
                cidr: None,
                not: Some(p),
                vpc_subnet: None,
            })
            .collect::<Vec<_>>();
        let r#as = generate_prefixes(d, num_v4_as, num_v6_as)?
            .into_iter()
            .map(|p| GatewayAgentPeeringsPeeringExposeAs {
                cidr: Some(p),
                not: None,
            });
        let not_as = generate_prefixes(d, num_v4_not_as, num_v6_not_as)?
            .into_iter()
            .map(|p| GatewayAgentPeeringsPeeringExposeAs {
                cidr: None,
                not: Some(p),
            });

        let mut subnets = Vec::new();
        let mut subnet_iter = self.subnets.iter();
        for _ in 0..num_subnets {
            let Some((name, _)) = subnet_iter.next() else {
                break;
            };
            subnets.push(GatewayAgentPeeringsPeeringExposeIps {
                cidr: None,
                not: None,
                vpc_subnet: Some(name.clone()),
            });
        }

        let mut final_ips = Vec::with_capacity(ips.len() + nots.len() + subnets.len());
        final_ips.extend(ips);
        final_ips.extend(nots);
        final_ips.extend(subnets);

        let mut final_as = Vec::with_capacity(r#as.len() + not_as.len());
        final_as.extend(r#as);
        final_as.extend(not_as);
        let has_as = !final_as.is_empty();

        Some(GatewayAgentPeeringsPeeringExpose {
            r#as: Some(final_as).filter(|f| !f.is_empty()),
            ips: Some(final_ips).filter(|f| !f.is_empty()),
            nat: if has_as {
                Some(
                    d.produce::<LegalValue<GatewayAgentPeeringsPeeringExposeNat>>()?
                        .take(),
                )
            } else {
                None
            },
        })
    }
}

// This is not exhaustive as it does not generate all possible time
// strings, just 0 to 2*3600 seconds
impl TypeGenerator for LegalValue<GatewayAgentPeeringsPeeringExposeNat> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let is_stateful = d.produce::<bool>()?;
        if is_stateful {
            let idle_timeout_secs = d.gen_u64(Bound::Included(&0), Bound::Included(&(2 * 3600)))?;
            let idle_timeout = std::time::Duration::from_secs(idle_timeout_secs);
            Some(LegalValue(GatewayAgentPeeringsPeeringExposeNat {
                stateless: None,
                stateful: Some(GatewayAgentPeeringsPeeringExposeNatStateful {
                    idle_timeout: Some(idle_timeout),
                }),
            }))
        } else {
            Some(LegalValue(GatewayAgentPeeringsPeeringExposeNat {
                stateful: None,
                stateless: Some(GatewayAgentPeeringsPeeringExposeNatStateless {}),
            }))
        }
    }
}
