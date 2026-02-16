// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use crate::bolero::support::generate_prefixes;
use crate::bolero::{LegalValue, SubnetMap};
use crate::gateway_agent_crd::{
    GatewayAgentPeeringsPeeringExpose, GatewayAgentPeeringsPeeringExposeAs,
    GatewayAgentPeeringsPeeringExposeIps, GatewayAgentPeeringsPeeringExposeNat,
    GatewayAgentPeeringsPeeringExposeNatMasquerade, GatewayAgentPeeringsPeeringExposeNatStatic,
};

/// Generate a legal value for `GatewayAgentPeeringsPeeringExpose`
///
/// This is not exhaustive over all legal values due to the complexity of doing this. For example,
/// the CIDR generators are not exhaustive; and we use a single port range for all CIDRs rather than
/// trying different combinations.
pub struct LegalValueExposeGenerator<'a> {
    subnets: &'a SubnetMap,
}

impl<'a> LegalValueExposeGenerator<'a> {
    #[must_use]
    pub fn new(subnets: &'a SubnetMap) -> Self {
        Self { subnets }
    }
}

impl ValueGenerator for LegalValueExposeGenerator<'_> {
    type Output = GatewayAgentPeeringsPeeringExpose;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let num_ips = d.gen_u16(Bound::Included(&1), Bound::Included(&16))?;
        let num_nots = d.gen_u16(Bound::Included(&0), Bound::Included(&16))?;
        let num_subnets = std::cmp::max(
            self.subnets.len(),
            d.gen_usize(Bound::Included(&0), Bound::Included(&16))?,
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
            default: None,
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
// strings, just 0 to 2*3600 seconds.
//
// FIXME: Add support for port forwarding
impl TypeGenerator for LegalValue<GatewayAgentPeeringsPeeringExposeNat> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let nat_mode = d.produce::<u16>()? % 2;
        match nat_mode {
            0 => {
                let idle_timeout_secs =
                    d.gen_u64(Bound::Included(&0), Bound::Included(&(2 * 3600)))?;
                let idle_timeout = std::time::Duration::from_secs(idle_timeout_secs);
                Some(LegalValue(GatewayAgentPeeringsPeeringExposeNat {
                    masquerade: Some(GatewayAgentPeeringsPeeringExposeNatMasquerade {
                        idle_timeout: Some(idle_timeout.into()),
                    }),
                    port_forward: None,
                    r#static: None,
                }))
            }
            1 => Some(LegalValue(GatewayAgentPeeringsPeeringExposeNat {
                masquerade: None,
                port_forward: None,
                r#static: Some(GatewayAgentPeeringsPeeringExposeNatStatic {}),
            })),
            // 2 => Some(LegalValue(GatewayAgentPeeringsPeeringExposeNat {
            //     masquerade: None,
            //     port_forward: Some(GatewayAgentPeeringsPeeringExposeNatPortForward {}),
            //     r#static: None,
            // })),
            _ => unreachable!(),
        }
    }
}
