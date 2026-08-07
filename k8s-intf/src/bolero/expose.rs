// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator};

use crate::bolero::support::generate_prefixes;
use crate::bolero::{LegalValue, SubnetMap};
use crate::gateway_agent_crd::{
    GatewayAgentPeeringsPeeringExpose, GatewayAgentPeeringsPeeringExposeAs,
    GatewayAgentPeeringsPeeringExposeIps, GatewayAgentPeeringsPeeringExposeNat,
    GatewayAgentPeeringsPeeringExposeNatMasquerade,
    GatewayAgentPeeringsPeeringExposeNatPortForward,
    GatewayAgentPeeringsPeeringExposeNatPortForwardPorts,
    GatewayAgentPeeringsPeeringExposeNatPortForwardPortsProto,
    GatewayAgentPeeringsPeeringExposeNatStatic,
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
        // `min`, not `max`: with `max` the count was always at least the number of subnets there
        // are, and the loop below stops when they run out, so every expose named all of them and
        // the count never varied.
        let num_subnets = std::cmp::min(
            self.subnets.len(),
            d.gen_usize(Bound::Included(&0), Bound::Included(&16))?,
        );

        let num_as = d.gen_u16(Bound::Included(&0), Bound::Included(&16))?;
        let num_as_not = d.gen_u16(Bound::Included(&0), Bound::Included(&16))?;

        // One address family per expose.
        //
        // A `VpcExpose` must be single-family: validation refuses a mixed one with
        // `ConfigError::InconsistentIpVersion`. Splitting each count into a v4 part and a v6 part --
        // as this used to -- makes a mixed expose the overwhelmingly likely outcome, so no expose
        // ever survived validation and nothing downstream of it ever saw a peering.
        let v4 = d.produce::<bool>()?;
        let (num_v4_ips, num_v6_ips) = if v4 { (num_ips, 0) } else { (0, num_ips) };
        let (num_v4_nots, num_v6_nots) = if v4 { (num_nots, 0) } else { (0, num_nots) };
        let (num_v4_as, num_v6_as) = if v4 { (num_as, 0) } else { (0, num_as) };
        let (num_v4_not_as, num_v6_not_as) = if v4 { (num_as_not, 0) } else { (0, num_as_not) };

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

        // Only subnets of the family this expose settled on: a named subnet contributes its own
        // prefix, so naming one of the other family makes the expose mixed just as surely as
        // writing the prefix out would.
        let mut subnets = Vec::new();
        let mut subnet_iter = self
            .subnets
            .iter()
            .filter(|(_, prefix)| prefix.is_ipv4() == v4);
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
impl TypeGenerator for LegalValue<GatewayAgentPeeringsPeeringExposeNat> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let nat_mode = d.produce::<u16>()? % 3;
        let idle_timeout_secs = d.gen_u64(Bound::Included(&0), Bound::Included(&(2 * 3600)))?;
        let idle_timeout = std::time::Duration::from_secs(idle_timeout_secs);
        match nat_mode {
            0 => Some(LegalValue(GatewayAgentPeeringsPeeringExposeNat {
                masquerade: Some(GatewayAgentPeeringsPeeringExposeNatMasquerade {
                    idle_timeout: Some(idle_timeout.into()),
                }),
                port_forward: None,
                r#static: None,
            })),
            1 => Some(LegalValue(GatewayAgentPeeringsPeeringExposeNat {
                masquerade: None,
                port_forward: None,
                r#static: Some(GatewayAgentPeeringsPeeringExposeNatStatic {}),
            })),
            2 => {
                // Generate a valid port range
                let bound1 = d.gen_u16(Bound::Included(&1), Bound::Included(&65535))?;
                let bound2 = d.gen_u16(Bound::Included(&1), Bound::Included(&65535))?;
                let start = bound1.min(bound2);
                let end = bound1.max(bound2);
                let port_range = format!("{start}-{end}");

                // Generate another valid port range of the same size
                let port_range_size = (end - start) as usize + 1;
                let max_new_start = u16::try_from(65536 - port_range_size).unwrap();
                let new_bound = d.gen_u16(Bound::Included(&0), Bound::Included(&max_new_start))?;
                let new_port_range = format!(
                    "{new_bound}-{}",
                    new_bound + u16::try_from(port_range_size - 1).unwrap()
                );

                Some(LegalValue(GatewayAgentPeeringsPeeringExposeNat {
                    masquerade: None,
                    port_forward: Some(GatewayAgentPeeringsPeeringExposeNatPortForward {
                        idle_timeout: Some(idle_timeout.into()),
                        ports: Some(vec![GatewayAgentPeeringsPeeringExposeNatPortForwardPorts {
                            r#as: Some(new_port_range),
                            port: Some(port_range),
                            proto: match d.produce::<u32>()? % 3 {
                                0 => Some(
                                    GatewayAgentPeeringsPeeringExposeNatPortForwardPortsProto::Tcp,
                                ),
                                1 => Some(
                                    GatewayAgentPeeringsPeeringExposeNatPortForwardPortsProto::Udp,
                                ),
                                2 => None,
                                _ => unreachable!(),
                            },
                        }]),
                    }),
                    r#static: None,
                }))
            }
            _ => unreachable!(),
        }
    }
}
