// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::support::blocks;
use crate::bolero::{AddressFamily, NatFlavour, SubnetMap};
use crate::gateway_agent_crd::{
    GatewayAgentPeeringsPeeringExpose, GatewayAgentPeeringsPeeringExposeAs,
    GatewayAgentPeeringsPeeringExposeIps, GatewayAgentPeeringsPeeringExposeNat,
    GatewayAgentPeeringsPeeringExposeNatMasquerade,
    GatewayAgentPeeringsPeeringExposeNatPortForward,
    GatewayAgentPeeringsPeeringExposeNatPortForwardPorts,
    GatewayAgentPeeringsPeeringExposeNatPortForwardPortsProto,
    GatewayAgentPeeringsPeeringExposeNatStatic,
};

/// The most prefixes an expose will offer on either side.
const MAX_PREFIXES: u8 = 3;

const MAX_PORTS: u16 = 1024;

#[derive(Debug, Clone)]
pub struct ExposeGenerator<'a> {
    flavour: NatFlavour,
    family: AddressFamily,
    which: Which,
    subnets: &'a SubnetMap,
}

#[derive(Debug, Clone, Copy)]
pub struct Which {
    pub slot: u8,
    pub index: u8,
    pub count: u8,
}

impl Which {
    #[must_use]
    pub fn only(slot: u8) -> Self {
        Self {
            slot,
            index: 0,
            count: 1,
        }
    }

    #[must_use]
    pub fn nth(slot: u8, index: u8, count: u8) -> Self {
        Self {
            slot,
            index,
            count: count.max(index.saturating_add(1)),
        }
    }
}

impl<'a> ExposeGenerator<'a> {
    #[must_use]
    pub fn new(
        flavour: NatFlavour,
        family: AddressFamily,
        which: Which,
        subnets: &'a SubnetMap,
    ) -> Self {
        Self {
            flavour,
            family,
            which,
            subnets,
        }
    }

    fn length<D: Driver>(&self, d: &mut D, at: blocks::At) -> Option<u8> {
        d.gen_u8(
            Bound::Included(&blocks::min_len_at(self.family, at)),
            Bound::Included(&blocks::max_len(self.family)),
        )
    }

    fn matching_subnets(&self) -> Vec<&'a String> {
        self.subnets
            .iter()
            .filter(|(_, prefix)| prefix.is_ipv4() == self.family.is_v4())
            .map(|(name, _)| name)
            .enumerate()
            .filter(|(index, _)| {
                index % usize::from(self.which.count) == usize::from(self.which.index)
            })
            .map(|(_, name)| name)
            .collect()
    }

    fn exclusion<D: Driver>(
        &self,
        d: &mut D,
        parent: &str,
        at: blocks::At,
        private: bool,
    ) -> Option<String> {
        let (_, len) = parent.split_once('/')?;
        let len: u8 = len.parse().ok()?;
        let max = blocks::max_len(self.family);
        if len >= max {
            return None;
        }
        let longer = d.gen_u8(Bound::Excluded(&len), Bound::Included(&max))?;
        if private {
            blocks::private(d, self.family, at, longer)
        } else {
            blocks::public(d, self.family, at, longer)
        }
    }

    fn port_pair<D: Driver>(d: &mut D) -> Option<(String, String)> {
        let size = d.gen_u16(Bound::Included(&1), Bound::Included(&MAX_PORTS))?;
        let first_start = d.gen_u16(Bound::Included(&1), Bound::Included(&(65535 - size + 1)))?;
        let second_start = d.gen_u16(Bound::Included(&1), Bound::Included(&(65535 - size + 1)))?;
        Some((
            format!("{first_start}-{}", first_start + (size - 1)),
            format!("{second_start}-{}", second_start + (size - 1)),
        ))
    }

    fn translation<D: Driver>(&self, d: &mut D) -> Option<GatewayAgentPeeringsPeeringExposeNat> {
        let idle_secs = d.gen_u64(Bound::Included(&0), Bound::Included(&(2 * 3600)))?;
        let idle = std::time::Duration::from_secs(idle_secs);
        Some(match self.flavour {
            NatFlavour::None => return None,
            NatFlavour::Masquerade => GatewayAgentPeeringsPeeringExposeNat {
                masquerade: Some(GatewayAgentPeeringsPeeringExposeNatMasquerade {
                    idle_timeout: Some(idle.into()),
                }),
                port_forward: None,
                r#static: None,
            },
            NatFlavour::Static => GatewayAgentPeeringsPeeringExposeNat {
                masquerade: None,
                port_forward: None,
                r#static: Some(GatewayAgentPeeringsPeeringExposeNatStatic {}),
            },
            NatFlavour::PortForward => {
                let (port, r#as) = Self::port_pair(d)?;
                GatewayAgentPeeringsPeeringExposeNat {
                    masquerade: None,
                    port_forward: Some(GatewayAgentPeeringsPeeringExposeNatPortForward {
                        idle_timeout: Some(idle.into()),
                        ports: Some(vec![GatewayAgentPeeringsPeeringExposeNatPortForwardPorts {
                            r#as: Some(r#as),
                            port: Some(port),
                            proto: match d.gen_u8(Bound::Included(&0), Bound::Included(&2))? {
                                0 => Some(
                                    GatewayAgentPeeringsPeeringExposeNatPortForwardPortsProto::Tcp,
                                ),
                                1 => Some(
                                    GatewayAgentPeeringsPeeringExposeNatPortForwardPortsProto::Udp,
                                ),
                                _ => None,
                            },
                        }]),
                    }),
                    r#static: None,
                }
            }
        })
    }
}

impl ValueGenerator for ExposeGenerator<'_> {
    type Output = GatewayAgentPeeringsPeeringExpose;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let paired = matches!(self.flavour, NatFlavour::Static | NatFlavour::PortForward);

        let mut ips = Vec::new();
        let mut translations = Vec::new();

        if paired {
            let at = blocks::At::whole(self.which.slot);
            let len = self.length(d, at)?;
            let private = blocks::private(d, self.family, at, len)?;
            let public = blocks::public(d, self.family, at, len)?;
            ips.push(GatewayAgentPeeringsPeeringExposeIps {
                cidr: Some(private),
                not: None,
                vpc_subnet: None,
            });
            translations.push(GatewayAgentPeeringsPeeringExposeAs {
                cidr: Some(public),
                not: None,
            });
        } else {
            let count = d.gen_u8(Bound::Included(&1), Bound::Included(&MAX_PREFIXES))?;
            for sub in 0..count {
                let at = blocks::At::nth(self.which.slot, sub, count);
                let len = self.length(d, at)?;
                ips.push(GatewayAgentPeeringsPeeringExposeIps {
                    cidr: Some(blocks::private(d, self.family, at, len)?),
                    not: None,
                    vpc_subnet: None,
                });
            }
            if self.flavour.needs_translation() {
                let count = d.gen_u8(Bound::Included(&1), Bound::Included(&MAX_PREFIXES))?;
                for sub in 0..count {
                    let at = blocks::At::nth(self.which.slot, sub, count);
                    let len = self.length(d, at)?;
                    translations.push(GatewayAgentPeeringsPeeringExposeAs {
                        cidr: Some(blocks::public(d, self.family, at, len)?),
                        not: None,
                    });
                }
            }

            let named = self.matching_subnets();
            if !named.is_empty() {
                let take = d.gen_usize(Bound::Included(&0), Bound::Included(&named.len()))?;
                for name in named.into_iter().take(take) {
                    ips.push(GatewayAgentPeeringsPeeringExposeIps {
                        cidr: None,
                        not: None,
                        vpc_subnet: Some(name.clone()),
                    });
                }
            }
        }

        if self.flavour.allows_exclusions() && d.produce::<bool>()? {
            let parents: Vec<String> = ips.iter().filter_map(|e| e.cidr.clone()).collect();
            let first =
                blocks::At::nth(self.which.slot, 0, u8::try_from(parents.len()).unwrap_or(1));
            if let Some(parent) = parents.first()
                && let Some(exclusion) = self.exclusion(d, parent, first, true)
            {
                ips.push(GatewayAgentPeeringsPeeringExposeIps {
                    cidr: None,
                    not: Some(exclusion),
                    vpc_subnet: None,
                });
            }
            let parents: Vec<String> = translations.iter().filter_map(|e| e.cidr.clone()).collect();
            let first =
                blocks::At::nth(self.which.slot, 0, u8::try_from(parents.len()).unwrap_or(1));
            if let Some(parent) = parents.first()
                && let Some(exclusion) = self.exclusion(d, parent, first, false)
            {
                translations.push(GatewayAgentPeeringsPeeringExposeAs {
                    cidr: None,
                    not: Some(exclusion),
                });
            }
        }

        Some(GatewayAgentPeeringsPeeringExpose {
            r#as: Some(translations).filter(|t| !t.is_empty()),
            ips: Some(ips).filter(|i| !i.is_empty()),
            default: None,
            nat: if self.flavour.needs_translation() {
                Some(self.translation(d)?)
            } else {
                None
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct AnyExposeGenerator<'a> {
    which: Which,
    subnets: &'a SubnetMap,
}

impl<'a> AnyExposeGenerator<'a> {
    #[must_use]
    pub fn new(slot: u8, subnets: &'a SubnetMap) -> Self {
        Self {
            which: Which::only(slot),
            subnets,
        }
    }
}

impl ValueGenerator for AnyExposeGenerator<'_> {
    type Output = GatewayAgentPeeringsPeeringExpose;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let flavours = NatFlavour::all();
        let families = AddressFamily::all();
        let flavour =
            flavours[d.gen_usize(Bound::Included(&0), Bound::Excluded(&flavours.len()))?];
        let family =
            families[d.gen_usize(Bound::Included(&0), Bound::Excluded(&families.len()))?];
        ExposeGenerator::new(flavour, family, self.which, self.subnets).generate(d)
    }
}
