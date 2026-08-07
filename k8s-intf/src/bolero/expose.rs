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

/// The most prefixes either side of an expose carries, where the flavour allows more than one.
///
/// Small on purpose. Nothing here needs a long list to be interesting, and a long one costs
/// throughput and makes a counterexample unreadable.
const MAX_PREFIXES: u8 = 3;

/// The widest port range port forwarding maps. Same reasoning.
const MAX_PORTS: u16 = 1024;

/// Generates exposes that [`crate::gateway_agent_crd::GatewayAgent`] validation accepts.
///
/// **Valid by construction rather than by generate-and-reject**, so every case reaches the code
/// under test. That matters more than it sounds: the generator this replaced drew the prefixes first
/// and chose a NAT flavour afterwards, and since each flavour constrains the shape, essentially no
/// expose it produced could be accepted. Peerings were generated in their tens of thousands and none
/// ever survived validation, so nothing downstream of it -- the NAT tables, the ACLs, the internal
/// config builder -- had ever seen one.
///
/// The rules each flavour has to satisfy, all of which `VpcExpose::validate` enforces:
///
/// * the private list is non-empty, and non-empty again once exclusions are applied;
/// * every prefix in the expose is of one address family, since NAT46 and NAT64 are unsupported;
/// * no prefix overlaps a special-use range, hence [`blocks`];
/// * a flavour that translates has a non-empty translation range;
/// * **static NAT**: the two sides cover the same number of address-port pairs, which one prefix of
///   equal length on each side satisfies;
/// * **port forwarding**: exactly one prefix per side of equal length, a port range on each, the two
///   ranges of equal size, and no exclusion prefixes at all.
#[derive(Debug, Clone)]
pub struct ExposeGenerator<'a> {
    flavour: NatFlavour,
    family: AddressFamily,
    subnets: &'a SubnetMap,
}

impl<'a> ExposeGenerator<'a> {
    #[must_use]
    pub fn new(flavour: NatFlavour, family: AddressFamily, subnets: &'a SubnetMap) -> Self {
        Self {
            flavour,
            family,
            subnets,
        }
    }

    /// A prefix length usable on either side of an expose in this family.
    fn length<D: Driver>(&self, d: &mut D) -> Option<u8> {
        d.gen_u8(
            Bound::Included(&blocks::min_len(self.family)),
            Bound::Included(&blocks::max_len(self.family)),
        )
    }

    /// The names of this vpc's subnets that are of the expose's family.
    ///
    /// A named subnet contributes its own prefix, so naming one of the other family makes the
    /// expose mixed just as surely as writing the prefix out would.
    fn matching_subnets(&self) -> Vec<&'a String> {
        self.subnets
            .iter()
            .filter(|(_, prefix)| prefix.is_ipv4() == self.family.is_v4())
            .map(|(name, _)| name)
            .collect()
    }

    /// An exclusion strictly inside `parent`, so it cannot remove all of it.
    ///
    /// Excluding a prefix from itself leaves nothing, and an expose whose private list is empty
    /// after exclusions is refused. A longer prefix inside the parent always leaves something.
    fn exclusion<D: Driver>(&self, d: &mut D, parent: &str, private: bool) -> Option<String> {
        let (_, len) = parent.split_once('/')?;
        let len: u8 = len.parse().ok()?;
        let max = blocks::max_len(self.family);
        if len >= max {
            return None;
        }
        let longer = d.gen_u8(Bound::Excluded(&len), Bound::Included(&max))?;
        if private {
            blocks::private(d, self.family, longer)
        } else {
            blocks::public(d, self.family, longer)
        }
    }

    /// A port range, and a second of the same size, for port forwarding.
    fn port_pair<D: Driver>(d: &mut D) -> Option<(String, String)> {
        let size = d.gen_u16(Bound::Included(&1), Bound::Included(&MAX_PORTS))?;
        // port 0 is forbidden on either side, so both starts are at least one
        let first_start = d.gen_u16(Bound::Included(&1), Bound::Included(&(65535 - size + 1)))?;
        let second_start = d.gen_u16(Bound::Included(&1), Bound::Included(&(65535 - size + 1)))?;
        // `start + (size - 1)`, not `start + size - 1`: the latter groups as `(start + size) - 1`
        // and overflows `u16` for a range that ends exactly at 65535.
        Some((
            format!("{first_start}-{}", first_start + (size - 1)),
            format!("{second_start}-{}", second_start + (size - 1)),
        ))
    }

    /// The NAT block for a flavour that translates.
    ///
    /// Only called when [`NatFlavour::needs_translation`] holds, so the `None` arm cannot be reached;
    /// returning the driver's `None` there rather than panicking costs nothing and keeps the return
    /// type a single `Option`.
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
        // Static NAT and port forwarding both need one prefix per side of equal length. The other
        // flavours may carry several, and may name vpc subnets alongside them.
        let paired = matches!(self.flavour, NatFlavour::Static | NatFlavour::PortForward);

        let mut ips = Vec::new();
        let mut translations = Vec::new();

        if paired {
            let len = self.length(d)?;
            let private = blocks::private(d, self.family, len)?;
            let public = blocks::public(d, self.family, len)?;
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
            for _ in 0..count {
                let len = self.length(d)?;
                ips.push(GatewayAgentPeeringsPeeringExposeIps {
                    cidr: Some(blocks::private(d, self.family, len)?),
                    not: None,
                    vpc_subnet: None,
                });
            }
            if self.flavour.needs_translation() {
                let count = d.gen_u8(Bound::Included(&1), Bound::Included(&MAX_PREFIXES))?;
                for _ in 0..count {
                    let len = self.length(d)?;
                    translations.push(GatewayAgentPeeringsPeeringExposeAs {
                        cidr: Some(blocks::public(d, self.family, len)?),
                        not: None,
                    });
                }
            }

            // Naming some of the vpc's own subnets is the ordinary way to write an expose, so draw a
            // prefix of them. Only those of this expose's family.
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

        // Exclusions, where the flavour allows them. Each sits strictly inside a prefix already in
        // the list, so it can never remove all of it.
        if self.flavour.allows_exclusions() && d.produce::<bool>()? {
            let parents: Vec<String> = ips.iter().filter_map(|e| e.cidr.clone()).collect();
            if let Some(parent) = parents.first()
                && let Some(exclusion) = self.exclusion(d, parent, true)
            {
                ips.push(GatewayAgentPeeringsPeeringExposeIps {
                    cidr: None,
                    not: Some(exclusion),
                    vpc_subnet: None,
                });
            }
            let parents: Vec<String> = translations.iter().filter_map(|e| e.cidr.clone()).collect();
            if let Some(parent) = parents.first()
                && let Some(exclusion) = self.exclusion(d, parent, false)
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

/// Draws exposes of any flavour and family, for a caller that does not want to choose either.
///
/// [`ExposeGenerator`] takes both because they have to be settled before the prefixes are drawn, and
/// because a property aiming at one flavour needs to say which. A caller that just wants "any legal
/// expose" -- a converter test, say -- can use this instead.
#[derive(Debug, Clone)]
pub struct AnyExposeGenerator<'a> {
    subnets: &'a SubnetMap,
}

impl<'a> AnyExposeGenerator<'a> {
    #[must_use]
    pub fn new(subnets: &'a SubnetMap) -> Self {
        Self { subnets }
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
        ExposeGenerator::new(flavour, family, self.subnets).generate(d)
    }
}
