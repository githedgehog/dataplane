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
    which: Which,
    subnets: &'a SubnetMap,
}

/// Which expose this is, at the two levels that matter for keeping prefixes apart.
///
/// `slot` is the block slot the prefixes come from, and it is unique across the *whole*
/// configuration -- see [`blocks::expose_slot`], which explains why the vpc has to be part of it.
/// Every prefix this generator writes out sits inside that slot, so no two exposes anywhere can
/// overlap.
///
/// `index` and `count` are this expose's place within its own manifest, which the slot does not
/// capture. They are needed because a *named* subnet contributes its prefix just as surely as a
/// written-out one does, and the subnets live in slots of their own: two exposes of one manifest
/// naming the same subnet share a prefix. So the manifest's subnets are dealt out round-robin,
/// `index` taking every `count`th one.
#[derive(Debug, Clone, Copy)]
pub struct Which {
    pub slot: u8,
    pub index: u8,
    pub count: u8,
}

impl Which {
    /// A lone expose, for a caller generating one at a time.
    #[must_use]
    pub fn only(slot: u8) -> Self {
        Self {
            slot,
            index: 0,
            count: 1,
        }
    }

    /// Expose `index` of `count` in a manifest, drawing from `slot`.
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

    /// A prefix length that fits inside `at`.
    ///
    /// The floor is the sub-slot's own length, not the block's: an expose splitting its slot between
    /// several prefixes has less room for each, so it has to draw longer ones.
    fn length<D: Driver>(&self, d: &mut D, at: blocks::At) -> Option<u8> {
        d.gen_u8(
            Bound::Included(&blocks::min_len_at(self.family, at)),
            Bound::Included(&blocks::max_len(self.family)),
        )
    }

    /// The names of this vpc's subnets that are of the expose's family, and that are this expose's
    /// to name.
    ///
    /// Two filters. Family, because a named subnet contributes its own prefix, so naming one of the
    /// other family makes the expose mixed just as surely as writing the prefix out would. And the
    /// round-robin share, because a subnet named by two exposes of one manifest is a prefix those two
    /// exposes have in common, which is the overlap the whole slot scheme exists to prevent.
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

    /// An exclusion strictly inside `parent`, so it cannot remove all of it.
    ///
    /// Excluding a prefix from itself leaves nothing, and an expose whose private list is empty
    /// after exclusions is refused. A longer prefix inside the parent always leaves something.
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
        // The parent's own sub-slot, so an exclusion can only ever shrink the prefix it belongs
        // to and never eats into a sibling's.
        if private {
            blocks::private(d, self.family, at, longer)
        } else {
            blocks::public(d, self.family, at, longer)
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
            // The count first, then a sub-slot per prefix: an expose's own prefixes have to be
            // disjoint from each other, not just from the other exposes'.
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

/// Draws exposes of any flavour and family, for a caller that does not want to choose either.
///
/// [`ExposeGenerator`] takes both because they have to be settled before the prefixes are drawn, and
/// because a property aiming at one flavour needs to say which. A caller that just wants "any legal
/// expose" -- a converter test, say -- can use this instead.
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
