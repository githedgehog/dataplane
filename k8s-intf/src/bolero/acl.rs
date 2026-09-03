// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::gateway_agent_crd::{
    GatewayAgentPeeringsAcl, GatewayAgentPeeringsAclDefault, GatewayAgentPeeringsAclRules,
    GatewayAgentPeeringsAclRulesAction, GatewayAgentPeeringsAclRulesMatch,
    GatewayAgentPeeringsAclRulesMatchDst, GatewayAgentPeeringsAclRulesMatchSrc,
    GatewayAgentPeeringsAclRulesScope, GatewayAgentPeeringsPeering,
};

const MAX_RULES: u8 = 3;
const MAX_MATCH_ENTRIES: u8 = 3;

/// One entry on one side of a rule's match, before it is split into a `Src` or a `Dst`.
///
/// The two generated types carry identical fields but are distinct, so the draw happens
/// once here and is mapped into whichever the caller needs.
struct Entry {
    cidr: Option<String>,
    vpc_subnet: Option<String>,
    ports: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct SideFacts {
    pub vpc: String,
    pub native: Vec<String>,
    pub advertised: Vec<String>,
    /// Subnet names a rule may write in place of a `native` cidr.
    ///
    /// A match entry resolves `vpcSubnet` against the subnets of the vpc on its own
    /// side of the rule, so the two sides cannot share one list. Only subnets an
    /// expose actually names belong here: the validator refuses a rule whose match
    /// covers no traffic the manifest carries, so a subnet this peering does not
    /// expose is not a legal thing to name.
    pub native_subnets: Vec<String>,
    /// The same, for the side of a rule that matches on advertised addresses.
    ///
    /// An expose that translates advertises its `as` prefixes rather than its own, and
    /// there is no subnet name for those, so a translating expose contributes nothing.
    pub advertised_subnets: Vec<String>,
    pub restricts_ports: bool,
    pub all_stateful: bool,
}

impl SideFacts {
    #[must_use]
    pub fn of(vpc: &str, manifest: &GatewayAgentPeeringsPeering) -> Self {
        let exposes = manifest.expose.as_deref().unwrap_or(&[]);
        let mut native = Vec::new();
        let mut advertised = Vec::new();
        let mut native_subnets = Vec::new();
        let mut advertised_subnets = Vec::new();
        let mut restricts_ports = false;
        let mut all_stateful = !exposes.is_empty();

        for expose in exposes {
            let ips: Vec<String> = expose
                .ips
                .iter()
                .flatten()
                .filter_map(|ip| ip.cidr.clone())
                .collect();
            let subnets: Vec<String> = expose
                .ips
                .iter()
                .flatten()
                .filter_map(|ip| ip.vpc_subnet.clone())
                .collect();
            let translations: Vec<String> = expose
                .r#as
                .iter()
                .flatten()
                .filter_map(|entry| entry.cidr.clone())
                .collect();

            native.extend(ips.iter().cloned());
            native_subnets.extend(subnets.iter().cloned());
            if translations.is_empty() {
                advertised.extend(ips);
                advertised_subnets.extend(subnets);
            } else {
                advertised.extend(translations);
            }

            let nat = expose.nat.as_ref();
            if nat.is_some_and(|nat| nat.port_forward.is_some()) {
                restricts_ports = true;
            }
            if !nat.is_some_and(|nat| nat.masquerade.is_some() || nat.port_forward.is_some()) {
                all_stateful = false;
            }
        }

        Self {
            vpc: vpc.to_string(),
            native,
            advertised,
            native_subnets,
            advertised_subnets,
            restricts_ports,
            all_stateful,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AclGenerator {
    left: SideFacts,
    right: SideFacts,
}

impl AclGenerator {
    #[must_use]
    pub fn new(left: SideFacts, right: SideFacts) -> Self {
        Self { left, right }
    }

    fn ports<D: Driver>(d: &mut D) -> Option<Vec<String>> {
        let count = d.gen_u8(Bound::Included(&1), Bound::Included(&2))?;
        let mut out = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let first = d.gen_u16(Bound::Included(&1), Bound::Included(&65535))?;
            if d.produce::<bool>()? {
                out.push(format!("{first}"));
            } else {
                let second = d.gen_u16(Bound::Included(&1), Bound::Included(&65535))?;
                out.push(format!("{}-{}", first.min(second), first.max(second)));
            }
        }
        Some(out)
    }

    fn prefix<D: Driver>(d: &mut D, choices: &[String]) -> Option<String> {
        crate::bolero::support::choose(d, choices)
    }

    /// Draw one side's address match: nothing, a cidr, or the name of one of its subnets.
    ///
    /// At most one of the two is ever `Some`. A side naming either is a branch of the
    /// converter's `resolve_prefix`, and nothing used to draw the subnet name, so that
    /// branch and the unknown-subnet refusal behind it were unreachable from here.
    fn address<D: Driver>(
        d: &mut D,
        cidrs: &[String],
        subnets: &[String],
    ) -> Option<(Option<String>, Option<String>)> {
        if !d.produce::<bool>()? {
            return Some((None, None));
        }
        if !subnets.is_empty() && d.produce::<bool>()? {
            return Some((None, crate::bolero::support::choose(d, subnets)));
        }
        Some((Self::prefix(d, cidrs), None))
    }

    /// Draw the entries on one side of a rule's match.
    ///
    /// A side is a list, and until now this drew exactly one entry for it. A list of one
    /// has no order, so the permutation that reorders these lists could never change
    /// anything, and the property comparing a configuration against its own reordering
    /// was being handed an identical input every time.
    ///
    /// An entry naming neither an address nor a port means "everything", and the
    /// converter answers one by discarding the whole side, so an entry that would come
    /// out empty is dropped rather than written.
    fn entries<D: Driver>(
        d: &mut D,
        cidrs: &[String],
        subnets: &[String],
        may_use_ports: bool,
    ) -> Option<Vec<Entry>> {
        let count = d.gen_u8(Bound::Included(&1), Bound::Included(&MAX_MATCH_ENTRIES))?;
        let mut out = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let (cidr, vpc_subnet) = Self::address(d, cidrs, subnets)?;
            let ports = if may_use_ports && d.produce::<bool>()? {
                Some(Self::ports(d)?)
            } else {
                None
            };
            if cidr.is_none() && vpc_subnet.is_none() && ports.is_none() {
                continue;
            }
            out.push(Entry {
                cidr,
                vpc_subnet,
                ports,
            });
        }
        Some(out)
    }

    fn rule<D: Driver>(&self, d: &mut D, index: u8) -> Option<GatewayAgentPeeringsAclRules> {
        let (from, to) = if d.produce::<bool>()? {
            (&self.left, &self.right)
        } else {
            (&self.right, &self.left)
        };

        let (from_field, to_field) = match d.gen_u8(Bound::Included(&0), Bound::Included(&2))? {
            0 => (Some(from.vpc.clone()), None),
            1 => (None, Some(to.vpc.clone())),
            _ => (Some(from.vpc.clone()), Some(to.vpc.clone())),
        };

        let (proto, may_use_ports) = match d.gen_u8(Bound::Included(&0), Bound::Included(&3))? {
            0 => (None, false),
            1 => (Some("tcp".to_string()), true),
            2 => (Some("udp".to_string()), true),
            _ => (
                Some(
                    d.gen_u8(Bound::Included(&1), Bound::Included(&254))?
                        .to_string(),
                ),
                false,
            ),
        };

        let src_entries = Self::entries(
            d,
            &from.native,
            &from.native_subnets,
            may_use_ports && !from.restricts_ports,
        )?;
        let dst_entries = Self::entries(
            d,
            &to.advertised,
            &to.advertised_subnets,
            may_use_ports && !to.restricts_ports,
        )?;

        let src = Some(
            src_entries
                .into_iter()
                .map(|entry| GatewayAgentPeeringsAclRulesMatchSrc {
                    cidr: entry.cidr,
                    ports: entry.ports,
                    vpc_subnet: entry.vpc_subnet,
                })
                .collect::<Vec<_>>(),
        )
        .filter(|entries| !entries.is_empty());
        let dst = Some(
            dst_entries
                .into_iter()
                .map(|entry| GatewayAgentPeeringsAclRulesMatchDst {
                    cidr: entry.cidr,
                    ports: entry.ports,
                    vpc_subnet: entry.vpc_subnet,
                })
                .collect::<Vec<_>>(),
        )
        .filter(|entries| !entries.is_empty());

        let r#match = if src.is_some() || dst.is_some() || proto.is_some() {
            Some(GatewayAgentPeeringsAclRulesMatch { dst, proto, src })
        } else {
            None
        };

        let flow_allowed = self.left.all_stateful || self.right.all_stateful;
        let scope = if flow_allowed && d.produce::<bool>()? {
            if d.produce::<bool>()? {
                Some(GatewayAgentPeeringsAclRulesScope::Flow)
            } else {
                None
            }
        } else {
            Some(GatewayAgentPeeringsAclRulesScope::Packet)
        };

        Some(GatewayAgentPeeringsAclRules {
            action: if d.produce::<bool>()? {
                GatewayAgentPeeringsAclRulesAction::Allow
            } else {
                GatewayAgentPeeringsAclRulesAction::Deny
            },
            from: from_field,
            log: Some(d.produce::<bool>()?),
            r#match,
            name: Some(format!("rule{index}")),
            scope,
            to: to_field,
        })
    }
}

impl ValueGenerator for AclGenerator {
    type Output = GatewayAgentPeeringsAcl;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let count = d.gen_u8(Bound::Included(&1), Bound::Included(&MAX_RULES))?;
        let mut rules = Vec::with_capacity(usize::from(count));
        for index in 0..count {
            rules.push(self.rule(d, index)?);
        }

        Some(GatewayAgentPeeringsAcl {
            default: match d.gen_u8(Bound::Included(&0), Bound::Included(&2))? {
                0 => GatewayAgentPeeringsAclDefault::Deny,
                1 => GatewayAgentPeeringsAclDefault::DenyUnlessExposed,
                _ => GatewayAgentPeeringsAclDefault::KopiumEmpty,
            },
            rules: Some(rules).filter(|r| !r.is_empty()),
        })
    }
}
