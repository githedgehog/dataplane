// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generators for the peering-scoped ACL section of the CRD.
//!
//! An ACL rule is only legal *relative to its peering*: `from`/`to` must name the peering's two
//! VPCs (or be blank, to be inferred), and a `vpcSubnet` reference in `match.src` resolves against
//! the from-side VPC's subnets while one in `match.dst` resolves against the to-side VPC's.  None
//! of that is expressible as a `TypeGenerator` on the CRD type, so this is a `ValueGenerator`
//! carrying the peering's two VPC names and the subnet map as borrowed context.

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::support::{choose, generate_port_list, generate_prefixes};
use crate::bolero::{SubnetMap, VpcSubnetMap};
use crate::gateway_agent_crd::{
    GatewayAgentPeeringsAcl, GatewayAgentPeeringsAclDefault, GatewayAgentPeeringsAclRules,
    GatewayAgentPeeringsAclRulesAction, GatewayAgentPeeringsAclRulesMatch,
    GatewayAgentPeeringsAclRulesMatchDst, GatewayAgentPeeringsAclRulesMatchSrc,
    GatewayAgentPeeringsAclRulesScope,
};

/// Largest number of rules a generated ACL may hold.
const MAX_RULES: usize = 8;
/// Largest number of match entries per rule side.
const MAX_MATCH_ENTRIES: u16 = 4;

/// Every legal spelling of a rule's `from`/`to` pair, given the peering's two VPC names.
///
/// `complete_from_to` accepts a matching pair in either direction, or one side matching with the
/// other blank (inferred).  Blank is spelled two ways in the CRD -- absent and empty-string -- and
/// the converter treats them identically via `unwrap_or_default`, so both are generated.
#[derive(Debug, Clone, Copy)]
enum FromToShape {
    LeftToRight,
    RightToLeft,
    LeftOnlyAbsent,
    LeftOnlyEmpty,
    RightOnlyAbsent,
    OnlyToLeftAbsent,
    OnlyToRightEmpty,
}

const FROM_TO_SHAPES: &[FromToShape] = &[
    FromToShape::LeftToRight,
    FromToShape::RightToLeft,
    FromToShape::LeftOnlyAbsent,
    FromToShape::LeftOnlyEmpty,
    FromToShape::RightOnlyAbsent,
    FromToShape::OnlyToLeftAbsent,
    FromToShape::OnlyToRightEmpty,
];

impl FromToShape {
    /// The `(from, to)` field values for this shape.
    fn fields(self, left: &str, right: &str) -> (Option<String>, Option<String>) {
        match self {
            FromToShape::LeftToRight => (Some(left.to_string()), Some(right.to_string())),
            FromToShape::RightToLeft => (Some(right.to_string()), Some(left.to_string())),
            FromToShape::LeftOnlyAbsent => (Some(left.to_string()), None),
            FromToShape::LeftOnlyEmpty => (Some(left.to_string()), Some(String::new())),
            FromToShape::RightOnlyAbsent => (Some(right.to_string()), None),
            FromToShape::OnlyToLeftAbsent => (None, Some(left.to_string())),
            FromToShape::OnlyToRightEmpty => (Some(String::new()), Some(right.to_string())),
        }
    }

    /// The VPC names the converter will resolve this shape to, in `(from, to)` order.
    ///
    /// This mirrors `complete_from_to`'s inference so the generator knows which subnet map each
    /// side of `match` must draw its `vpcSubnet` references from.
    fn resolved<'a>(self, left: &'a str, right: &'a str) -> (&'a str, &'a str) {
        match self {
            FromToShape::LeftToRight
            | FromToShape::LeftOnlyAbsent
            | FromToShape::LeftOnlyEmpty
            | FromToShape::OnlyToRightEmpty => (left, right),
            FromToShape::RightToLeft
            | FromToShape::RightOnlyAbsent
            | FromToShape::OnlyToLeftAbsent => (right, left),
        }
    }
}

/// One entry of a rule's `match.src` / `match.dst` list.
///
/// The converter accepts `cidr` xor `vpcSubnet` (or neither, meaning "any address"), each with an
/// optional non-empty `ports` list.
struct MatchEntry {
    cidr: Option<String>,
    vpc_subnet: Option<String>,
    ports: Option<Vec<String>>,
}

impl From<MatchEntry> for GatewayAgentPeeringsAclRulesMatchSrc {
    fn from(e: MatchEntry) -> Self {
        Self {
            cidr: e.cidr,
            ports: e.ports,
            vpc_subnet: e.vpc_subnet,
        }
    }
}

impl From<MatchEntry> for GatewayAgentPeeringsAclRulesMatchDst {
    fn from(e: MatchEntry) -> Self {
        Self {
            cidr: e.cidr,
            ports: e.ports,
            vpc_subnet: e.vpc_subnet,
        }
    }
}

/// Whether a rule's generated protocol supports port matching.
///
/// `AclPattern::validate` rejects ports on anything but TCP and UDP, and a numeric `6`/`17`
/// normalizes to those variants, so this is decided from the *converted* protocol, not the string.
fn proto_supports_ports(proto: Option<&str>) -> bool {
    matches!(proto, Some("tcp" | "udp" | "6" | "17"))
}

/// Generate one side (`src` or `dst`) of a rule's match block.
///
/// `subnets` must be the subnet map of the VPC that this side's `vpcSubnet` references resolve
/// against -- the from-side VPC for `src`, the to-side VPC for `dst`.  `want_v4` fixes the address
/// family: `AclPattern::validate` requires `src` and `dst` to agree on it.  `allow_ports` reflects
/// whether the rule's protocol supports port matching at all.
fn generate_match_side<D: Driver>(
    d: &mut D,
    subnets: &SubnetMap,
    want_v4: bool,
    allow_ports: bool,
) -> Option<Vec<MatchEntry>> {
    let count = d.gen_u16(Bound::Included(&0), Bound::Included(&MAX_MATCH_ENTRIES))?;
    if count == 0 {
        return Some(Vec::new());
    }

    let subnet_names: Vec<&String> = subnets.keys().collect();

    // Draw each entry's shape and ports first, then generate exactly as many prefixes as the
    // `cidr` entries need.  Generating one per entry up front would spend driver draws on
    // prefixes the `vpcSubnet` and "any address" entries discard, which costs nothing in output
    // but blunts shrinking; asking for them in one call is what keeps them distinct, so a `cidr`
    // entry never duplicates another.
    let mut shapes = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        // A present-but-empty ports list is rejected by the converter, so only ever emit
        // `None` (match all ports) or a non-empty list.
        let ports = if allow_ports && d.gen_bool(None)? {
            Some(vec![generate_port_list(d)?])
        } else {
            None
        };

        // Three legal address shapes: shape 0 is a CIDR, shape 1 a named VPC subnet, and shape 2
        // neither ("any address within the peering", which the converter routes through a separate
        // code path).  Shape 1 falls through to "any address" when the VPC has no subnets.
        let shape = d.gen_usize(Bound::Included(&0), Bound::Included(&2))?;
        let vpc_subnet = if shape == 1 && !subnet_names.is_empty() {
            Some(choose(d, &subnet_names)?.clone())
        } else {
            None
        };
        shapes.push((shape == 0, vpc_subnet, ports));
    }

    let cidr_count = u16::try_from(shapes.iter().filter(|(cidr, _, _)| *cidr).count())
        .unwrap_or_else(|_| unreachable!("at most MAX_MATCH_ENTRIES entries"));
    let mut prefixes = if want_v4 {
        generate_prefixes(d, cidr_count, 0)?
    } else {
        generate_prefixes(d, 0, cidr_count)?
    }
    .into_iter();

    let mut entries = Vec::with_capacity(usize::from(count));
    for (wants_cidr, vpc_subnet, ports) in shapes {
        let cidr = if wants_cidr { prefixes.next() } else { None };

        // "Any address" with no ports means "match everything"; the converter short-circuits the
        // whole side on it, discarding any other entry.  Skip it unless it is the only entry, so
        // that generated multi-entry sides stay meaningful.
        if cidr.is_none() && vpc_subnet.is_none() && ports.is_none() && count > 1 {
            continue;
        }

        entries.push(MatchEntry {
            cidr,
            vpc_subnet,
            ports,
        });
    }
    Some(entries)
}

/// One of the protocol spellings the converter accepts.
///
/// `Absent` is a distinct case from any string: it means "match any protocol", and it also decides
/// whether ports are legal on the rule.
enum ProtoChoice {
    Absent,
    Named(String),
}

impl From<ProtoChoice> for Option<String> {
    fn from(choice: ProtoChoice) -> Self {
        match choice {
            ProtoChoice::Absent => None,
            ProtoChoice::Named(name) => Some(name),
        }
    }
}

/// Protocols the converter accepts: absent, the two names, or a numeric value.
fn generate_proto<D: Driver>(d: &mut D) -> Option<ProtoChoice> {
    match d.gen_usize(Bound::Included(&0), Bound::Included(&3))? {
        0 => Some(ProtoChoice::Absent),
        1 => Some(ProtoChoice::Named("tcp".to_string())),
        2 => Some(ProtoChoice::Named("udp".to_string())),
        // Any u8 is accepted; 6 and 17 normalize to the Tcp/Udp variants rather than Other.
        _ => Some(ProtoChoice::Named(d.produce::<u8>()?.to_string())),
    }
}

/// Generate a legal, peering-relative ACL.
///
/// By default the generated ACL is legal with respect to *conversion*: `Acl::try_from` accepts it
/// for the peering it was built against.  It is not necessarily legal with respect to
/// `ValidatedAcl` -- see [`LegalValueAclGenerator::independent_of_exposes`].
pub struct LegalValueAclGenerator<'a> {
    vpc_subnets: &'a VpcSubnetMap,
    left_name: &'a str,
    right_name: &'a str,
    independent_of_exposes: bool,
}

impl<'a> LegalValueAclGenerator<'a> {
    /// `left_name` and `right_name` must be the two VPC names of the peering this ACL belongs to.
    #[must_use]
    pub fn new(vpc_subnets: &'a VpcSubnetMap, left_name: &'a str, right_name: &'a str) -> Self {
        Self {
            vpc_subnets,
            left_name,
            right_name,
            independent_of_exposes: false,
        }
    }

    /// Restrict generation to ACLs whose legality does not depend on the peering's exposes.
    ///
    /// Two validation rules couple an ACL to the exposes on either side of its peering, neither of
    /// which is visible from the ACL section alone:
    ///
    /// - `ValidatedAclRule::validate_patterns_coverage` requires a rule's `src`/`dst` addresses to
    ///   intersect what the corresponding side actually exposes.  An empty side is exempt: it is
    ///   read as "everything the manifest exposes".
    /// - `ValidatedAclRule::validate_scope` rejects `scope: flow` -- which is also the default --
    ///   unless every expose on one side of the peering uses masquerade or port forwarding.
    ///
    /// In this mode, rules carry no address matches (so coverage is trivially satisfied) and always
    /// set `scope: packet`.  Everything else -- `from`/`to` inference, actions, protocols, logging,
    /// the default action -- is still generated.
    ///
    /// FIXME: a generator that also covers address matches and `scope: flow` needs the *generated
    /// exposes* of both sides as further context, and would have to mirror `manifest_coverage_set`
    /// to know which prefixes are in scope.  Until then, address matches are exercised at the
    /// conversion level only (`converters::k8s::config::peering`).
    #[must_use]
    pub fn independent_of_exposes(mut self) -> Self {
        self.independent_of_exposes = true;
        self
    }
}

impl ValueGenerator for LegalValueAclGenerator<'_> {
    type Output = GatewayAgentPeeringsAcl;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let default = match d.gen_usize(Bound::Included(&0), Bound::Included(&2))? {
            0 => GatewayAgentPeeringsAclDefault::Deny,
            1 => GatewayAgentPeeringsAclDefault::DenyUnlessExposed,
            // The CRD's `""` member: documented to mean the same as "deny-unless-exposed".
            _ => GatewayAgentPeeringsAclDefault::KopiumEmpty,
        };

        // `Acl::validate` rejects an ACL with no rules at all, so a present ACL always has one.
        let num_rules = d.gen_usize(Bound::Included(&1), Bound::Included(&MAX_RULES))?;
        let empty_map = SubnetMap::new();
        let mut rules = Vec::with_capacity(num_rules);

        for index in 0..num_rules {
            let shape = choose(d, FROM_TO_SHAPES)?;
            let (from, to) = shape.fields(self.left_name, self.right_name);
            let (from_vpc, to_vpc) = shape.resolved(self.left_name, self.right_name);

            let src_subnets = self.vpc_subnets.get(from_vpc).unwrap_or(&empty_map);
            let dst_subnets = self.vpc_subnets.get(to_vpc).unwrap_or(&empty_map);

            let r#match = if d.gen_bool(None)? {
                let proto: Option<String> = generate_proto(d)?.into();
                let allow_ports = proto_supports_ports(proto.as_deref());
                let (src, dst) = if self.independent_of_exposes {
                    (Vec::new(), Vec::new())
                } else {
                    // One family per rule: `AclPattern::validate` rejects a rule whose `src` and
                    // `dst` disagree on IP version.  Drawn here rather than above so that the
                    // no-address-match mode does not spend a draw on it.
                    let want_v4 = d.gen_bool(None)?;
                    (
                        generate_match_side(d, src_subnets, want_v4, allow_ports)?,
                        generate_match_side(d, dst_subnets, want_v4, allow_ports)?,
                    )
                };
                Some(GatewayAgentPeeringsAclRulesMatch {
                    src: Some(src.into_iter().map(Into::into).collect::<Vec<_>>())
                        .filter(|s: &Vec<GatewayAgentPeeringsAclRulesMatchSrc>| !s.is_empty()),
                    dst: Some(dst.into_iter().map(Into::into).collect::<Vec<_>>())
                        .filter(|s: &Vec<GatewayAgentPeeringsAclRulesMatchDst>| !s.is_empty()),
                    proto,
                })
            } else {
                None
            };

            // Rule names must be unique within an ACL when non-empty (empty ones are exempt), so
            // suffix with the index rather than relying on the name space being large.
            let name = d
                .produce::<Option<crate::bolero::support::K8sName>>()?
                .map(|n| format!("{n}-{index}"));

            let scope = if self.independent_of_exposes {
                Some(GatewayAgentPeeringsAclRulesScope::Packet)
            } else {
                match d.gen_usize(Bound::Included(&0), Bound::Included(&3))? {
                    0 => None,
                    1 => Some(GatewayAgentPeeringsAclRulesScope::Flow),
                    2 => Some(GatewayAgentPeeringsAclRulesScope::Packet),
                    _ => Some(GatewayAgentPeeringsAclRulesScope::KopiumEmpty),
                }
            };

            rules.push(GatewayAgentPeeringsAclRules {
                action: if d.gen_bool(None)? {
                    GatewayAgentPeeringsAclRulesAction::Allow
                } else {
                    GatewayAgentPeeringsAclRulesAction::Deny
                },
                from,
                to,
                log: d.produce::<Option<bool>>()?,
                r#match,
                name,
                scope,
            });
        }

        Some(GatewayAgentPeeringsAcl {
            default,
            rules: Some(rules),
        })
    }
}
