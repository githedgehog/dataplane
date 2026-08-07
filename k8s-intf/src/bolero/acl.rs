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

/// The most rules one generated ACL carries. Small, for the usual reasons.
const MAX_RULES: u8 = 3;

/// What one side of a peering offers, as far as an ACL rule has to care.
///
/// An ACL rule's `match` is checked against the manifests it sits beside: the **source** prefixes
/// have to intersect the *from* side's native addresses, and the **destination** prefixes the *to*
/// side's advertised ones. A rule whose match intersects neither is refused outright, so a generator
/// that draws prefixes freely produces rules that are thrown away. These are read back off the
/// manifests the peering generator has just built, so a rule can name something that is really
/// there.
#[derive(Debug, Clone)]
pub struct SideFacts {
    /// The vpc this side is, for `from` and `to`.
    pub vpc: String,
    /// The addresses this side exposes natively -- what a rule's `src` is checked against when this
    /// is the *from* side.
    pub native: Vec<String>,
    /// The addresses this side is reachable at from outside -- the translation range where the
    /// expose has one, and the native prefix where it does not. A rule's `dst` is checked against
    /// this when this is the *to* side.
    pub advertised: Vec<String>,
    /// Whether any expose restricts ports.
    ///
    /// Port forwarding attaches port ranges to its prefixes, and coverage is checked over addresses
    /// *and* ports together -- so a rule naming ports outside those ranges intersects nothing. Where
    /// this is set, rules on this side leave ports alone.
    pub restricts_ports: bool,
    /// Whether *every* expose on this side uses masquerade or port forwarding.
    ///
    /// `scope: flow` needs one side of the peering to be entirely stateful, since a flow-scoped rule
    /// has nothing to attach to for connections that never reach the flow table.
    pub all_stateful: bool,
}

impl SideFacts {
    /// Read the facts off a generated manifest.
    #[must_use]
    pub fn of(vpc: &str, manifest: &GatewayAgentPeeringsPeering) -> Self {
        let exposes = manifest.expose.as_deref().unwrap_or(&[]);
        let mut native = Vec::new();
        let mut advertised = Vec::new();
        let mut restricts_ports = false;
        let mut all_stateful = !exposes.is_empty();

        for expose in exposes {
            let ips: Vec<String> = expose
                .ips
                .iter()
                .flatten()
                .filter_map(|ip| ip.cidr.clone())
                .collect();
            let translations: Vec<String> = expose
                .r#as
                .iter()
                .flatten()
                .filter_map(|entry| entry.cidr.clone())
                .collect();

            native.extend(ips.iter().cloned());
            // reachable from outside at the translation range if there is one, at the native prefix
            // otherwise
            if translations.is_empty() {
                advertised.extend(ips);
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
            restricts_ports,
            all_stateful,
        }
    }
}

/// Generates peering-scoped ACLs that validation accepts.
///
/// Valid by construction, like the expose generator beside it. The rules an ACL has to satisfy:
///
/// * `from` and `to` name the peering's two vpcs, in either order. One may be omitted, since the
///   converter completes it from the other -- which is worth generating, because that completion is
///   itself code.
/// * a rule's source prefixes intersect the *from* side's native addresses, and its destination
///   prefixes the *to* side's advertised ones. An empty list means "everything in this direction",
///   which is always accepted.
/// * source and destination prefixes are of one address family.
/// * only TCP and UDP support port matching. Any other protocol, and any-protocol, must carry no
///   ports at all.
/// * `scope: flow` needs one side of the peering to use masquerade or port forwarding for *all* of
///   its exposes.
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

    /// A port range, as the CRD writes them: a single port or a range.
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

    /// One prefix of `choices`, or `None` to match everything in the rule's direction.
    ///
    /// Naming a prefix the manifest really has is what makes the coverage check pass. No ports go
    /// with it: coverage compares addresses *and* ports, so a prefix that carries ports of its own in
    /// the manifest would be intersected against whatever this named, and a mismatch means the rule
    /// matches nothing and is refused.
    fn prefix<D: Driver>(d: &mut D, choices: &[String]) -> Option<String> {
        if choices.is_empty() {
            return None;
        }
        let index = d.gen_usize(Bound::Included(&0), Bound::Excluded(&choices.len()))?;
        Some(choices[index].clone())
    }

    fn rule<D: Driver>(&self, d: &mut D, index: u8) -> Option<GatewayAgentPeeringsAclRules> {
        // either direction across the peering
        let (from, to) = if d.produce::<bool>()? {
            (&self.left, &self.right)
        } else {
            (&self.right, &self.left)
        };

        // Sometimes leave one end out: the converter fills it in from the other, and that
        // completion is code worth running.
        let (from_field, to_field) = match d.gen_u8(Bound::Included(&0), Bound::Included(&2))? {
            0 => (Some(from.vpc.clone()), None),
            1 => (None, Some(to.vpc.clone())),
            _ => (Some(from.vpc.clone()), Some(to.vpc.clone())),
        };

        // TCP and UDP are the only protocols that may carry ports.
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

        let src_ports = may_use_ports && !from.restricts_ports && d.produce::<bool>()?;
        let dst_ports = may_use_ports && !to.restricts_ports && d.produce::<bool>()?;

        // A src or dst entry may name a prefix, may name ports, or may be left out entirely -- but an
        // entry with neither says nothing, so it is only emitted when it has one or the other.
        let src_prefix = if d.produce::<bool>()? {
            Self::prefix(d, &from.native)
        } else {
            None
        };
        let dst_prefix = if d.produce::<bool>()? {
            Self::prefix(d, &to.advertised)
        } else {
            None
        };

        let src = if src_prefix.is_some() || src_ports {
            Some(vec![GatewayAgentPeeringsAclRulesMatchSrc {
                cidr: src_prefix,
                ports: if src_ports {
                    Self::ports(d)?.into()
                } else {
                    None
                },
                vpc_subnet: None,
            }])
        } else {
            None
        };
        let dst = if dst_prefix.is_some() || dst_ports {
            Some(vec![GatewayAgentPeeringsAclRulesMatchDst {
                cidr: dst_prefix,
                ports: if dst_ports {
                    Self::ports(d)?.into()
                } else {
                    None
                },
                vpc_subnet: None,
            }])
        } else {
            None
        };

        let r#match = if src.is_some() || dst.is_some() || proto.is_some() {
            Some(GatewayAgentPeeringsAclRulesMatch { dst, proto, src })
        } else {
            None
        };

        // `scope: flow` needs one side of the peering to use masquerade or port forwarding for all
        // of its exposes, since a flow-scoped rule has nothing to attach to for connections that
        // never reach the flow table.
        //
        // Note what omitting the field means. The CRD says the scope "can be either 'flow' (default
        // if empty) or 'packet'" -- so leaving it out is not "unspecified", it is *flow*, and it is
        // refused in exactly the cases an explicit `flow` would be. An earlier version of this drew
        // three ways and let the no-flow case fall through to omitting the field, which asked for
        // flow by another name.
        let flow_allowed = self.left.all_stateful || self.right.all_stateful;
        let scope = if flow_allowed && d.produce::<bool>()? {
            // both spellings of flow: named, and left to the default
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
        // At least one: an ACL with no rules is refused, since it says nothing that the peering's
        // default action does not already say.
        let count = d.gen_u8(Bound::Included(&1), Bound::Included(&MAX_RULES))?;
        let mut rules = Vec::with_capacity(usize::from(count));
        for index in 0..count {
            rules.push(self.rule(d, index)?);
        }

        Some(GatewayAgentPeeringsAcl {
            default: match d.gen_u8(Bound::Included(&0), Bound::Included(&2))? {
                0 => GatewayAgentPeeringsAclDefault::Deny,
                1 => GatewayAgentPeeringsAclDefault::DenyUnlessExposed,
                // the empty string, which the CRD accepts and means the default
                _ => GatewayAgentPeeringsAclDefault::KopiumEmpty,
            },
            rules: Some(rules).filter(|r| !r.is_empty()),
        })
    }
}
