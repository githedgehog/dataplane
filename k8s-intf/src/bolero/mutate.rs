// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configurations that are syntactically valid and semantically doubtful.
//!
//! Everything else in this module generates configurations that are legal *by construction*, which
//! exercises everything downstream of validation and nothing of validation itself. This generates
//! the other kind: a legal configuration with **one** rule deliberately broken, so the result lands
//! just outside the legal space rather than far outside it.
//!
//! Near-miss rather than arbitrary on purpose. A configuration wrong in one way is far more likely
//! to slip past a validator than one wrong in twenty, and slipping past is the failure that matters:
//! the validator ships as a wasm module in a separate process, which blesses a configuration and
//! writes it to Kubernetes. The dataplane runs the same validator later but has no way to report a
//! problem to anyone -- by then it is too late. So **anything the validator accepts has to be
//! enactable**, and a validator that is merely too strict is a nuisance while one that is too
//! permissive is unrecoverable.

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::crd::GatewayAgents;
use crate::gateway_agent_crd::{
    GatewayAgent, GatewayAgentPeeringsAclRulesScope, GatewayAgentPeeringsPeering,
    GatewayAgentPeeringsPeeringExpose, GatewayAgentPeeringsPeeringExposeAs,
    GatewayAgentPeeringsPeeringExposeIps, GatewayAgentPeeringsPeeringExposeNatMasquerade,
};

/// One way of breaking an otherwise-legal configuration.
///
/// Each names a rule the validator is supposed to enforce. Where a rule is enforced only further
/// downstream -- by a table builder during apply, say -- the mutation that breaks it will be
/// *accepted*, and that is exactly the gap worth finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// Leave it alone. A control: the properties should hold on an unmutated configuration too.
    None,
    /// Give the two sides of a port-forwarding expose prefixes of different length.
    ///
    /// The shape of a real bug: sides with equal address-port *totals* and unequal lengths pass a
    /// product comparison and cannot be expressed as a port-forwarding rule.
    MismatchPortForwardPrefixes,
    /// Give the two sides of a static-NAT expose prefixes of different length.
    MismatchStaticNatPrefixes,
    /// Add an exclusion prefix to an expose that uses port forwarding, which forbids them.
    ExcludeFromPortForwarding,
    /// Put a prefix of the other address family into an expose.
    MixAddressFamilies,
    /// Replace a prefix with one that overlaps a special-use range.
    UseReservedPrefix,
    /// Empty an expose's private prefix list.
    EmptyPrivatePrefixes,
    /// Remove the translation range from an expose that translates.
    DropTranslationRange,
    /// Make both manifests of a peering use masquerade, which may not both be stateful.
    MakeBothSidesStateful,
    /// Point the peering at a gateway group that does not exist.
    NameAMissingGroup,
    /// Point an ACL rule's `from` at a vpc that is not in the peering.
    NameAStrangerInARule,
    /// Ask for flow-scoped ACL rules, which need a peering that is stateful throughout.
    DemandFlowScope,
    /// Put port 0 in a port range, which is not a port.
    UsePortZero,
    /// Duplicate one static-NAT expose over a sibling in the same manifest.
    ///
    /// The two exposes then claim the same private prefix, which `validate_expose_collisions` refuses
    /// for every pair of NAT modes except masquerade-with-port-forwarding.
    ///
    /// The reason to aim at static NAT specifically is what happens downstream when the validator does
    /// not catch it. `NatRuleTable::insert` takes no `Result` and checks nothing: two entries for one
    /// prefix and the second **silently replaces** the first. Compare the port-forwarding table, whose
    /// `RangeSet::insert_range` says "overlap is forbidden" and returns an error, and whose lookup is
    /// a longest-prefix match for distinct prefixes -- structurally incapable of this. So static NAT
    /// is where an unrefused duplicate becomes a table that quietly holds one of the two rules the
    /// configuration asked for.
    ///
    /// The recipient is a copy of the donor whose translation range is moved to the prefix next door,
    /// and both halves of that matter.
    ///
    /// A *plain* copy is not enough: the two exposes would then be identical, the table entry would be
    /// overwritten with the same value, and there would be nothing to pick between. Run against a
    /// validator with the overlap check removed, the ambiguity property saw no difference across 43,269
    /// comparisons -- and was right not to. Ambiguity needs one prefix with **two different**
    /// translations.
    ///
    /// Moving the range to a *sibling* prefix keeps every length equal, so static NAT's equal-totals
    /// rule still holds and overlap stays the only rule broken; keeps it disjoint from the donor's, so
    /// the public-prefix rule holds too; and needs no agreement between the two exposes' prefix
    /// lengths, which an earlier version required and which made it apply to one draw in 250.
    DuplicateAStaticExpose,
    /// Make two peers of one vpc expose the same prefix to it.
    ///
    /// `VpcRouteTable` is built per vpc from what its *peers* expose to it, so this leaves that vpc
    /// with one destination and two places to send it. The rule the generator's slot scheme exists to
    /// satisfy, deliberately broken: it was reached for a long time only because the generator broke
    /// it by accident, and once that was fixed nothing tested it.
    ///
    /// Sometimes legal, and correctly so -- `VpcRoute::can_overlap` permits overlap between
    /// masqueraded or default routes, and then only within one gateway group.
    ///
    /// **Note what weakening the validator shows.** Delete the `OverlappingPrefixes` check from
    /// `VpcRouteTable::validate` and the "whatever validates, builds" property still passes: every
    /// configuration the weakened validator accepts still builds and enacts. So this rule is not
    /// about *feasibility* -- the dataplane will cheerfully install two routes to one destination and
    /// pick one -- it is about *ambiguity*, which only the validator is in a position to refuse. That
    /// makes it a rule the near-miss property structurally cannot police, and the gap is in the
    /// property, not the validator. See the note in `validator_completeness`.
    OverlapWithAnotherPeer,
}

impl Mutation {
    /// How many mutations there are, so a harness can keep a counter per mutation without a lock.
    pub const COUNT: usize = 15;

    /// This mutation's position in [`Mutation::all`].
    #[must_use]
    pub fn index(self) -> usize {
        Self::all()
            .iter()
            .position(|other| *other == self)
            .unwrap_or_else(|| unreachable!())
    }

    /// Every mutation, the control included.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::None,
            Self::MismatchPortForwardPrefixes,
            Self::MismatchStaticNatPrefixes,
            Self::ExcludeFromPortForwarding,
            Self::MixAddressFamilies,
            Self::UseReservedPrefix,
            Self::EmptyPrivatePrefixes,
            Self::DropTranslationRange,
            Self::MakeBothSidesStateful,
            Self::NameAMissingGroup,
            Self::NameAStrangerInARule,
            Self::DemandFlowScope,
            Self::UsePortZero,
            Self::DuplicateAStaticExpose,
            Self::OverlapWithAnotherPeer,
        ]
    }
}

/// Lengthen a CIDR's mask by `by`, staying within the family's limit.
fn lengthen(cidr: &str, by: u8) -> Option<String> {
    let (address, len) = cidr.split_once('/')?;
    let len: u8 = len.parse().ok()?;
    let max = if address.contains(':') { 128 } else { 32 };
    let longer = len.saturating_add(by).min(max);
    if longer == len {
        return None;
    }
    Some(format!("{address}/{longer}"))
}

/// The prefix next door: same length, differing only in its last network bit.
///
/// A prefix and its sibling are disjoint by construction, and the sibling sits inside the same parent,
/// so it stays in whatever block and slot the original came from and cannot stray into a reserved
/// range or another expose's territory.
fn sibling(cidr: &str) -> Option<String> {
    let (address, len) = cidr.split_once('/')?;
    let len: u8 = len.parse().ok()?;
    if address.contains(':') {
        let bits = address.parse::<std::net::Ipv6Addr>().ok()?.to_bits();
        let flipped = bits ^ (1u128 << (128u8.checked_sub(len)?));
        Some(format!("{}/{len}", std::net::Ipv6Addr::from(flipped)))
    } else {
        let bits = address.parse::<std::net::Ipv4Addr>().ok()?.to_bits();
        let flipped = bits ^ (1u32 << (32u8.checked_sub(len)?));
        Some(format!("{}/{len}", std::net::Ipv4Addr::from(flipped)))
    }
}

/// Every expose of every manifest of every peering, in a stable order.
fn exposes_mut(agent: &mut GatewayAgent) -> Vec<&mut GatewayAgentPeeringsPeeringExpose> {
    agent
        .spec
        .peerings
        .iter_mut()
        .flatten()
        .flat_map(|(_, peerings)| peerings.peering.iter_mut().flatten())
        .flat_map(|(_, manifest)| manifest.expose.iter_mut().flatten())
        .collect()
}

fn is_port_forwarding(expose: &GatewayAgentPeeringsPeeringExpose) -> bool {
    expose
        .nat
        .as_ref()
        .is_some_and(|nat| nat.port_forward.is_some())
}

fn is_static(expose: &GatewayAgentPeeringsPeeringExpose) -> bool {
    expose
        .nat
        .as_ref()
        .is_some_and(|nat| nat.r#static.is_some())
}

/// Whether every expose of a manifest translates statefully.
///
/// `scope: flow` needs one side of a peering to be stateful throughout, since a flow-scoped rule has
/// nothing to attach to for connections that never reach the flow table. Mirrors
/// `Acl::validate_scope`, and the two being separate statements of the same rule is the point: a
/// mutation that asserts the validator refuses something has to know when it is entitled to.
fn stateful_throughout(manifest: &GatewayAgentPeeringsPeering) -> bool {
    let exposes = manifest.expose.as_deref().unwrap_or(&[]);
    !exposes.is_empty()
        && exposes.iter().all(|expose| {
            expose
                .nat
                .as_ref()
                .is_some_and(|nat| nat.masquerade.is_some() || nat.port_forward.is_some())
        })
}

/// Whether an expose advertises exactly its `ips`, with nothing subtracted and nothing translated.
///
/// Route destinations come from `VpcExpose::public_ips`, which is the **translation range** for any
/// expose that translates and the private prefixes only for one that does not. So a prefix copied out
/// of a static-NAT expose's `ips` never becomes a route at all, and copying one is not the overlap it
/// looks like -- the assertion that whatever a mutation touches must be refused caught exactly that
/// mistake, on a static expose, within seconds.
///
/// Exclusions are ruled out for the same reason: `public_ips` is the prefixes *minus* the `not`s, so
/// an exclusion could carve away the very prefix being copied.
///
/// Masquerade would be wrong twice over: it translates, and `VpcRoute::can_overlap` lets two
/// masqueraded routes share a destination legitimately.
fn advertises_its_ips(expose: &GatewayAgentPeeringsPeeringExpose) -> bool {
    expose.nat.is_none()
        && expose.default != Some(true)
        && expose.ips.iter().flatten().all(|ip| ip.not.is_none())
}

/// Make two peers of one vpc advertise the same destination to it.
///
/// Split out of [`apply`] only for length. Two passes, so nothing has to be borrowed mutably while
/// the search is still reading -- a single pass with two live borrows would need `leak()` or a clone
/// of the whole spec, and this runs millions of times.
fn overlap_with_another_peer(agent: &mut GatewayAgent) -> bool {
    // Two passes, so nothing has to be borrowed mutably while the search is still reading.
    // A single pass with two live borrows would need `leak()` or a clone of the whole spec,
    // and this runs millions of times.
    //
    // First: find a vpc that appears in two peerings, and a prefix one of its peers exposes.
    let mut donor: Option<(String, String, String)> = None;
    for (key, peering) in agent.spec.peerings.iter().flatten() {
        let Some(manifests) = peering.peering.as_ref() else {
            continue;
        };
        for shared in manifests.keys() {
            let elsewhere = agent
                .spec
                .peerings
                .iter()
                .flatten()
                .any(|(other, peering)| {
                    other != key
                        && peering
                            .peering
                            .as_ref()
                            .is_some_and(|m| m.contains_key(shared))
                });
            if !elsewhere {
                continue;
            }
            // Only from an expose that advertises its `ips` verbatim, so the prefix taken
            // really is one of this peer's route destinations.
            let prefix = manifests
                .iter()
                .filter(|(name, _)| *name != shared)
                .flat_map(|(_, manifest)| manifest.expose.iter().flatten())
                .filter(|expose| advertises_its_ips(expose))
                .flat_map(|expose| expose.ips.iter().flatten())
                .find_map(|ip| ip.cidr.clone());
            if let Some(prefix) = prefix {
                donor = Some((key.clone(), shared.clone(), prefix));
                break;
            }
        }
        if donor.is_some() {
            break;
        }
    }

    // Second: give that prefix to the shared vpc's *other* peer, in a different peering.
    let mut done = false;
    if let Some((donor_key, shared, prefix)) = donor {
        for (key, peering) in agent.spec.peerings.iter_mut().flatten() {
            if *key == donor_key {
                continue;
            }
            let Some(manifests) = peering.peering.as_mut() else {
                continue;
            };
            if !manifests.contains_key(&shared) {
                continue;
            }
            let names: Vec<String> = manifests
                .keys()
                .filter(|name| **name != shared)
                .cloned()
                .collect();
            for name in names {
                let Some(manifest) = manifests.get_mut(&name) else {
                    continue;
                };
                if let Some(ip) = manifest
                    .expose
                    .iter_mut()
                    .flatten()
                    .filter(|expose| advertises_its_ips(expose))
                    .flat_map(|expose| expose.ips.iter_mut().flatten())
                    .find(|ip| ip.cidr.is_some())
                {
                    ip.cidr = Some(prefix.clone());
                    done = true;
                    break;
                }
            }
            if done {
                break;
            }
        }
    }
    done
}

/// The mutations that break a peering's ACL or the group it names, rather than an expose's prefixes.
///
/// Split out of [`apply`] only for length; none of these needs the driver.
fn mutate_peering_metadata(agent: &mut GatewayAgent, mutation: Mutation) -> bool {
    match mutation {
        Mutation::MakeBothSidesStateful => {
            let mut done = false;
            for (_, peerings) in agent.spec.peerings.iter_mut().flatten() {
                let manifests = peerings.peering.iter_mut().flatten();
                let mut touched = 0;
                for (_, manifest) in manifests {
                    for expose in manifest.expose.iter_mut().flatten() {
                        let nat = expose.nat.get_or_insert(
                            crate::gateway_agent_crd::GatewayAgentPeeringsPeeringExposeNat {
                                masquerade: None,
                                port_forward: None,
                                r#static: None,
                            },
                        );
                        nat.port_forward = None;
                        nat.r#static = None;
                        nat.masquerade = Some(GatewayAgentPeeringsPeeringExposeNatMasquerade {
                            idle_timeout: None,
                        });
                        // masquerade needs somewhere to translate to
                        if expose.r#as.is_none() {
                            expose.r#as = Some(vec![GatewayAgentPeeringsPeeringExposeAs {
                                cidr: Some("172.31.0.0/16".to_string()),
                                not: None,
                            }]);
                        }
                    }
                    touched += 1;
                }
                if touched == 2 {
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::NameAMissingGroup => {
            if let Some((_, peerings)) = agent.spec.peerings.iter_mut().flatten().next() {
                peerings.gateway_group = Some("no-such-group".to_string());
                true
            } else {
                false
            }
        }

        Mutation::NameAStrangerInARule => {
            let mut done = false;
            for (_, peerings) in agent.spec.peerings.iter_mut().flatten() {
                let Some(acl) = peerings.acl.as_mut() else {
                    continue;
                };
                if let Some(rule) = acl.rules.iter_mut().flatten().next() {
                    rule.from = Some("not-in-this-peering".to_string());
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::DemandFlowScope => {
            let mut done = false;
            for (_, peerings) in agent.spec.peerings.iter_mut().flatten() {
                // Flow scope is legal where a side is stateful throughout, so asking for it there
                // breaks nothing. Skip those peerings rather than produce a case whose legality is
                // arguable: the assertion this feeds is "whatever was touched must be refused".
                let allowed = peerings
                    .peering
                    .iter()
                    .flatten()
                    .any(|(_, manifest)| stateful_throughout(manifest));
                if allowed {
                    continue;
                }
                let Some(acl) = peerings.acl.as_mut() else {
                    continue;
                };
                for rule in acl.rules.iter_mut().flatten() {
                    rule.scope = Some(GatewayAgentPeeringsAclRulesScope::Flow);
                    done = true;
                }
                if done {
                    break;
                }
            }
            done
        }
        _ => unreachable!("mutate_peering_metadata called for {mutation:?}"),
    }
}

/// The mutations that break the *shape* of an expose's prefix lists -- lengths, families, exclusions.
///
/// Split out of [`apply`] only for length; none of these needs the driver.
fn mutate_expose_shape(agent: &mut GatewayAgent, mutation: Mutation) -> bool {
    match mutation {
        Mutation::MismatchPortForwardPrefixes | Mutation::MismatchStaticNatPrefixes => {
            let wanted: fn(&GatewayAgentPeeringsPeeringExpose) -> bool =
                if mutation == Mutation::MismatchPortForwardPrefixes {
                    is_port_forwarding
                } else {
                    is_static
                };
            let mut done = false;
            for expose in exposes_mut(agent) {
                if !wanted(expose) {
                    continue;
                }
                // lengthening one side's mask leaves the two unequal, and for port forwarding
                // leaves the address-port totals unequal too unless the ports compensate
                if let Some(entry) = expose.r#as.iter_mut().flatten().next()
                    && let Some(cidr) = entry.cidr.as_ref()
                    && let Some(longer) = lengthen(cidr, 2)
                {
                    entry.cidr = Some(longer);
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::ExcludeFromPortForwarding => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                if !is_port_forwarding(expose) {
                    continue;
                }
                let Some(inside) = expose
                    .ips
                    .iter()
                    .flatten()
                    .find_map(|ip| ip.cidr.as_ref())
                    .and_then(|cidr| lengthen(cidr, 1))
                else {
                    continue;
                };
                expose.ips.get_or_insert_with(Vec::new).push(
                    GatewayAgentPeeringsPeeringExposeIps {
                        cidr: None,
                        not: Some(inside),
                        vpc_subnet: None,
                    },
                );
                done = true;
                break;
            }
            done
        }

        Mutation::MixAddressFamilies => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                let Some(entry) = expose.ips.iter_mut().flatten().next() else {
                    continue;
                };
                let Some(cidr) = entry.cidr.as_ref() else {
                    continue;
                };
                // whichever family it is not
                let other = if cidr.contains(':') {
                    "10.99.0.0/16"
                } else {
                    "2001:db8:9999::/48"
                };
                expose.ips.get_or_insert_with(Vec::new).push(
                    GatewayAgentPeeringsPeeringExposeIps {
                        cidr: Some(other.to_string()),
                        not: None,
                        vpc_subnet: None,
                    },
                );
                done = true;
                break;
            }
            done
        }
        _ => unreachable!("mutate_expose_shape called for {mutation:?}"),
    }
}

/// Copy one static-NAT expose over a sibling in the same manifest, so both claim one private prefix,
/// then move the copy's translation range next door so the two claims disagree.
///
/// Split out of [`apply`] only for length.
fn duplicate_a_static_expose(agent: &mut GatewayAgent) -> bool {
    for (_, peering) in agent.spec.peerings.iter_mut().flatten() {
        for manifest in peering.peering.iter_mut().flatten().map(|(_, m)| m) {
            let Some(exposes) = manifest.expose.as_mut() else {
                continue;
            };
            // Both must use static NAT: it is the mode whose table silently replaces a duplicate
            // rather than refusing it, and a pair of modes the validator lets overlap would make a
            // case that is legitimately legal.
            let statics: Vec<usize> = exposes
                .iter()
                .enumerate()
                .filter(|(_, expose)| {
                    expose
                        .nat
                        .as_ref()
                        .is_some_and(|nat| nat.r#static.is_some())
                })
                .map(|(index, _)| index)
                .collect();

            let (Some(donor), Some(recipient)) = (statics.first(), statics.get(1)) else {
                continue;
            };
            let mut copy = exposes[*donor].clone();
            let moved = copy
                .r#as
                .as_mut()
                .and_then(|ranges| ranges.first_mut())
                .and_then(|range| {
                    let next_door = sibling(range.cidr.as_ref()?)?;
                    range.cidr = Some(next_door);
                    Some(())
                });
            if moved.is_some() {
                exposes[*recipient] = copy;
                return true;
            }
        }
    }
    false
}

/// Apply `mutation`, returning whether it found something to break.
///
/// **A `true` return means the result is certainly illegal**, not merely that something changed. Every
/// mutation is written to decline rather than to produce a case whose legality is arguable -- see
/// `DemandFlowScope` and `OverlapWithAnotherPeer`, both of which break rules that have legitimate
/// exceptions and so check the exception does not apply before touching anything. That is what lets a
/// property assert the validator refuses whatever this touched, which is the only guard against the
/// validator growing more permissive about a rule nothing downstream enforces.
pub fn apply<D: Driver>(d: &mut D, agent: &mut GatewayAgent, mutation: Mutation) -> Option<bool> {
    let bit = match mutation {
        Mutation::None => false,

        Mutation::MismatchPortForwardPrefixes
        | Mutation::MismatchStaticNatPrefixes
        | Mutation::ExcludeFromPortForwarding
        | Mutation::MixAddressFamilies => mutate_expose_shape(agent, mutation),
        Mutation::UseReservedPrefix => {
            let reserved = ["127.0.0.0/8", "224.0.0.0/4", "0.0.0.0/8", "ff00::/8"];
            let choice =
                reserved[d.gen_usize(Bound::Included(&0), Bound::Excluded(&reserved.len()))?];
            let mut done = false;
            for expose in exposes_mut(agent) {
                if let Some(entry) = expose.ips.iter_mut().flatten().next()
                    && entry.cidr.is_some()
                {
                    entry.cidr = Some(choice.to_string());
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::EmptyPrivatePrefixes => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                if expose.ips.is_some() {
                    expose.ips = None;
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::DropTranslationRange => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                if expose.nat.is_some() && expose.r#as.is_some() {
                    expose.r#as = None;
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::MakeBothSidesStateful
        | Mutation::NameAMissingGroup
        | Mutation::NameAStrangerInARule
        | Mutation::DemandFlowScope => mutate_peering_metadata(agent, mutation),
        Mutation::UsePortZero => {
            let mut done = false;
            for expose in exposes_mut(agent) {
                let Some(nat) = expose.nat.as_mut() else {
                    continue;
                };
                let Some(pf) = nat.port_forward.as_mut() else {
                    continue;
                };
                if let Some(ports) = pf.ports.iter_mut().flatten().next() {
                    ports.port = Some("0-100".to_string());
                    ports.r#as = Some("0-100".to_string());
                    done = true;
                    break;
                }
            }
            done
        }

        Mutation::DuplicateAStaticExpose => duplicate_a_static_expose(agent),
        Mutation::OverlapWithAnotherPeer => overlap_with_another_peer(agent),
    };
    Some(bit)
}

/// A legal configuration with one rule deliberately broken.
///
/// Yields the mutation that was chosen and whether it found anything to change, alongside the
/// configuration, so a property can say what it was testing and a harness can tell whether the
/// generator is doing any work.
#[derive(Debug, Clone, Default)]
pub struct MutatedAgents(GatewayAgents);

impl MutatedAgents {
    #[must_use]
    pub fn new(agents: GatewayAgents) -> Self {
        Self(agents)
    }
}

impl ValueGenerator for MutatedAgents {
    type Output = (Mutation, bool, GatewayAgent);

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let mut agent = self.0.generate(d)?;
        let all = Mutation::all();
        let mutation = all[d.gen_usize(Bound::Included(&0), Bound::Excluded(&all.len()))?];
        let bit = apply(d, &mut agent, mutation)?;
        Some((mutation, bit, agent))
    }
}
