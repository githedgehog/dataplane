// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A configuration, and the same configuration with its set-valued lists in a different order.
//!
//! Paired with `mutate`, which asks whether the validator is too permissive about configurations that
//! cannot be *enacted*. This asks the other question: whether an accepted configuration has only one
//! *meaning*.
//!
//! The two failures are nothing alike from where the user stands. An unenactable configuration at
//! least fails to build, and something somewhere gets an error. An **ambiguous** one builds
//! perfectly: two readings, both valid outputs of the code as written, and the chain silently takes
//! whichever its containers hand it first. Nothing reports that, and nothing can, because there is no
//! error to report -- only traffic going somewhere nobody chose.
//!
//! Permutation is the oracle, and its virtue is that it restates no rule. A CRD's `expose` list, and
//! the `ips` and `as` lists inside it, are *sets*: their order is not part of what the configuration
//! means. Nor is which name a peering happens to carry, since peering names reach no artifact -- the
//! names in the rendered FRR config come from vpcs. So reordering all of those must leave every
//! artifact the dataplane installs identical. Where it does not, the chain resolved a conflict by
//! position, and the configuration had two meanings.
//!
//! What is deliberately *not* permuted: an ACL's `rules`. Those are ordered by definition -- first
//! match wins -- so reordering them changes the configuration's meaning legitimately, and a property
//! that permuted them would be asserting something false.

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::mutate::{MutatedAgents, Mutation};
use crate::gateway_agent_crd::{
    GatewayAgent, GatewayAgentPeerings, GatewayAgentPeeringsPeeringExpose,
};

/// Reorder `items`, if there is more than one way to.
///
/// A rotation and a swap rather than a full shuffle: enough to move every element for the short lists
/// a configuration holds, and it costs two draws instead of one per element.
fn reorder<D: Driver, T>(d: &mut D, items: &mut [T]) -> Option<()> {
    if items.len() < 2 {
        return Some(());
    }
    let by = d.gen_usize(Bound::Included(&0), Bound::Excluded(&items.len()))?;
    items.rotate_left(by);
    let first = d.gen_usize(Bound::Included(&0), Bound::Excluded(&items.len()))?;
    let second = d.gen_usize(Bound::Included(&0), Bound::Excluded(&items.len()))?;
    items.swap(first, second);
    Some(())
}

/// Reorder the lists inside one expose.
fn reorder_expose<D: Driver>(
    d: &mut D,
    expose: &mut GatewayAgentPeeringsPeeringExpose,
) -> Option<()> {
    if let Some(ips) = expose.ips.as_mut() {
        reorder(d, ips)?;
    }
    if let Some(translations) = expose.r#as.as_mut() {
        reorder(d, translations)?;
    }
    // Each port-forwarding `ports` block becomes an expose of its own during conversion, so the
    // blocks are a set of rules and their order should not matter either.
    if let Some(ports) = expose
        .nat
        .as_mut()
        .and_then(|nat| nat.port_forward.as_mut())
        .and_then(|forward| forward.ports.as_mut())
    {
        reorder(d, ports)?;
    }
    Some(())
}

/// Reorder everything inside one peering, but not its ACL's rules.
fn reorder_peering<D: Driver>(d: &mut D, peering: &mut GatewayAgentPeerings) -> Option<()> {
    for manifest in peering.peering.iter_mut().flatten().map(|(_, m)| m) {
        if let Some(exposes) = manifest.expose.as_mut() {
            reorder(d, exposes)?;
            for expose in exposes.iter_mut() {
                reorder_expose(d, expose)?;
            }
        }
    }

    // A rule's `match` names sets of prefixes; the rules themselves are ordered and are left alone.
    for rule in peering
        .acl
        .iter_mut()
        .flat_map(|acl| acl.rules.iter_mut())
        .flatten()
    {
        let Some(pattern) = rule.r#match.as_mut() else {
            continue;
        };
        if let Some(src) = pattern.src.as_mut() {
            reorder(d, src)?;
        }
        if let Some(dst) = pattern.dst.as_mut() {
            reorder(d, dst)?;
        }
    }
    Some(())
}

/// Reorder a whole configuration's set-valued lists.
///
/// Returns whether anything actually moved, so a property can tell a real agreement from a
/// permutation that happened to be the identity on a configuration with nothing to reorder.
fn reorder_agent<D: Driver>(d: &mut D, agent: &mut GatewayAgent) -> Option<bool> {
    let before = format!("{:?}", agent.spec.peerings);

    // The peerings themselves: rotate which name holds which peering. Peering names reach no
    // artifact -- the names in the rendered config are vpcs' -- so this is a permutation of the
    // configuration and not a change to it, and it is the only one that reorders the *peering* walk
    // that `VpcRouteTable::build` does.
    if let Some(peerings) = agent.spec.peerings.as_mut() {
        let names: Vec<String> = peerings.keys().cloned().collect();
        let mut bodies: Vec<GatewayAgentPeerings> = peerings.values().cloned().collect();
        reorder(d, &mut bodies)?;
        *peerings = names.into_iter().zip(bodies).collect::<BTreeMap<_, _>>();

        for peering in peerings.values_mut() {
            reorder_peering(d, peering)?;
        }
    }

    Some(before != format!("{:?}", agent.spec.peerings))
}

/// Draws a configuration and a reordering of it.
///
/// The reordering is a *different value* rather than an in-place edit, so the property receives both
/// and holds no ordering logic of its own.
///
/// Built on [`MutatedAgents`] rather than on legal-by-construction configurations alone, and that
/// choice is the whole point. The generator is now careful to keep every vpc's prefixes disjoint, so
/// it *cannot* produce the overlapping-route ambiguity by itself -- a permutation property driven by
/// legal input only would pass without ever meeting the case it exists for. Feeding it near-misses
/// puts the question where it belongs: when the validator lets a rule slide, is the result still
/// unambiguous? A property that only sees configurations the generator was careful to make clean is
/// measuring its own generator.
#[derive(Debug, Default, Clone)]
pub struct PermutedAgents(MutatedAgents);

impl PermutedAgents {
    #[must_use]
    pub fn new(agents: MutatedAgents) -> Self {
        Self(agents)
    }
}

impl ValueGenerator for PermutedAgents {
    /// The mutation applied, the configuration, its reordering, and whether the reordering moved
    /// anything.
    type Output = (Mutation, GatewayAgent, GatewayAgent, bool);

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let (mutation, _applied, agent) = self.0.generate(d)?;
        let mut permuted = agent.clone();
        let moved = reorder_agent(d, &mut permuted)?;
        Some((mutation, agent, permuted, moved))
    }
}
