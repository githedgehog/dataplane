// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::mutate::{MutatedAgents, Mutation};
use crate::gateway_agent_crd::{
    GatewayAgent, GatewayAgentPeerings, GatewayAgentPeeringsPeeringExpose,
};

/// Rotate and swap `items`, reporting whether that was actually a reordering.
///
/// The caller counts these to tell a run where the permutation did nothing from a
/// run where it did something and the configuration was unmoved by it. Reporting the
/// operation rather than diffing the value is both cheaper and truer: a list of equal
/// elements is genuinely reordered even though it does not look any different.
fn reorder<D: Driver, T>(d: &mut D, items: &mut [T]) -> Option<bool> {
    if items.len() < 2 {
        return Some(false);
    }
    let by = d.gen_usize(Bound::Included(&0), Bound::Excluded(&items.len()))?;
    items.rotate_left(by);
    let first = d.gen_usize(Bound::Included(&0), Bound::Excluded(&items.len()))?;
    let second = d.gen_usize(Bound::Included(&0), Bound::Excluded(&items.len()))?;
    items.swap(first, second);
    Some(by != 0 || first != second)
}

fn reorder_expose<D: Driver>(
    d: &mut D,
    expose: &mut GatewayAgentPeeringsPeeringExpose,
) -> Option<bool> {
    let mut moved = false;
    if let Some(ips) = expose.ips.as_mut() {
        moved |= reorder(d, ips)?;
    }
    if let Some(translations) = expose.r#as.as_mut() {
        moved |= reorder(d, translations)?;
    }
    if let Some(ports) = expose
        .nat
        .as_mut()
        .and_then(|nat| nat.port_forward.as_mut())
        .and_then(|forward| forward.ports.as_mut())
    {
        moved |= reorder(d, ports)?;
    }
    Some(moved)
}

fn reorder_peering<D: Driver>(d: &mut D, peering: &mut GatewayAgentPeerings) -> Option<bool> {
    let mut moved = false;
    for manifest in peering.peering.iter_mut().flatten().map(|(_, m)| m) {
        if let Some(exposes) = manifest.expose.as_mut() {
            moved |= reorder(d, exposes)?;
            for expose in exposes.iter_mut() {
                moved |= reorder_expose(d, expose)?;
            }
        }
    }

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
            moved |= reorder(d, src)?;
        }
        if let Some(dst) = pattern.dst.as_mut() {
            moved |= reorder(d, dst)?;
        }
    }
    Some(moved)
}

/// Reorder every list inside every peering, leaving the peering map itself alone.
///
/// Peerings live in a `BTreeMap`, so there is no order there to permute. What the
/// earlier version did instead was shuffle the peering bodies and zip them back onto
/// the sorted names, handing each name a different peering's body. That is a different
/// configuration, not a reordering of this one. It happened to be invisible downstream
/// only because a peering's name never reaches the built artifacts, so the property was
/// resting on a coincidence that any future use of the name would silently break.
fn reorder_agent<D: Driver>(d: &mut D, agent: &mut GatewayAgent) -> Option<bool> {
    let mut moved = false;
    for peering in agent.spec.peerings.iter_mut().flatten().map(|(_, p)| p) {
        moved |= reorder_peering(d, peering)?;
    }
    Some(moved)
}

#[derive(Debug, Default, Clone)]
pub struct PermutedAgents(MutatedAgents);

impl PermutedAgents {
    #[must_use]
    pub fn new(agents: MutatedAgents) -> Self {
        Self(agents)
    }
}

impl ValueGenerator for PermutedAgents {
    type Output = (Mutation, GatewayAgent, GatewayAgent, bool);

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let (mutation, _applied, agent) = self.0.generate(d)?;
        let mut permuted = agent.clone();
        let moved = reorder_agent(d, &mut permuted)?;
        Some((mutation, agent, permuted, moved))
    }
}
