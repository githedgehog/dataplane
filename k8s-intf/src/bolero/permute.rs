// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::mutate::{MutatedAgents, Mutation};
use crate::gateway_agent_crd::{
    GatewayAgent, GatewayAgentPeerings, GatewayAgentPeeringsPeeringExpose,
};

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

fn reorder_peering<D: Driver>(d: &mut D, peering: &mut GatewayAgentPeerings) -> Option<()> {
    for manifest in peering.peering.iter_mut().flatten().map(|(_, m)| m) {
        if let Some(exposes) = manifest.expose.as_mut() {
            reorder(d, exposes)?;
            for expose in exposes.iter_mut() {
                reorder_expose(d, expose)?;
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
            reorder(d, src)?;
        }
        if let Some(dst) = pattern.dst.as_mut() {
            reorder(d, dst)?;
        }
    }
    Some(())
}

fn reorder_agent<D: Driver>(d: &mut D, agent: &mut GatewayAgent) -> Option<bool> {
    let before = format!("{:?}", agent.spec.peerings);

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
