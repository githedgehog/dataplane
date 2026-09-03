// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::NatFlavour;
use crate::bolero::mutate::{MutatedAgents, Mutation};
use crate::gateway_agent_crd::GatewayAgent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    pub peering: String,
    pub vpc: String,
    pub index: usize,
    /// Which kind of translation the dropped expose asked for, if any.
    ///
    /// A `NatFlavour` rather than a string. `development/code/error-handling.md` calls
    /// arbitrary string values actively hostile and matching on their contents extremely
    /// fragile, and the consumer of this field does exactly that kind of match: a typo in
    /// either the producer or the consumer compiled cleanly and surfaced as an
    /// `unreachable!` during a fuzz run rather than as a build error.
    pub nat: Option<NatFlavour>,
}

impl std::fmt::Display for Dropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} expose {} ({})",
            self.peering,
            self.vpc,
            self.index,
            self.nat
                .map_or_else(|| "no nat".to_string(), |nat| format!("{nat:?}"))
        )
    }
}

fn candidates(agent: &GatewayAgent) -> Vec<(String, String, usize)> {
    let mut out = Vec::new();
    for (peering_name, peering) in agent.spec.peerings.iter().flatten() {
        for (vpc, manifest) in peering.peering.iter().flatten() {
            let count = manifest.expose.as_ref().map_or(0, Vec::len);
            if count < 2 {
                continue;
            }
            for index in 0..count {
                out.push((peering_name.clone(), vpc.clone(), index));
            }
        }
    }
    out
}

fn drop_an_expose<D: Driver>(
    d: &mut D,
    agent: &mut GatewayAgent,
    mut choices: Vec<(String, String, usize)>,
) -> Option<Dropped> {
    let choice = d.gen_usize(Bound::Included(&0), Bound::Excluded(&choices.len()))?;
    let (peering_name, vpc, index) = choices.swap_remove(choice);

    let exposes = agent
        .spec
        .peerings
        .as_mut()?
        .get_mut(&peering_name)?
        .peering
        .as_mut()?
        .get_mut(&vpc)?
        .expose
        .as_mut()?;
    if index >= exposes.len() {
        return None;
    }
    let removed = exposes.remove(index);
    let nat = removed.nat.as_ref().and_then(|nat| {
        if nat.r#static.is_some() {
            Some(NatFlavour::Static)
        } else if nat.masquerade.is_some() {
            Some(NatFlavour::Masquerade)
        } else if nat.port_forward.is_some() {
            Some(NatFlavour::PortForward)
        } else {
            None
        }
    });

    Some(Dropped {
        peering: peering_name,
        vpc,
        index,
        nat,
    })
}

#[derive(Debug, Default, Clone)]
pub struct ReducedAgents(MutatedAgents);

impl ReducedAgents {
    #[must_use]
    pub fn new(agents: MutatedAgents) -> Self {
        Self(agents)
    }
}

impl ValueGenerator for ReducedAgents {
    type Output = (Mutation, GatewayAgent, GatewayAgent, Option<Dropped>);

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let (mutation, _applied, agent) = self.0.generate(d)?;
        let mut reduced = agent.clone();
        let choices = candidates(&reduced);
        if choices.is_empty() {
            return Some((mutation, agent, reduced, None));
        }
        let dropped = drop_an_expose(d, &mut reduced, choices)?;
        Some((mutation, agent, reduced, Some(dropped)))
    }
}
