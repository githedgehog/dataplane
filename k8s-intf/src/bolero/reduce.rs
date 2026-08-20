// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A configuration, and the same configuration with one expose taken out of it.
//!
//! The third of the near-miss family, after `mutate` (is an accepted configuration *enactable*?) and
//! `permute` (does it have only *one* meaning?). This one asks whether the dataplane is doing
//! everything the configuration asked for: **remove an expose and something the dataplane installs
//! must change.**
//!
//! The failure it hunts is a builder that silently ignores part of its input -- a shape it does not
//! handle, a `continue` on a branch nobody expected to be reachable. That is a class nothing else here
//! covers, and unlike overlap it needs no mutation to reach: the bug would be in the builder, not
//! behind a validator rule, so it shows up on configurations that are entirely legal.
//!
//! Whether an expose is ever *legitimately* a no-op is a domain question, and the answer taken here is
//! no: every expose contributes prefixes to the peer's import and advertise lists at the very least.
//! If that turns out to be wrong for some shape, this generator is where the exemption belongs.

use std::ops::Bound;

use bolero::{Driver, ValueGenerator};

use crate::bolero::mutate::{MutatedAgents, Mutation};
use crate::gateway_agent_crd::GatewayAgent;

/// Which expose was removed, for a failure message: peering, vpc, and its place in the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    pub peering: String,
    pub vpc: String,
    pub index: usize,
    /// The NAT mode it used, as the CRD spells it, so a property can say which artifact it expected to
    /// change. `None` means the expose translated nothing.
    pub nat: Option<&'static str>,
}

impl std::fmt::Display for Dropped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} expose {} ({})",
            self.peering,
            self.vpc,
            self.index,
            self.nat.unwrap_or("no nat")
        )
    }
}

/// Every expose that could be removed, as (peering, vpc, index).
///
/// Enumerated up front so the choice is uniform over exposes rather than biased by where in the walk it
/// happens to fall. Only manifests holding more than one expose are candidates: emptying a manifest
/// makes the configuration illegal outright (`NoExposes`), so drawing one would only produce a case
/// thrown away downstream.
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

/// Take one of `choices` out of `agent`, chosen by the driver, and say which it was.
///
/// A `None` return means the driver ran out of input, never that there was nothing to remove -- the
/// caller has already established there is. Keeping those two apart is why `choices` comes in as an
/// argument rather than being computed here.
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
            Some("static")
        } else if nat.masquerade.is_some() {
            Some("masquerade")
        } else if nat.port_forward.is_some() {
            Some("port forwarding")
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

/// Draws a configuration and the same configuration with one expose removed.
///
/// Built on [`MutatedAgents`] for the same reason [`crate::bolero::permute`] is: a property that only
/// ever sees configurations the generator took care to keep clean is measuring its own generator. Here
/// it also means the near-misses get asked the question, which is where a masked rule would show up.
#[derive(Debug, Default, Clone)]
pub struct ReducedAgents(MutatedAgents);

impl ReducedAgents {
    #[must_use]
    pub fn new(agents: MutatedAgents) -> Self {
        Self(agents)
    }
}

impl ValueGenerator for ReducedAgents {
    /// The mutation, the configuration, the configuration less one expose, and which expose that was
    /// (`None` when there was no manifest with two exposes to take one from).
    type Output = (Mutation, GatewayAgent, GatewayAgent, Option<Dropped>);

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let (mutation, _applied, agent) = self.0.generate(d)?;
        let mut reduced = agent.clone();
        let choices = candidates(&reduced);
        if choices.is_empty() {
            // Nothing to remove, which is a case the property skips -- not the driver running out, so
            // it must not be reported as `None` from here.
            return Some((mutation, agent, reduced, None));
        }
        let dropped = drop_an_expose(d, &mut reduced, choices)?;
        Some((mutation, agent, reduced, Some(dropped)))
    }
}
