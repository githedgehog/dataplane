// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator, produce};
use kube::core::ObjectMeta;

use crate::bolero::spec::{GatewayAgentSpecs, SpecBuilder};
use crate::bolero::{AddressFamily, LegalValue, NatFlavour};
use crate::gateway_agent_crd::{GatewayAgent, GatewayAgentSpec};

const HOSTNAME_BASE: &str = "host-";

fn simple_hostname<D: Driver>(d: &mut D) -> Option<String> {
    let raw_chars = (produce::<Vec<u8>>().with().len(1..=10)).generate(d)?;
    Some(
        String::from(HOSTNAME_BASE)
            + raw_chars
                .iter()
                .map(|c| (b'a' + (c % 26)) as char)
                .collect::<String>()
                .as_str(),
    )
}

///
fn join_own_groups<D: Driver>(d: &mut D, name: &str, spec: &mut GatewayAgentSpec) -> Option<()> {
    for group in spec.groups.iter_mut().flatten().map(|(_, group)| group) {
        if !d.produce::<bool>()? {
            continue;
        }
        if let Some(member) = group.members.iter_mut().flatten().next() {
            member.name = name.to_string();
        }
    }
    Some(())
}

#[derive(Debug, Clone, Default)]
pub struct GatewayAgents(GatewayAgentSpecs);

impl ValueGenerator for GatewayAgents {
    type Output = GatewayAgent;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let name = simple_hostname(d)?;
        let generation = d.gen_i64(Bound::Excluded(&0), Bound::Unbounded)?;
        let mut spec = self.0.generate(d)?;
        join_own_groups(d, &name, &mut spec)?;
        Some(GatewayAgent {
            metadata: ObjectMeta {
                name: Some(name),
                generation: Some(generation),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec,
            status: None, // Add when we build a generator and converter for status
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct GatewayAgentBuilder(SpecBuilder);

impl GatewayAgentBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn flavours(mut self, flavours: Vec<NatFlavour>) -> Self {
        self.0 = self.0.flavours(flavours);
        self
    }

    #[must_use]
    pub fn families(mut self, families: Vec<AddressFamily>) -> Self {
        self.0 = self.0.families(families);
        self
    }

    #[must_use]
    pub fn sizes(mut self, vpcs: u8, peerings: u8, exposes: u8, subnets: u8) -> Self {
        self.0 = self
            .0
            .max_vpcs(vpcs)
            .max_peerings(peerings)
            .max_exposes(exposes)
            .max_subnets(subnets);
        self
    }

    #[must_use]
    pub fn build(self) -> GatewayAgents {
        GatewayAgents(self.0.build())
    }
}

/// Generate a random legal `GatewayAgent` value
/// Is not exhaustive due to hostname generation
/// Coverage of values is subject to limitations of the `GatewayAgentSpec` `TypeGenerator` as well
impl TypeGenerator for LegalValue<GatewayAgent> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        Some(LegalValue(GatewayAgents::default().generate(d)?))
    }
}
