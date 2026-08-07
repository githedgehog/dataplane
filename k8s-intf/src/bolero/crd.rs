// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator, produce};
use kube::core::ObjectMeta;

use crate::bolero::spec::{GatewayAgentSpecs, SpecBuilder};
use crate::bolero::{AddressFamily, LegalValue, NatFlavour};
use crate::gateway_agent_crd::GatewayAgent;

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

/// Draws `GatewayAgent` custom resources, as configured by a [`GatewayAgentBuilder`].
///
/// This is the generator to reach for when a property wants to *aim*: at one NAT flavour, at one
/// address family, at a fabric of a particular size. The `TypeGenerator` impl below is this with
/// default knobs.
#[derive(Debug, Clone, Default)]
pub struct GatewayAgents(GatewayAgentSpecs);

impl ValueGenerator for GatewayAgents {
    type Output = GatewayAgent;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        Some(GatewayAgent {
            metadata: ObjectMeta {
                name: Some(simple_hostname(d)?),
                generation: Some(d.gen_i64(Bound::Excluded(&0), Bound::Unbounded)?),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: self.0.generate(d)?,
            status: None, // Add when we build a generator and converter for status
        })
    }
}

/// Knobs for [`GatewayAgents`].
///
/// A thin wrapper over [`SpecBuilder`], since everything worth steering is in the spec.
#[derive(Debug, Clone, Default)]
pub struct GatewayAgentBuilder(SpecBuilder);

impl GatewayAgentBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict the NAT flavours the exposes may use.
    #[must_use]
    pub fn flavours(mut self, flavours: Vec<NatFlavour>) -> Self {
        self.0 = self.0.flavours(flavours);
        self
    }

    /// Restrict the address families the exposes may use.
    #[must_use]
    pub fn families(mut self, families: Vec<AddressFamily>) -> Self {
        self.0 = self.0.families(families);
        self
    }

    /// The most vpcs, peerings, exposes per peering, and subnets per vpc.
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

    /// The generator these knobs describe.
    #[must_use]
    pub fn build(self) -> GatewayAgents {
        GatewayAgents(self.0.build())
    }
}

/// Generate a random legal `GatewayAgent` value
///
/// Is not exhaustive due to hostname generation
/// Coverage of values is subject to limitations of the `GatewayAgentSpec` `TypeGenerator` as well
///
/// Delegates to [`GatewayAgents`] with default knobs; use [`GatewayAgentBuilder`] to aim.
impl TypeGenerator for LegalValue<GatewayAgent> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        Some(LegalValue(GatewayAgents::default().generate(d)?))
    }
}
