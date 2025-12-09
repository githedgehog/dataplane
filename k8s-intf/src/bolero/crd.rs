// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::ops::Bound;

use bolero::{Driver, TypeGenerator, ValueGenerator, produce};
use kube::core::ObjectMeta;

use crate::bolero::LegalValue;
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

/// Generate a random legal `GatewayAgent` value
///
/// Is not exhaustive due to hostname generation
/// Coverage of values is subject to limitations of the `GatewayAgentSpec` `TypeGenerator` as well
impl TypeGenerator for LegalValue<GatewayAgent> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        Some(LegalValue(GatewayAgent {
            metadata: ObjectMeta {
                name: Some(simple_hostname(d)?),
                generation: Some(d.gen_i64(Bound::Included(&0), Bound::Unbounded)?),
                ..Default::default()
            },
            spec: d.produce::<LegalValue<GatewayAgentSpec>>()?.take(),
            status: None, // Add when we build a generator and converter for status
        }))
    }
}
