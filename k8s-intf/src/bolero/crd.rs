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
                generation: Some(d.gen_i64(Bound::Excluded(&0), Bound::Unbounded)?),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: d.produce::<LegalValue<GatewayAgentSpec>>()?.take(),
            status: None, // Add when we build a generator and converter for status
        }))
    }
}

/// Tests for the deserialization boundary itself.
///
/// This is the real trust boundary in both intake modes: k8s-less parses YAML from a watched file
/// (`k8s_less::kubeless_watch_gateway_agent_crd` -> [`crate::utils::load_crd_from_file`]) and the
/// k8s watcher parses JSON off the API server.  Both land in the same kopium-generated types, and
/// `build.rs` rewrites those types' integer widths textually (`i64` -> `u64`, `i32` -> `u32`, with
/// specific fields patched back).  Nothing else checks that those rewrites round-trip.
#[cfg(test)]
mod test {
    use crate::bolero::LegalValue;
    use crate::gateway_agent_crd::GatewayAgentSpec;

    /// A spec must survive YAML serialization, which is what k8s-less reads.
    #[test]
    fn test_spec_yaml_round_trip() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentSpec>>()
            .for_each(|spec| {
                let spec = spec.as_ref();
                let yaml = serde_yaml_ng::to_string(spec).expect("failed to serialize as YAML");
                let parsed: GatewayAgentSpec = serde_yaml_ng::from_str(&yaml)
                    .unwrap_or_else(|e| panic!("failed to parse YAML: {e}\n{yaml}"));
                assert_eq!(*spec, parsed, "YAML round-trip changed the spec:\n{yaml}");
            });
    }

    /// A spec must survive JSON serialization, which is what the k8s watcher receives.
    #[test]
    fn test_spec_json_round_trip() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentSpec>>()
            .for_each(|spec| {
                let spec = spec.as_ref();
                let json = serde_json::to_string(spec).expect("failed to serialize as JSON");
                let parsed: GatewayAgentSpec = serde_json::from_str(&json)
                    .unwrap_or_else(|e| panic!("failed to parse JSON: {e}\n{json}"));
                assert_eq!(*spec, parsed, "JSON round-trip changed the spec:\n{json}");
            });
    }

    /// The spec generator must actually reach the shapes it claims to cover.
    ///
    /// A property test passes just as easily against a generator that has quietly degenerated --
    /// `GatewayAgentGroups` used to draw a member count in `0..=10` and then emit exactly one, so
    /// nothing ever exercised a multi-member group.  Nothing detects that from the outside, so
    /// assert reachability directly: sample specs and require each interesting shape to show up.
    ///
    /// Ignored under emulation -- miri, and qemu-user for a cross-arch test archive -- because
    /// `bolero`'s budget is wall-clock (one second unless iterations are pinned), and a second of
    /// emulation buys about one sample, which cannot exhibit every shape.  The iteration count is
    /// pinned so that what this asserts does not depend on how fast the machine running it happens
    /// to be.
    #[test]
    #[cfg_attr(emulated, ignore = "needs many samples; emulation buys too few")]
    fn test_spec_generator_is_not_vacuous() {
        // Deliberately `std::sync` rather than the `concurrency::sync` facade: under the `shuttle`
        // and `loom` features that facade hands out model-checker atomics, which panic outside a
        // model-checked execution, and this is an ordinary `#[test]`.
        use std::sync::atomic::{AtomicU32, Ordering}; // nosemgrep: rust-no-direct-std-sync-import

        /// Samples to draw.  Every shape below is reachable with probability well over 1/16, so
        /// this is many orders of magnitude more than "reliable".
        const ITERATIONS: usize = 512;

        /// Shapes a generated spec can exhibit; every one must show up somewhere in the sample.
        /// Index in this array is the bit position used to record it.
        const SHAPES: &[&str] = &[
            "multiple vpcs",
            "peerings",
            "acl",
            "multi-rule acl",
            "default expose",
            "multiple exposes",
            "empty group",
            "multi-member group",
            "fabricBFD on",
            "fabricBFD off",
            "fabricBFD absent",
            "flow table capacity",
            "profiling",
            // `config::converters::k8s::config::gateway_config`'s
            // `test_fabric_bfd_fans_out_to_all_neighbors` asserts over every underlay BGP
            // neighbor, which the converter builds one-for-one from `gateway.neighbors`.  An
            // empty list satisfies that assertion vacuously, so require a non-empty one to be
            // reachable here, where the reachability claims live.
            "bgp neighbors",
        ];

        // An atomic bitmask rather than a collection behind a lock: `bolero` runs each case inside
        // `catch_unwind`, so whatever the closure captures has to be `RefUnwindSafe`, and the
        // project disallows `std::sync::Mutex`.
        let seen = AtomicU32::new(0);
        let record = |shape: &str| {
            #[allow(clippy::expect_used)]
            let bit = SHAPES
                .iter()
                .position(|s| *s == shape)
                .expect("shape not listed in SHAPES");
            seen.fetch_or(1 << bit, Ordering::Relaxed);
        };

        bolero::check!()
            .with_type::<LegalValue<GatewayAgentSpec>>()
            .with_iterations(ITERATIONS)
            .for_each(|spec| {
                let spec = spec.as_ref();

                if spec.vpcs.as_ref().is_some_and(|v| v.len() > 1) {
                    record("multiple vpcs");
                }
                if let Some(peerings) = spec.peerings.as_ref().filter(|p| !p.is_empty()) {
                    record("peerings");
                    for peering in peerings.values() {
                        if let Some(acl) = peering.acl.as_ref() {
                            record("acl");
                            if acl.rules.as_ref().is_some_and(|r| r.len() > 1) {
                                record("multi-rule acl");
                            }
                        }
                        for side in peering.peering.iter().flat_map(|p| p.values()) {
                            let Some(exposes) = side.expose.as_ref() else {
                                continue;
                            };
                            if exposes.iter().any(|e| e.default == Some(true)) {
                                record("default expose");
                            }
                            if exposes.len() > 1 {
                                record("multiple exposes");
                            }
                        }
                    }
                }
                for group in spec.groups.iter().flat_map(|g| g.values()) {
                    match group.members.as_ref().map_or(0, Vec::len) {
                        0 => record("empty group"),
                        1 => {}
                        _ => record("multi-member group"),
                    }
                }
                match spec.config.as_ref().and_then(|c| c.fabric_bfd) {
                    Some(true) => record("fabricBFD on"),
                    Some(false) => record("fabricBFD off"),
                    None => record("fabricBFD absent"),
                }
                if let Some(gw) = spec.gateway.as_ref() {
                    if gw.flow_table_capacity.is_some() {
                        record("flow table capacity");
                    }
                    if gw.profiling.is_some() {
                        record("profiling");
                    }
                    if gw.neighbors.as_ref().is_some_and(|n| !n.is_empty()) {
                        record("bgp neighbors");
                    }
                }
            });

        let seen = seen.load(Ordering::Relaxed);
        let missing: Vec<&str> = SHAPES
            .iter()
            .enumerate()
            .filter(|(bit, _)| seen & (1 << bit) == 0)
            .map(|(_, shape)| *shape)
            .collect();
        assert!(
            missing.is_empty(),
            "the spec generator never produced: {missing:?}"
        );
    }

    /// The two intake encodings must agree.
    ///
    /// A field that survives one encoding but not the other would make the k8s and k8s-less modes
    /// disagree about the same configuration, which is the failure this pins down.
    #[test]
    fn test_yaml_and_json_agree() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentSpec>>()
            .for_each(|spec| {
                let spec = spec.as_ref();
                let from_yaml: GatewayAgentSpec = serde_yaml_ng::from_str(
                    &serde_yaml_ng::to_string(spec).expect("failed to serialize as YAML"),
                )
                .expect("failed to parse YAML");
                let from_json: GatewayAgentSpec = serde_json::from_str(
                    &serde_json::to_string(spec).expect("failed to serialize as JSON"),
                )
                .expect("failed to parse JSON");
                assert_eq!(from_yaml, from_json, "YAML and JSON intake disagree");
            });
    }
}
