// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ConfigError;
use crate::external::overlay::vpcpeering::ValidatedExpose;
use lpm::prefix::{IpRangeWithPorts, PrefixPortsSet, PrefixWithOptionalPorts};

pub fn check_private_prefixes_dont_overlap(
    expose_left: &ValidatedExpose,
    expose_right: &ValidatedExpose,
) -> Result<(), ConfigError> {
    if port_forwarding_with_distinct_l4_protocols(expose_left, expose_right) {
        return Ok(());
    }
    check_prefixes_dont_overlap(expose_left.ips(), expose_right.ips())
}

// Check for overlap for the lists of public prefixes.
// Depending on whether exposes require NAT, this can be:
// - expose_left.as_range / expose_right.as_range
// - expose_left.ips      / expose_right.as_range
// - expose_left.as_range / expose_right.ips
// - expose_left.ips      / expose_right.ips
pub fn check_public_prefixes_dont_overlap(
    expose_left: &ValidatedExpose,
    expose_right: &ValidatedExpose,
) -> Result<(), ConfigError> {
    if port_forwarding_with_distinct_l4_protocols(expose_left, expose_right) {
        return Ok(());
    }
    check_prefixes_dont_overlap(expose_left.public_ips(), expose_right.public_ips())
}

// If the two expose blocks have port forwarding set up, one for TCP and one for UDP, then there is
// no overlap.
fn port_forwarding_with_distinct_l4_protocols(
    expose_left: &ValidatedExpose,
    expose_right: &ValidatedExpose,
) -> bool {
    expose_left.has_port_forwarding()
        && expose_right.has_port_forwarding()
        && expose_left.nat_proto().is_some_and(|proto_left| {
            expose_right
                .nat_proto()
                .is_some_and(|proto_right| proto_left.intersection(proto_right).is_none())
        })
}

// Validate that two sets of prefixes, with their exclusion prefixes applied, don't overlap
fn check_prefixes_dont_overlap(
    prefixes_left: &PrefixPortsSet,
    prefixes_right: &PrefixPortsSet,
) -> Result<(), ConfigError> {
    for prefix_left in prefixes_left {
        for prefix_right in prefixes_right {
            if prefix_left.overlaps(prefix_right) {
                return Err(ConfigError::OverlappingPrefixes(
                    *prefix_left,
                    *prefix_right,
                ));
            }
        }
    }
    Ok(())
}

pub fn merge_overlapping_prefixes(prefixes: &mut PrefixPortsSet) {
    let mut prefixes_to_merge = prefixes
        .iter()
        .copied()
        .collect::<Vec<PrefixWithOptionalPorts>>();
    let mut merged_prefixes = PrefixPortsSet::default();

    'next_prefix: while let Some(prefix_left) = prefixes_to_merge.pop() {
        for prefix_right in &prefixes_to_merge {
            if prefix_left.overlaps(prefix_right) {
                let fragments_left = prefix_left.subtract(prefix_right);
                prefixes_to_merge.extend(fragments_left);
                continue 'next_prefix;
            }
        }
        merged_prefixes.insert(prefix_left);
    }

    *prefixes = merged_prefixes;
}
