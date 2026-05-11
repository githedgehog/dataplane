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
    let mut prefixes_to_merge = prefixes.iter().copied().collect::<Vec<_>>();
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

pub fn merge_contiguous_prefixes(prefixes: &mut PrefixPortsSet) {
    let mut uses_ports = false;
    let mut did_merge = false;
    let mut merged_prefixes = PrefixPortsSet::default();

    // Sort the exclusion prefixes by length in ascending order (meaning a /16 comes before a /24).
    // Then start processing from the end of the vector, so we can merge smaller prefixes (bigger
    // mask lengths) together before trying to merge the results into larger ones.
    let mut sorted_prefixes = prefixes.iter().copied().collect::<Vec<_>>();
    sorted_prefixes.sort_by_key(|p| p.prefix().length());

    'next_prefix: while let Some(prefix_left) = sorted_prefixes.pop() {
        if matches!(prefix_left, PrefixWithOptionalPorts::PrefixPorts(_)) {
            uses_ports = true;
        }
        for (index_right, prefix_right) in sorted_prefixes.iter().enumerate() {
            if let Some(merged_prefix) = prefix_left.merge(prefix_right) {
                did_merge = true;
                sorted_prefixes.remove(index_right);
                // Get the new index based on the new prefix length, so we can re-insert it and
                // preserve the length order, to potentially merge this prefix again with one of the
                // same size later - including prefixes we'll only create later by merging together
                // other smaller prefixes.
                let new_index = sorted_prefixes
                    .iter()
                    .position(|p| p.prefix().length() > merged_prefix.prefix().length())
                    .unwrap_or(sorted_prefixes.len());
                sorted_prefixes.insert(new_index, merged_prefix);
                continue 'next_prefix;
            }
        }
        merged_prefixes.insert(prefix_left);
    }
    *prefixes = merged_prefixes;

    // If we merged any prefixes and we have prefixes with ports, then maybe we produced a set of
    // prefixes that could now be merged again. Recursively call the function until no more merges
    // are possible.
    //
    // If we don't use port ranges, then sorting the prefixes by length ensures that we merge
    // prefixes from longest to shortest (/32 together then /31 together, etc.), so we process new
    // "mergeable" pairs without needing another pass.
    if uses_ports && did_merge {
        merge_contiguous_prefixes(prefixes);
    }
}

#[cfg(test)]
mod bolero_tests {
    use super::*;
    use std::ops::Bound::{Excluded, Unbounded};

    #[test]
    fn test_merge_overlapping_prefixes() {
        bolero::check!()
            .with_type()
            .for_each(|set: &PrefixPortsSet| {
                let mut set_clone = set.clone();
                merge_overlapping_prefixes(&mut set_clone);
                for prefix_left in &set_clone {
                    for prefix_right in set_clone.range((Excluded(prefix_left), Unbounded)) {
                        assert!(!prefix_left.overlaps(prefix_right));
                    }
                }
            });
    }
}
