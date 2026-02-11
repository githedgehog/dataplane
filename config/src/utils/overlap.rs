// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ConfigError;
use crate::external::overlay::vpcpeering::VpcExpose;
use crate::utils::collapse_prefix_lists;
use lpm::prefix::{IpRangeWithPorts, PrefixWithOptionalPorts, PrefixWithPortsSize};
use std::collections::BTreeSet;

pub fn check_private_prefixes_dont_overlap(
    expose_left: &VpcExpose,
    expose_right: &VpcExpose,
) -> Result<(), ConfigError> {
    check_prefixes_dont_overlap(
        &expose_left.ips,
        &expose_left.nots,
        &expose_right.ips,
        &expose_right.nots,
    )
}

// Check for overlap for the lists of public prefixes.
// Depending on whether exposes require NAT, this can be:
// - expose_left.as_range / expose_right.as_range
// - expose_left.ips      / expose_right.as_range
// - expose_left.as_range / expose_right.ips
// - expose_left.ips      / expose_right.ips
// (along with the respective exclusion prefixes applied).
pub fn check_public_prefixes_dont_overlap(
    expose_left: &VpcExpose,
    expose_right: &VpcExpose,
) -> Result<(), ConfigError> {
    check_prefixes_dont_overlap(
        expose_left.public_ips(),
        expose_left.public_excludes(),
        expose_right.public_ips(),
        expose_right.public_excludes(),
    )
}

// Validate that two sets of prefixes, with their exclusion prefixes applied, don't overlap
fn check_prefixes_dont_overlap(
    prefixes_left: &BTreeSet<PrefixWithOptionalPorts>,
    excludes_left: &BTreeSet<PrefixWithOptionalPorts>,
    prefixes_right: &BTreeSet<PrefixWithOptionalPorts>,
    excludes_right: &BTreeSet<PrefixWithOptionalPorts>,
) -> Result<(), ConfigError> {
    // Find colliding prefixes
    let mut colliding = Vec::new();
    for prefix_left in prefixes_left {
        for prefix_right in prefixes_right {
            if prefix_left.overlaps(prefix_right) {
                colliding.push((*prefix_left, *prefix_right));
            }
        }
    }
    // If not prefixes collide, we're good - exit.
    if colliding.is_empty() {
        return Ok(());
    }

    // How do we determine whether there is a collision between the set of available addresses on
    // the left side, and the set of available addresses on the right side? A collision means:
    //
    // - Prefixes collide, in other words, they have a non-empty intersection (we've checked that
    //   earlier)
    //
    // - This intersection is not fully covered by exclusion prefixes
    //
    // The idea in the loop below is that for each pair of colliding prefixes:
    //
    // - We retrieve the size of the intersection of the colliding prefixes.
    //
    // - We retrieve the size of the union of the intersections of all the exclusion prefixes (from
    //   left and right sides) covering part of this intersection.
    //
    // - If the size of the intersection of colliding allowed prefixes is bigger than the size of
    //   the union of the intersections of the exclusion prefixes applying to these allowed
    //   prefixes, then it means that some addresses are effectively allowed in both the left-side
    //   and the right-side set of available addresses, and this is an error. If the sizes are
    //   identical, then all addresses in the intersection of the prefixes are excluded on at least
    //   one side, so it's all good.
    for (prefix_left, prefix_right) in colliding {
        let intersection_prefix = prefix_left.intersection(&prefix_right).unwrap_or_else(|| {
            unreachable!(); // These prefixes were paired precisely because they collide
        });

        // We need to compute the size of the union of the excluded prefixes. Start by adding the
        // sizes of all exclusion prefixes, from both sides.
        let mut union_excludes_size = PrefixWithPortsSize::from(0u8);

        // Now we remove once the size of the intersection of each pair of excluded prefixes, to
        // avoid double-counting some ranges. We know that all exclusion prefixes on the left side
        // are disjoint, and all so are exclusion prefixes on the right side, which means that we
        // cannot have more than two prefixes overlapping. It's enough to look for intersection of
        // all left-side prefixes with each right-side prefix.
        for exclude_left in excludes_left
            .iter()
            .filter(|exclude| exclude.overlaps(&intersection_prefix))
        {
            let exclude_covering_allowed_left = exclude_left
                .intersection(&intersection_prefix)
                .unwrap_or_else(|| {
                    // We filtered prefixes with overlap with intersection_prefix
                    unreachable!();
                });
            union_excludes_size += exclude_covering_allowed_left.size();
            for exclude_right in excludes_right
                .iter()
                .filter(|exclude| exclude.overlaps(&intersection_prefix))
            {
                let exclude_covering_allowed_right = exclude_right
                    .intersection(&intersection_prefix)
                    .unwrap_or_else(|| {
                        // We filtered prefixes with overlap with intersection_prefix
                        unreachable!();
                    });
                union_excludes_size += exclude_covering_allowed_right.size();
                // Remove size of intersection, to avoid double-counting for a given range
                union_excludes_size -= exclude_covering_allowed_left
                    .intersection(&exclude_covering_allowed_right)
                    .map_or(PrefixWithPortsSize::from(0u8), |p| p.size());
            }
        }

        if union_excludes_size < intersection_prefix.size() {
            // Some addresses at the intersection of both prefixes are not covered by the union of
            // all exclusion prefixes, in other words, they are available from both prefixes. This
            // is an error.
            return Err(ConfigError::OverlappingPrefixes(prefix_left, prefix_right));
        }
    }
    Ok(())
}

// Check that private prefixes in expose_left and expose_right overlap if and only if the set of
// prefixes in expose_left fully covers the one in expose_right; and then check the same for public
// prefixes of expose_left and expose_right.
pub fn check_no_overlap_or_left_contains_right(
    expose_left: &VpcExpose,
    expose_right: &VpcExpose,
) -> Result<(), ConfigError> {
    check_prefix_lists_no_overlap_or_left_contains_right(
        &expose_left.ips,
        &expose_left.nots,
        &expose_right.ips,
        &expose_right.nots,
    )?;
    check_prefix_lists_no_overlap_or_left_contains_right(
        expose_left.public_ips(),
        expose_left.public_excludes(),
        expose_right.public_ips(),
        expose_right.public_excludes(),
    )
}

fn check_prefix_lists_no_overlap_or_left_contains_right(
    prefixes_left: &BTreeSet<PrefixWithOptionalPorts>,
    excludes_left: &BTreeSet<PrefixWithOptionalPorts>,
    prefixes_right: &BTreeSet<PrefixWithOptionalPorts>,
    excludes_right: &BTreeSet<PrefixWithOptionalPorts>,
) -> Result<(), ConfigError> {
    let collapsed_prefixes_left = collapse_prefix_lists(prefixes_left, excludes_left);
    let collapsed_prefixes_right = collapse_prefix_lists(prefixes_right, excludes_right);
    for prefix_left in &collapsed_prefixes_left {
        for prefix_right in &collapsed_prefixes_right {
            if prefix_left.overlaps(prefix_right) && !prefix_left.covers(prefix_right) {
                return Err(ConfigError::OverlappingPrefixes(
                    *prefix_left,
                    *prefix_right,
                ));
            }
        }
    }
    Ok(())
}
