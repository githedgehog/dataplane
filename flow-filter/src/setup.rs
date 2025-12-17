// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::FlowFilterTable;
use crate::tables::VpcdLookupResult;
use config::ConfigError;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Peering, Vpc};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use config::internal::interfaces::interface::InterfaceConfigTable;
use config::utils::{ConfigUtilError, collapse_prefixes_peering};
use lpm::prefix::{IpRangeWithPorts, PrefixWithOptionalPorts};
use net::packet::VpcDiscriminant;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use tracectl::trace_target;
use tracing::debug;
trace_target!("flow-filter-setup", LevelFilter::INFO, &[]);

impl FlowFilterTable {
    /// Build a [`FlowFilterTable`] from an overlay
    pub fn build_from_overlay(overlay: &Overlay) -> Result<Self, ConfigError> {
        let clean_vpc_table = cleanup_vpc_table(overlay.vpc_table.values().collect())?;
        let mut table = FlowFilterTable::new();

        for vpc in &clean_vpc_table {
            for peering in &vpc.peerings {
                table.process_peering(overlay, vpc, peering)?;
            }
        }
        debug!("Flow filter table successfully built: {table:?}");
        Ok(table)
    }

    // When processing a peering, we split prefixes when they have partial overlapping with prefixes
    // from other peerings for the same VPC
    //
    // For example:
    //
    // - VPC A is peered with VPC B and C
    // - VPC B exposes 10.0.0.0/24 and 20.0.0.128/25
    // - VPC C exposes 10.0.0.0/25 and 20.0.0.0/24
    //
    // When packet A sends to 10.0.0.1, we don't know whether the destination VPC is B or C.
    // However, if A sends to 10.0.0.200, we know that the destination is in VPC B.
    //
    // To account for the non-overlapping section of the prefixes, we split the prefix exposed by
    // the remote end of the peering: for A's peering with B, the remote end becomes {10.0.0.0/25,
    // 10.0.0.128/25, 20.0.0.128/25}. This way, when we do the destination VPC lookup, we can tell
    // that the result is ambiguous if we get a match on 10.0.0.0/25, but we can find a unique
    // answer if we get a match on 10.0.0.128/25.
    //
    // Similarly, for A's peering with C, the remote ends of the peering becomes {10.0.0.0/25,
    // 20.0.0.0/25, 20.0.0.128/25}.
    fn process_peering(
        &mut self,
        overlay: &Overlay,
        vpc: &Vpc,
        peering: &Peering,
    ) -> Result<(), ConfigError> {
        let local_vpcd = VpcDiscriminant::VNI(vpc.vni);

        // Compute lists of overlapping prefixes:
        // - between prefixes from remote manifest and prefixes from remote manifests for other peerings
        // - between prefixes from local manifest and prefixes from local manifests for other peerings
        let mut local_manifests_overlap = BTreeMap::new();
        let mut remote_manifests_overlap = BTreeMap::new();
        for other_peering in &vpc.peerings {
            if other_peering.name == peering.name {
                // Don't compare peering with itself
                continue;
            }
            let remote_vpcd = VpcDiscriminant::VNI(overlay.vpc_table.get_remote_vni(other_peering));
            // Get overlap for prefixes related to source address
            let local_overlap = get_manifest_ips_overlap(
                &peering.local,
                &local_vpcd,
                &other_peering.local,
                &remote_vpcd,
                |expose| &expose.ips,
            );
            // Get overlap for prefixes related to destination address
            let remote_overlap = get_manifest_ips_overlap(
                &peering.remote,
                &local_vpcd,
                &other_peering.remote,
                &remote_vpcd,
                |expose| expose.public_ips(),
            );

            if local_overlap.is_empty() || remote_overlap.is_empty() {
                // If either side has no overlap, we'll be able to tell which is the destination VPC
                // by looking at both the source and destination prefixes for the packet, so there's
                // no need to account for any overlap
                continue;
            }

            // If there's overlap for both source and destination, we'll need to split prefixes to
            // separate the overlapping sections, so we can determine the destination VPC for
            // non-overlapping sections
            local_manifests_overlap.extend(local_overlap);
            remote_manifests_overlap.extend(remote_overlap);
        }

        let dst_vpcd = VpcDiscriminant::VNI(overlay.vpc_table.get_remote_vni(peering));

        // Get list of local prefixes, splitting to account for overlapping, if necessary
        let overlap_trie = consolidate_overlap_list(local_manifests_overlap);
        let local_prefixes = get_split_prefixes_for_manifest(
            &peering.local,
            &dst_vpcd,
            |expose| &expose.ips,
            overlap_trie,
        );

        // Get list of remote prefixes, splitting to account for overlapping, if necessary
        let overlap_trie = consolidate_overlap_list(remote_manifests_overlap);
        let remote_prefixes = get_split_prefixes_for_manifest(
            &peering.remote,
            &dst_vpcd,
            |expose| expose.public_ips(),
            overlap_trie,
        );

        // For each local prefix, add one entry for each associated remote prefix
        for (local_prefix, local_vpcd_result) in &local_prefixes {
            for (remote_prefix, remote_vpcd_result) in &remote_prefixes {
                let remote_vpcd_to_use = match (remote_vpcd_result, local_vpcd_result) {
                    (VpcdLookupResult::MultipleMatches, VpcdLookupResult::Single(_)) => {
                        // If the remote prefix is ambiguous but we are able to tell what
                        // destination VPC to use based on the local prefix in use, do so
                        local_vpcd_result.clone()
                    }
                    _ => remote_vpcd_result.clone(),
                };
                self.insert(
                    local_vpcd,
                    remote_vpcd_to_use,
                    local_prefix.prefix(),
                    local_prefix.ports().into(),
                    remote_prefix.prefix(),
                    remote_prefix.ports().into(),
                )?;
            }
        }
        Ok(())
    }
}

fn cleanup_vpc_table(vpcs: Vec<&Vpc>) -> Result<Vec<Vpc>, ConfigError> {
    let mut new_set = Vec::new();
    for vpc in vpcs {
        let mut new_vpc = clone_skipping_peerings(vpc);

        for peering in &vpc.peerings {
            // "Collapse" prefixes to get rid of exclusion prefixes
            let collapsed_peering = collapse_prefixes_peering(peering).map_err(|e| match e {
                ConfigUtilError::SplitPrefixError(prefix) => {
                    ConfigError::FailureApply(format!("Failed to split prefix: {prefix}"))
                }
            })?;
            new_vpc.peerings.push(collapsed_peering);
        }
        new_set.push(new_vpc);
    }
    Ok(new_set)
}

fn clone_skipping_peerings(vpc: &Vpc) -> Vpc {
    Vpc {
        name: vpc.name.clone(),
        id: vpc.id.clone(),
        vni: vpc.vni,
        interfaces: InterfaceConfigTable::default(),
        peerings: vec![],
    }
}

// Return the list of overlapping prefix sections between the sets of exposed prefixes of two
// manifests
//
// For example:
//
// - first manifest exposes 1.0.0.0/24 and 2.0.0.128/25
// - second manifest exposes 1.0.0.0/23, 2.0.0.0/24, and 3.0.0.0/8
// - the function returns [1.0.0.0/24, 2.0.0.128/25] and associated VPC discriminants
fn get_manifest_ips_overlap(
    manifest_left: &VpcManifest,
    vcpd_left: &VpcDiscriminant,
    manifest_right: &VpcManifest,
    vcpd_right: &VpcDiscriminant,
    get_ips: fn(&VpcExpose) -> &BTreeSet<PrefixWithOptionalPorts>,
) -> BTreeMap<PrefixWithOptionalPorts, HashSet<VpcDiscriminant>> {
    let mut overlap = BTreeMap::new();
    for prefix_left in manifest_left
        .exposes
        .iter()
        .flat_map(|expose| get_ips(expose).iter())
    {
        for prefix_right in manifest_right
            .exposes
            .iter()
            .flat_map(|expose| get_ips(expose).iter())
        {
            if let Some(intersection) = prefix_left.intersection(prefix_right) {
                let vpcds = HashSet::from([*vcpd_left, *vcpd_right]);
                overlap.insert(intersection, vpcds);
            }
        }
    }
    overlap
}

// Consolidate overlapping prefixes, by merging adjacent prefixes when possible
// This is to avoid splitting prefixes for a peering more than necessary
fn consolidate_overlap_list(
    mut overlap: BTreeMap<PrefixWithOptionalPorts, HashSet<VpcDiscriminant>>,
) -> BTreeMap<PrefixWithOptionalPorts, HashSet<VpcDiscriminant>> {
    let mut consolidated_overlap = BTreeMap::new();
    while let Some((first_prefix, first_vpcds)) = overlap.pop_first() {
        let Some((&second_prefix, second_vpcds)) = overlap.first_key_value() else {
            // We've reached the end of the list, just insert the last item we popped
            consolidated_overlap.insert(first_prefix, first_vpcds.clone());
            break;
        };
        if let Some(merged_prefix) = first_prefix.merge(&second_prefix) {
            let merged_set = first_vpcds.union(second_vpcds).cloned().collect();
            overlap.remove(&second_prefix);
            overlap.insert(merged_prefix, merged_set);
            continue;
        }
        consolidated_overlap.insert(first_prefix, first_vpcds.clone());
    }
    consolidated_overlap
}

// Return all exposed prefixes for a manifest, split such that there is no partial overlapping with
// manifests for other peerings.
//
// For example:
//
// - VPC A is peered with VPC B and C
// - VPC B exposes 10.0.0.0/24
// - VPC C exposes 10.0.0.0/25
//
// Then the prefixes in the remote manifests for VPC A's peerings will be:
//
// - For VPC B: [10.0.0.0/25, 10.0.0.128/25] (split so that 10.0.0.0/24 does not overlap partially
//   with VPC C's 10.0.0.0/25)
// - For VPC C: [10.0.0.0/25]
fn get_split_prefixes_for_manifest(
    manifest: &VpcManifest,
    vpcd: &VpcDiscriminant,
    get_ips: fn(&VpcExpose) -> &BTreeSet<PrefixWithOptionalPorts>,
    overlaps: BTreeMap<PrefixWithOptionalPorts, HashSet<VpcDiscriminant>>,
) -> Vec<(PrefixWithOptionalPorts, VpcdLookupResult)> {
    let mut prefixes_with_vpcd = Vec::new();
    'next_prefix: for prefix in manifest
        .exposes
        .iter()
        .flat_map(|expose| get_ips(expose).iter())
    {
        for (overlap_prefix, _overlap_vpcds) in overlaps.iter() {
            if overlap_prefix.covers(prefix) {
                // The overlap prefix covers the current prefix, so we know the current prefix is
                // overlapping and is associated to multiple matches for the destination VPC lookup
                prefixes_with_vpcd.push((*prefix, VpcdLookupResult::MultipleMatches));
                continue 'next_prefix;
            } else if prefix.covers(overlap_prefix) {
                // The current prefix partially overlaps with some other prefixes (of which
                // overlap_prefix is the union of all intersections with the current prefix), so we
                // need to split the current prefix into parts that don't have partial overlap with
                // the other prefixes
                prefixes_with_vpcd.extend(
                    split_overlapping(prefix, overlap_prefix)
                        .into_iter()
                        .map(|p| {
                            (
                                p,
                                if p == *overlap_prefix {
                                    // Multiple destination VPC matches for the overlapping section
                                    VpcdLookupResult::MultipleMatches
                                } else {
                                    // Single destination VPC match for the other sections
                                    VpcdLookupResult::Single(*vpcd)
                                },
                            )
                        }),
                );
                continue 'next_prefix;
            }
        }
        // We found no overlap, just add the prefix with the single associated destination VPC
        prefixes_with_vpcd.push((*prefix, VpcdLookupResult::Single(*vpcd)));
    }
    prefixes_with_vpcd
}

// Split a prefix into the given subprefix, and the difference
fn split_overlapping(
    prefix_to_split: &PrefixWithOptionalPorts,
    mask_prefix: &PrefixWithOptionalPorts,
) -> Vec<PrefixWithOptionalPorts> {
    debug_assert!(prefix_to_split.overlaps(mask_prefix) && !mask_prefix.covers(prefix_to_split));
    let mut split_prefixes = prefix_to_split.subtract(mask_prefix);
    split_prefixes.push(
        prefix_to_split
            .intersection(mask_prefix)
            // Intersection non-empty given that prefixes overlap
            .unwrap_or_else(|| unreachable!()),
    );
    split_prefixes
}
