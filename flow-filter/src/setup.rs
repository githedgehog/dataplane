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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VpcdLookupResult;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeeringTable};
    use lpm::prefix::{PortRange, Prefix, PrefixWithPortsSize};
    use net::vxlan::Vni;
    use std::collections::BTreeSet;
    use std::ops::Bound;

    #[test]
    fn test_split_overlapping_basic() {
        // Test splitting 10.0.0.0/16 with mask 10.0.1.0/24
        let prefix_to_split = PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/16"), None);
        let mask_prefix = PrefixWithOptionalPorts::new(Prefix::from("10.0.1.0/24"), None);

        let result: BTreeSet<_> = split_overlapping(&prefix_to_split, &mask_prefix)
            .into_iter()
            .collect();

        // Should produce the intersection (10.0.1.0/24) and the remainder parts
        assert!(!result.is_empty());

        // Verify that one of the results is the intersection
        assert!(result.contains(&mask_prefix));

        // Verify all results together are the same size as the original prefix
        let total_ips = result
            .iter()
            .fold(PrefixWithPortsSize::from(0u8), |sum, prefix| {
                sum + prefix.size()
            });
        let original_ips = prefix_to_split.size();
        assert_eq!(total_ips, original_ips);

        // Verify all results are within the original prefix
        for prefix in &result {
            assert!(prefix_to_split.covers(prefix));
        }

        // Verify results do not overlap
        for i in &result.clone() {
            for j in result.range((Bound::Excluded(i), Bound::Unbounded)) {
                assert!(!i.overlaps(j));
            }
        }

        // Just to be on the safe side for this test, check the list manually
        let expected = BTreeSet::from([
            PrefixWithOptionalPorts::new(Prefix::from("10.0.128.0/17"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.64.0/18"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.32.0/19"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.16.0/20"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.8.0/21"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.4.0/22"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.3.0/23"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.1.0/24"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/24"), None),
        ]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_split_overlapping_with_ports() {
        // Test splitting with port ranges
        let port_range1 = PortRange::new(80, 443).unwrap();
        let port_range2 = PortRange::new(100, 200).unwrap();

        let prefix_to_split =
            PrefixWithOptionalPorts::new(Prefix::from("192.168.0.0/16"), Some(port_range1));
        let mask_prefix =
            PrefixWithOptionalPorts::new(Prefix::from("192.168.1.0/24"), Some(port_range2));

        let result: BTreeSet<_> = split_overlapping(&prefix_to_split, &mask_prefix)
            .into_iter()
            .collect();

        // Should produce multiple prefixes including the intersection
        assert!(!result.is_empty());

        // The intersection should have the intersection of both IP prefix and port range
        let intersection = prefix_to_split.intersection(&mask_prefix).unwrap();
        assert!(result.contains(&intersection));

        // Check the list manually
        let expected = BTreeSet::from([
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.0.0/16"),
                Some(PortRange::new(80, 99).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.0.0/16"),
                Some(PortRange::new(201, 443).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.128.0/17"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.64.0/18"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.32.0/19"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.16.0/20"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.8.0/21"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.4.0/22"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.3.0/23"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.1.0/24"),
                Some(PortRange::new(100, 200).unwrap()), // Corresponds to the mask
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.0.0/24"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
        ]);
        assert_eq!(result, expected, "{result:#?},\n {expected:#?}");
    }

    #[test]
    fn test_get_manifest_ips_overlap_no_overlap() {
        let vpcd1 = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let vpcd2 = VpcDiscriminant::VNI(Vni::new_checked(200).unwrap());

        let manifest1 = VpcManifest {
            name: "manifest1".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };

        let manifest2 = VpcManifest {
            name: "manifest2".to_string(),
            exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
        };

        let overlap =
            get_manifest_ips_overlap(&manifest1, &vpcd1, &manifest2, &vpcd2, |expose| &expose.ips);

        // No overlap between 10.0.0.0/24 and 20.0.0.0/24
        assert!(overlap.is_empty());
    }

    #[test]
    fn test_get_manifest_ips_overlap_with_overlap() {
        let vpcd1 = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let vpcd2 = VpcDiscriminant::VNI(Vni::new_checked(200).unwrap());

        let manifest1 = VpcManifest {
            name: "manifest1".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };

        let manifest2 = VpcManifest {
            name: "manifest2".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/25".into())],
        };

        let overlap =
            get_manifest_ips_overlap(&manifest1, &vpcd1, &manifest2, &vpcd2, |expose| &expose.ips);

        // Should have one overlap: 10.0.0.0/25 (intersection of /24 and /25)
        assert_eq!(overlap.len(), 1);
        let expected_prefix = PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None);
        assert!(overlap.contains_key(&expected_prefix));

        let vpcds = overlap.get(&expected_prefix).unwrap();
        assert_eq!(vpcds.len(), 2);
        assert!(vpcds.contains(&vpcd1));
        assert!(vpcds.contains(&vpcd2));
    }

    #[test]
    fn test_get_manifest_ips_overlap_multiple_prefixes() {
        let vpcd1 = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let vpcd2 = VpcDiscriminant::VNI(Vni::new_checked(200).unwrap());

        let manifest1 = VpcManifest {
            name: "manifest1".to_string(),
            exposes: vec![
                VpcExpose::empty()
                    .ip("10.0.0.0/24".into())
                    .ip("20.0.0.128/25".into()),
            ],
        };

        let manifest2 = VpcManifest {
            name: "manifest2".to_string(),
            exposes: vec![
                VpcExpose::empty().ip("10.0.0.0/25".into()),
                VpcExpose::empty().ip("20.0.0.0/24".into()),
            ],
        };

        let overlap =
            get_manifest_ips_overlap(&manifest1, &vpcd1, &manifest2, &vpcd2, |expose| &expose.ips);

        // Should have two overlaps: 10.0.0.0/25 and 20.0.0.128/25
        assert_eq!(overlap.len(), 2);

        let prefix1 = PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None);
        let prefix2 = PrefixWithOptionalPorts::new(Prefix::from("20.0.0.128/25"), None);

        assert!(overlap.contains_key(&prefix1));
        assert!(overlap.contains_key(&prefix2));
    }

    #[test]
    fn test_consolidate_overlap_list_no_merge() {
        let vpcd1 = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let vpcd2 = VpcDiscriminant::VNI(Vni::new_checked(200).unwrap());

        let mut overlap = BTreeMap::new();
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None),
            HashSet::from([vpcd1]),
        );
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("20.0.0.0/25"), None),
            HashSet::from([vpcd2]),
        );

        let result = consolidate_overlap_list(overlap);

        // Should have two separate prefixes (no merging possible)
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_consolidate_overlap_list_with_merge() {
        let vpcd1 = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let vpcd2 = VpcDiscriminant::VNI(Vni::new_checked(200).unwrap());

        let mut overlap = BTreeMap::new();
        // These two adjacent /25 prefixes can merge into a /24
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None),
            HashSet::from([vpcd1, vpcd2]),
        );
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.128/25"), None),
            HashSet::from([vpcd1, vpcd2]),
        );

        let result = consolidate_overlap_list(overlap);

        // Should merge into a single /24
        assert_eq!(result.len(), 1);
        let expected_prefix = PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/24"), None);
        assert!(result.contains_key(&expected_prefix));
    }

    #[test]
    fn test_get_split_prefixes_for_manifest_no_overlap() {
        let vpcd = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());

        let manifest = VpcManifest {
            name: "manifest".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };

        let overlaps = BTreeMap::new();

        let result =
            get_split_prefixes_for_manifest(&manifest, &vpcd, |expose| &expose.ips, overlaps);

        // With no overlaps, should return the original prefix with Single result
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].0,
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/24"), None)
        );
        assert_eq!(result[0].1, VpcdLookupResult::Single(vpcd));
    }

    #[test]
    fn test_get_split_prefixes_for_manifest_with_overlap() {
        let vpcd1 = VpcDiscriminant::VNI(Vni::new_checked(100).unwrap());
        let vpcd2 = VpcDiscriminant::VNI(Vni::new_checked(200).unwrap());

        let manifest = VpcManifest {
            name: "manifest".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };

        let mut overlaps = BTreeMap::new();
        // The overlap covers part of the manifest's prefix
        overlaps.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None),
            HashSet::from([vpcd1, vpcd2]),
        );

        let mut result =
            get_split_prefixes_for_manifest(&manifest, &vpcd1, |expose| &expose.ips, overlaps);
        result.sort_by_key(|(prefix, _)| *prefix);

        // Should split into multiple prefixes
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].0,
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None)
        );
        assert_eq!(result[0].1, VpcdLookupResult::MultipleMatches);
        assert_eq!(
            result[1].0,
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.128/25"), None)
        );
        assert_eq!(result[1].1, VpcdLookupResult::Single(vpcd1));
    }

    #[test]
    fn test_process_peering_no_overlap() {
        let mut vpc_table = VpcTable::new();

        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();

        let mut vpc1 = Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap();
        let vpc2 = Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap();

        vpc1.peerings.push(Peering {
            name: "vpc1-to-vpc2".to_string(),
            local: VpcManifest {
                name: "vpc1-local".to_string(),
                exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
            },
            remote: VpcManifest {
                name: "vpc2-remote".to_string(),
                exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
            },
            remote_id: "VPC02".try_into().unwrap(),
            gwgroup: None,
            adv_communities: vec![],
        });

        vpc_table.add(vpc1.clone()).unwrap();
        vpc_table.add(vpc2).unwrap();

        let overlay = Overlay {
            vpc_table,
            peering_table: VpcPeeringTable::new(),
        };

        let mut table = FlowFilterTable::new();
        table
            .process_peering(&overlay, &vpc1, &vpc1.peerings[0])
            .unwrap();

        let src_vpcd = VpcDiscriminant::VNI(vni1);
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.5".parse().unwrap();

        let dst_vpcd = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_vpcd,
            Some(VpcdLookupResult::Single(VpcDiscriminant::VNI(vni2)))
        );
    }

    #[test]
    fn test_process_peering_with_overlap() {
        let mut vpc_table = VpcTable::new();

        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();
        let vni3 = Vni::new_checked(300).unwrap();

        let mut vpc1 = Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap();
        let vpc2 = Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap();
        let vpc3 = Vpc::new("vpc3", "VPC03", vni3.as_u32()).unwrap();

        // Add two peerings with overlapping remote prefixes
        vpc1.peerings.push(Peering {
            name: "vpc1-to-vpc2".to_string(),
            local: VpcManifest {
                name: "vpc1-local".to_string(),
                exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
            },
            remote: VpcManifest {
                name: "vpc2-remote".to_string(),
                exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
            },
            remote_id: "VPC02".try_into().unwrap(),
            gwgroup: None,
            adv_communities: vec![],
        });

        vpc1.peerings.push(Peering {
            name: "vpc1-to-vpc3".to_string(),
            local: VpcManifest {
                name: "vpc1-local2".to_string(),
                exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
            },
            remote: VpcManifest {
                name: "vpc3-remote".to_string(),
                exposes: vec![VpcExpose::empty().ip("20.0.0.0/25".into())],
            },
            remote_id: "VPC03".try_into().unwrap(),
            gwgroup: None,
            adv_communities: vec![],
        });

        vpc_table.add(vpc1.clone()).unwrap();
        vpc_table.add(vpc2).unwrap();
        vpc_table.add(vpc3).unwrap();

        let overlay = Overlay {
            vpc_table,
            peering_table: VpcPeeringTable::new(),
        };

        let mut table = FlowFilterTable::new();
        table
            .process_peering(&overlay, &vpc1, &vpc1.peerings[0])
            .unwrap();

        let src_vpcd = VpcDiscriminant::VNI(vni1);
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.5".parse().unwrap(); // In overlapping segment

        let dst_vpcd = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(dst_vpcd, Some(VpcdLookupResult::MultipleMatches));

        let src_vpcd = VpcDiscriminant::VNI(vni1);
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.129".parse().unwrap(); // Not in overlapping segment

        let dst_vpcd = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_vpcd,
            Some(VpcdLookupResult::Single(VpcDiscriminant::VNI(vni2)))
        );
    }

    #[test]
    fn test_clone_skipping_peerings() {
        let mut vpc = Vpc::new("test-vpc", "VPC01", 100).unwrap();

        vpc.peerings.push(Peering {
            name: "peering1".to_string(),
            local: VpcManifest {
                name: "local1".to_string(),
                exposes: vec![],
            },
            remote: VpcManifest {
                name: "remote1".to_string(),
                exposes: vec![],
            },
            remote_id: "VPC02".try_into().unwrap(),
            gwgroup: None,
            adv_communities: vec![],
        });

        let cloned = clone_skipping_peerings(&vpc);

        assert_eq!(cloned.name, vpc.name);
        assert_eq!(cloned.id, vpc.id);
        assert_eq!(cloned.vni, vpc.vni);
        assert_eq!(cloned.peerings.len(), 0);
    }

    #[test]
    fn test_cleanup_vpc_table() {
        let mut vpc = Vpc::new("test-vpc", "VPC01", 100).unwrap();

        // Add a peering with some exposes
        vpc.peerings.push(Peering {
            name: "peering1".to_string(),
            local: VpcManifest {
                name: "local1".to_string(),
                exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
            },
            remote: VpcManifest {
                name: "remote1".to_string(),
                exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
            },
            remote_id: "VPC02".try_into().unwrap(),
            gwgroup: None,
            adv_communities: vec![],
        });

        let vpcs = vec![&vpc];
        let result = cleanup_vpc_table(vpcs);

        assert!(result.is_ok());
        let cleaned_vpcs = result.unwrap();
        assert_eq!(cleaned_vpcs.len(), 1);
        assert_eq!(cleaned_vpcs[0].name, vpc.name);
    }

    #[test]
    fn test_build_from_overlay() {
        // Create a simple overlay with two VPCs and a peering
        let mut vpc_table = VpcTable::new();

        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();

        let mut vpc1 = Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap();
        let vpc2 = Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap();

        // Add peering from vpc1 to vpc2
        vpc1.peerings.push(Peering {
            name: "vpc1-to-vpc2".to_string(),
            local: VpcManifest {
                name: "vpc1-local".to_string(),
                exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
            },
            remote: VpcManifest {
                name: "vpc2-remote".to_string(),
                exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
            },
            remote_id: "VPC02".try_into().unwrap(),
            gwgroup: None,
            adv_communities: vec![],
        });

        vpc_table.add(vpc1).unwrap();
        vpc_table.add(vpc2).unwrap();

        let overlay = Overlay {
            vpc_table,
            peering_table: VpcPeeringTable::new(),
        };

        let result = FlowFilterTable::build_from_overlay(&overlay);
        assert!(result.is_ok());

        let table = result.unwrap();
        // Should be able to look up flows
        let src_vpcd = VpcDiscriminant::VNI(vni1);
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.5".parse().unwrap();

        let dst_vpcd = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_vpcd,
            Some(VpcdLookupResult::Single(VpcDiscriminant::VNI(vni2)))
        );
    }
}
