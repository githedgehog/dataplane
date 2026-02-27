// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::FlowFilterTable;
use crate::tables::{NatRequirement, RemoteData, VpcdLookupResult};
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
                table.add_peering(overlay, vpc, peering)?;
            }
        }
        debug!("Flow filter table successfully built: {table:?}");
        Ok(table)
    }

    fn add_peering(
        &mut self,
        overlay: &Overlay,
        vpc: &Vpc,
        peering: &Peering,
    ) -> Result<(), ConfigError> {
        let local_vpcd = VpcDiscriminant::VNI(vpc.vni);
        let dst_vpcd = VpcDiscriminant::VNI(overlay.vpc_table.get_remote_vni(peering));
        let (local_manifests_overlap, remote_manifests_overlap) =
            get_manifests_overlap(overlay, vpc, peering, dst_vpcd);

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

        // Handle local default expose (for all remote prefixes)
        if let Some(local_default_expose) = peering.local.default_expose()? {
            for (remote_prefix, remote_vpcd_result, remote_nat_req) in &remote_prefixes {
                let dst_data_result = match remote_vpcd_result {
                    VpcdLookupResult::Single(dst_data) => {
                        VpcdLookupResult::Single(RemoteData::new(
                            dst_data.vpcd,
                            get_nat_requirement(local_default_expose),
                            *remote_nat_req,
                        ))
                    }
                    VpcdLookupResult::MultipleMatches(_) => {
                        return Err(ConfigError::InternalFailure(
                            "Unexpected multiple matches for destination VPC when handling local default expose".to_string(),
                        ));
                    }
                };
                self.insert_default_source(
                    local_vpcd,
                    dst_data_result,
                    remote_prefix.prefix(),
                    remote_prefix.ports(),
                )?;
            }
        }

        // Handle remote default expose (for all local prefixes)
        if let Some(remote_default_expose) = peering.remote.default_expose()? {
            for (local_prefix, local_vpcd_result, local_nat_req) in &local_prefixes {
                let dst_data_result = match local_vpcd_result {
                    VpcdLookupResult::Single(dst_data) => {
                        VpcdLookupResult::Single(RemoteData::new(
                            dst_data.vpcd,
                            *local_nat_req,
                            get_nat_requirement(remote_default_expose),
                        ))
                    }
                    VpcdLookupResult::MultipleMatches(_) => {
                        return Err(ConfigError::InternalFailure(
                            "Unexpected multiple matches for destination VPC when handling remote default expose".to_string(),
                        ));
                    }
                };
                self.insert_default_remote(
                    local_vpcd,
                    dst_data_result,
                    local_prefix.prefix(),
                    local_prefix.ports(),
                )?;
            }
        }

        // Handle the case when we have both local and remote default exposes
        if let Some(local_default_expose) = peering.local.default_expose()?
            && let Some(remote_default_expose) = peering.remote.default_expose()?
        {
            let dst_data = RemoteData::new(
                dst_vpcd,
                get_nat_requirement(local_default_expose),
                get_nat_requirement(remote_default_expose),
            );
            self.insert_default_source_to_default_remote(
                local_vpcd,
                VpcdLookupResult::Single(dst_data),
            )?;
        }

        // Now, handle all the other, regular prefixes
        for (local_prefix, local_vpcd_result, local_nat_req) in &local_prefixes {
            for (remote_prefix, remote_vpcd_result, remote_nat_req) in &remote_prefixes {
                let remote_vpcd_to_use = match (remote_vpcd_result, local_vpcd_result) {
                    (
                        VpcdLookupResult::MultipleMatches(dst_data),
                        VpcdLookupResult::MultipleMatches(_),
                    ) => {
                        // Update the source NAT requirement for all matching destinations
                        let data = dst_data
                            .iter()
                            .cloned()
                            .map(|mut d| {
                                d.src_nat_req = *local_nat_req;
                                d
                            })
                            .collect();
                        VpcdLookupResult::MultipleMatches(data)
                    }
                    (
                        VpcdLookupResult::MultipleMatches(dst_data),
                        VpcdLookupResult::Single(local_dst_data),
                    ) => {
                        // If the remote prefix is ambiguous but we are able to tell what
                        // destination VPC to use based on the local prefix in use, do so.
                        //
                        // Assuming we have distinct remote_nat_req between exposes, we'll create
                        // several RemoteData entries for the same destination VPC, but indicating
                        // the NAT mode is ambiguous.
                        //
                        // Note: We should never have a single entry in the MultipleMatches at the
                        // end of the processing, because this would mean we have overlapping
                        // prefixes with the same NAT mode; otherwise, if there's no overlap, we
                        // should have created a Single variant.
                        let data = dst_data
                            .iter()
                            .cloned()
                            .map(|mut d| {
                                d.vpcd = local_dst_data.vpcd;
                                d.src_nat_req = *local_nat_req;
                                d
                            })
                            .collect();
                        VpcdLookupResult::MultipleMatches(data)
                    }
                    (VpcdLookupResult::Single(dst_data), VpcdLookupResult::MultipleMatches(_)) => {
                        VpcdLookupResult::MultipleMatches(HashSet::from([RemoteData::new(
                            dst_data.vpcd,
                            *local_nat_req,
                            *remote_nat_req,
                        )]))
                    }
                    (VpcdLookupResult::Single(dst_data), VpcdLookupResult::Single(_)) => {
                        VpcdLookupResult::Single(RemoteData::new(
                            dst_data.vpcd,
                            *local_nat_req,
                            *remote_nat_req,
                        ))
                    }
                };

                self.insert(
                    local_vpcd,
                    remote_vpcd_to_use,
                    local_prefix.prefix(),
                    local_prefix.ports(),
                    remote_prefix.prefix(),
                    remote_prefix.ports(),
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

// Compute lists of overlapping prefixes:
// - between prefixes from remote manifest and prefixes from remote manifests for other peerings
// - between prefixes from local manifest and prefixes from local manifests for other peerings
fn get_manifests_overlap(
    overlay: &Overlay,
    vpc: &Vpc,
    peering: &Peering,
    dst_vpcd: VpcDiscriminant,
) -> (
    BTreeMap<PrefixWithOptionalPorts, HashSet<RemoteData>>,
    BTreeMap<PrefixWithOptionalPorts, HashSet<RemoteData>>,
) {
    let mut local_manifests_overlap = BTreeMap::new();
    let mut remote_manifests_overlap = BTreeMap::new();
    for other_peering in &vpc.peerings {
        let compare_to_self = other_peering.name == peering.name;
        let other_dst_vpcd = VpcDiscriminant::VNI(overlay.vpc_table.get_remote_vni(other_peering));

        // Get overlap for prefixes related to source address
        let local_overlap = get_manifest_ips_overlap(
            &peering.local,
            &other_peering.local,
            dst_vpcd,
            other_dst_vpcd,
            |expose| &expose.ips,
            compare_to_self,
        );
        // Get overlap for prefixes related to destination address
        let remote_overlap = get_manifest_ips_overlap(
            &peering.remote,
            &other_peering.remote,
            dst_vpcd,
            other_dst_vpcd,
            |expose| expose.public_ips(),
            compare_to_self,
        );

        // If either side has no overlap, we'll be able to tell which is the destination VPC by
        // looking at both the source and destination prefixes for the packet, so there's no need to
        // account for any overlap...
        if local_overlap.is_empty() || remote_overlap.is_empty() {
            // ... However, when we compare two expose blocks from the same manifest, we want to
            // split anyway: this is the case when we have two expose blocks on the same side of a
            // peering with overlapping prefixes, one with stateful NAT, one with port forwarding,
            // for example. In such a case we need to split to determine what portion of the
            // overlapping prefixes is shared.
            if !compare_to_self {
                continue;
            }
        }

        // If there's overlap for both source and destination, we'll need to split prefixes to
        // separate the overlapping sections, so we can determine the destination VPC for
        // non-overlapping sections
        local_manifests_overlap.extend(local_overlap);
        remote_manifests_overlap.extend(remote_overlap);
    }
    (local_manifests_overlap, remote_manifests_overlap)
}

// Return the list of overlapping prefix sections between the sets of exposed prefixes of two
// manifests
//
// For example:
//
// - first manifest exposes 1.0.0.0/24 and 2.0.0.128/25
// - second manifest exposes 1.0.0.0/23, 2.0.0.0/24, and 3.0.0.0/8
// - the function returns [1.0.0.0/24, 2.0.0.128/25]
//
// Exclude the "default"-destination expose blocks from overlap calculation.
fn get_manifest_ips_overlap(
    manifest_left: &VpcManifest,
    manifest_right: &VpcManifest,
    dst_vpcd_left: VpcDiscriminant,
    dst_vpcd_right: VpcDiscriminant,
    get_ips: fn(&VpcExpose) -> &BTreeSet<PrefixWithOptionalPorts>,
    compare_to_self: bool,
) -> BTreeMap<PrefixWithOptionalPorts, HashSet<RemoteData>> {
    let mut overlap = BTreeMap::new();
    for expose_left in manifest_left
        .exposes
        .iter()
        .filter(|expose| !expose.default)
    {
        for expose_right in manifest_right
            .exposes
            .iter()
            .filter(|expose| !expose.default)
        {
            if compare_to_self && expose_left == expose_right {
                // We're comparing the expose to itself: skip
                continue;
            }
            for prefix_left in get_ips(expose_left).iter() {
                for prefix_right in get_ips(expose_right).iter() {
                    if let Some(intersection) = prefix_left.intersection(prefix_right) {
                        overlap.insert(
                            intersection,
                            HashSet::from([
                                RemoteData::new(
                                    dst_vpcd_left,
                                    None, // Unknown at this stage
                                    get_nat_requirement(expose_left),
                                ),
                                RemoteData::new(
                                    dst_vpcd_right,
                                    None, // Unknown at this stage
                                    get_nat_requirement(expose_right),
                                ),
                            ]),
                        );
                    }
                }
            }
        }
    }
    overlap
}

// Consolidate overlapping prefixes, by merging adjacent prefixes when possible
// This is to avoid splitting prefixes for a peering more than necessary
fn consolidate_overlap_list(
    mut overlap: BTreeMap<PrefixWithOptionalPorts, HashSet<RemoteData>>,
) -> BTreeMap<PrefixWithOptionalPorts, HashSet<RemoteData>> {
    let mut consolidated_overlap = BTreeMap::new();
    while let Some((first_prefix, first_data)) = overlap.pop_first() {
        let Some((&second_prefix, second_data)) = overlap.first_key_value() else {
            // We've reached the end of the list, just insert the last item we popped
            consolidated_overlap.insert(first_prefix, first_data);
            break;
        };
        // Only merge if associated RemoteData objects are the same
        if first_data
            .symmetric_difference(second_data)
            .next()
            .is_none()
            && let Some(merged_prefix) = first_prefix.merge(&second_prefix)
        {
            overlap.remove(&second_prefix);
            overlap.insert(merged_prefix, first_data);
            continue;
        }
        consolidated_overlap.insert(first_prefix, first_data);
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
    overlaps: BTreeMap<PrefixWithOptionalPorts, HashSet<RemoteData>>,
) -> Vec<(
    PrefixWithOptionalPorts,
    VpcdLookupResult,
    Option<NatRequirement>,
)> {
    let mut prefixes_with_vpcd = Vec::new();
    for expose in &manifest.exposes {
        let nat_req = get_nat_requirement(expose);
        'next_prefix: for prefix in get_ips(expose) {
            for (overlap_prefix, overlap_data) in overlaps.iter() {
                if overlap_prefix.covers(prefix) {
                    prefixes_with_vpcd.push((
                        *prefix,
                        VpcdLookupResult::MultipleMatches(overlap_data.clone()),
                        nat_req,
                    ));
                    continue 'next_prefix;
                } else if prefix.covers(overlap_prefix) {
                    // The current prefix partially overlaps with some other prefixes (of which
                    // overlap_prefix is the union of all intersections with the current prefix), so
                    // we need to split the current prefix into parts that don't have partial
                    // overlap with the other prefixes
                    prefixes_with_vpcd.extend(
                        split_overlapping(prefix, overlap_prefix)
                            .into_iter()
                            .map(|p| {
                                (
                                    p,
                                    if p == *overlap_prefix {
                                        // Multiple destination VPC matches for the overlapping section
                                        VpcdLookupResult::MultipleMatches(overlap_data.clone())
                                    } else {
                                        // Single destination VPC match for the other sections
                                        VpcdLookupResult::Single(RemoteData::new(*vpcd, None, None))
                                    },
                                    nat_req,
                                )
                            }),
                    );
                    continue 'next_prefix;
                }
            }
            // We found no overlap, just add the prefix with the single associated destination VPC
            prefixes_with_vpcd.push((
                *prefix,
                VpcdLookupResult::Single(RemoteData::new(*vpcd, None, None)),
                nat_req,
            ));
        }
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

fn get_nat_requirement(expose: &VpcExpose) -> Option<NatRequirement> {
    expose.nat.as_ref().map(NatRequirement::from_nat)
}

#[cfg(test)]
mod tests {
    use crate::tables::VpcdLookupResult;

    use super::*;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeeringTable};
    use lpm::prefix::{L4Protocol, PortRange, Prefix, PrefixWithPortsSize};
    use net::packet::VpcDiscriminant;
    use net::vxlan::Vni;
    use std::collections::BTreeSet;
    use std::ops::Bound;

    fn vni(id: u32) -> Vni {
        Vni::new_checked(id).unwrap()
    }
    fn vpcd(id: u32) -> VpcDiscriminant {
        VpcDiscriminant::VNI(vni(id))
    }

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
        let vpcd1 = vpcd(100);
        let vpcd2 = vpcd(200);

        let manifest1 = VpcManifest {
            name: "manifest1".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };

        let manifest2 = VpcManifest {
            name: "manifest2".to_string(),
            exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
        };

        let overlap = get_manifest_ips_overlap(
            &manifest1,
            &manifest2,
            vpcd1,
            vpcd2,
            |expose| &expose.ips,
            false,
        );

        // No overlap between 10.0.0.0/24 and 20.0.0.0/24
        assert!(overlap.is_empty());
    }

    #[test]
    fn test_get_manifest_ips_overlap_with_overlap() {
        let vpcd1 = vpcd(100);
        let vpcd2 = vpcd(200);

        let manifest1 = VpcManifest {
            name: "manifest1".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };

        let manifest2 = VpcManifest {
            name: "manifest2".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/25".into())],
        };

        let overlap = get_manifest_ips_overlap(
            &manifest1,
            &manifest2,
            vpcd1,
            vpcd2,
            |expose| &expose.ips,
            false,
        );

        // Should have one overlap: 10.0.0.0/25 (intersection of /24 and /25)
        assert_eq!(overlap.len(), 1);
        let expected_prefix = PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None);
        assert!(overlap.get(&expected_prefix).is_some_and(|set| {
            set.len() == 2
                && set.contains(&RemoteData::new(vpcd1, None, None))
                && set.contains(&RemoteData::new(vpcd2, None, None))
        }));
    }

    #[test]
    fn test_get_manifest_ips_overlap_with_overlap_and_ports() {
        let vpcd1 = vpcd(100);
        let vpcd2 = vpcd(200);

        let manifest1 = VpcManifest {
            name: "manifest1".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };

        let manifest2 = VpcManifest {
            name: "manifest2".to_string(),
            exposes: vec![VpcExpose::empty().ip(PrefixWithOptionalPorts::new(
                "10.0.0.0/25".into(),
                Some(PortRange::new(100, 200).unwrap()),
            ))],
        };

        let overlap = get_manifest_ips_overlap(
            &manifest1,
            &manifest2,
            vpcd1,
            vpcd2,
            |expose| &expose.ips,
            false,
        );

        // Should have one overlap: 10.0.0.0/25 with ports 100-200 (intersection of /24 and /25 and
        // port ranges)
        assert_eq!(overlap.len(), 1);
        let expected_prefix = PrefixWithOptionalPorts::new(
            Prefix::from("10.0.0.0/25"),
            Some(PortRange::new(100, 200).unwrap()),
        );
        assert!(overlap.get(&expected_prefix).is_some_and(|set| {
            set.len() == 2
                && set.contains(&RemoteData::new(vpcd1, None, None))
                && set.contains(&RemoteData::new(vpcd2, None, None))
        }));
    }

    #[test]
    fn test_get_manifest_ips_overlap_multiple_prefixes() {
        let vpcd1 = vpcd(100);
        let vpcd2 = vpcd(200);

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
                VpcExpose::empty()
                    .make_stateful_nat(None)
                    .unwrap()
                    .ip("10.0.0.0/25".into()),
                VpcExpose::empty().ip("20.0.0.0/24".into()),
            ],
        };

        let overlap = get_manifest_ips_overlap(
            &manifest1,
            &manifest2,
            vpcd1,
            vpcd2,
            |expose| &expose.ips,
            false,
        );

        // Should have two overlaps: 10.0.0.0/25 and 20.0.0.128/25
        assert_eq!(overlap.len(), 2);

        let prefix1 = PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None);
        let prefix2 = PrefixWithOptionalPorts::new(Prefix::from("20.0.0.128/25"), None);

        assert!(
            overlap.get(&prefix1).is_some_and(|set| {
                set.len() == 2
                    // Sending to 10.0.0.0/25 via manifest 1 requires no NAT
                    && set.contains(&RemoteData::new(vpcd1, None, None))
                    // Replying to 10.0.0.0/25 via manifest 2 requires stateful (destination) NAT
                    && set.contains(&RemoteData::new(
                        vpcd2,
                        None,
                        Some(NatRequirement::Stateful),
                    ))
            }),
            "{overlap:#?}"
        );

        assert!(
            overlap.get(&prefix2).is_some_and(|set| {
                // Sending to 20.0.0.128/25 requires no NAT
                set.len() == 2
                    && set.contains(&RemoteData::new(vpcd1, None, None))
                    && set.contains(&RemoteData::new(vpcd2, None, None))
            }),
            "{overlap:#?}"
        );
    }

    #[test]
    fn test_consolidate_overlap_list_no_merge() {
        let mut overlap = BTreeMap::new();
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None),
            HashSet::new(),
        );
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("20.0.0.0/25"), None),
            HashSet::new(),
        );

        let result = consolidate_overlap_list(overlap);

        // Should have two separate prefixes (no merging possible)
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_consolidate_overlap_list_with_merge() {
        let mut overlap = BTreeMap::new();
        // These two adjacent /25 prefixes can merge into a /24
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None),
            HashSet::new(),
        );
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.128/25"), None),
            HashSet::new(),
        );

        let result = consolidate_overlap_list(overlap);

        // Should merge into a single /24
        assert_eq!(result.len(), 1);
        let expected_prefix = PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/24"), None);
        assert!(result.contains_key(&expected_prefix));
    }

    #[test]
    fn test_consolidate_overlap_list_differing_dst_vpcd() {
        let mut overlap = BTreeMap::new();
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None),
            HashSet::from([RemoteData::new(vpcd(100), None, None)]),
        );
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.128/25"), None),
            HashSet::from([RemoteData::new(vpcd(200), None, None)]),
        );

        let result = consolidate_overlap_list(overlap);

        // Should have two separate prefixes (no merging possible)
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_consolidate_overlap_list_differing_nat_requirements() {
        let mut overlap = BTreeMap::new();
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None),
            HashSet::from([RemoteData::new(
                vpcd(200),
                None,
                Some(NatRequirement::Stateful),
            )]),
        );
        overlap.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.128/25"), None),
            HashSet::from([RemoteData::new(
                vpcd(200),
                None,
                Some(NatRequirement::PortForwarding(L4Protocol::Any)),
            )]),
        );

        let result = consolidate_overlap_list(overlap);

        // Should have two separate prefixes (no merging possible)
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_get_split_prefixes_for_manifest_no_overlap() {
        let vpcd = vpcd(100);

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
        assert_eq!(
            result[0].1,
            VpcdLookupResult::Single(RemoteData::new(vpcd, None, None))
        );
    }

    #[test]
    fn test_get_split_prefixes_for_manifest_with_overlap() {
        let vpcd = vpcd(100);

        let manifest = VpcManifest {
            name: "manifest".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };

        let mut overlaps = BTreeMap::new();
        // The overlap covers part of the manifest's prefix
        overlaps.insert(
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None),
            HashSet::new(),
        );

        let mut result =
            get_split_prefixes_for_manifest(&manifest, &vpcd, |expose| &expose.ips, overlaps);
        result.sort_by_key(|(prefix, _, _)| *prefix);

        // Should split into multiple prefixes
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].0,
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/25"), None)
        );
        assert!(matches!(result[0].1, VpcdLookupResult::MultipleMatches(_)));
        assert_eq!(
            result[1].0,
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.128/25"), None)
        );
        assert_eq!(
            result[1].1,
            VpcdLookupResult::Single(RemoteData::new(vpcd, None, None))
        );
    }

    #[test]
    fn test_add_peering_no_overlap() {
        let mut vpc_table = VpcTable::new();

        let vni1 = vni(100);
        let vni2 = vni(200);

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
        });

        vpc_table.add(vpc1.clone()).unwrap();
        vpc_table.add(vpc2).unwrap();

        let overlay = Overlay {
            vpc_table,
            peering_table: VpcPeeringTable::new(),
        };

        let mut table = FlowFilterTable::new();
        table
            .add_peering(&overlay, &vpc1, &vpc1.peerings[0])
            .unwrap();

        let src_vpcd = vni1.into();
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.5".parse().unwrap();

        let dst_data = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_data,
            Some(VpcdLookupResult::Single(RemoteData::new(
                vni2.into(),
                None,
                None
            )))
        );
    }

    #[test]
    fn test_process_peering_with_overlap() {
        let mut vpc_table = VpcTable::new();

        let vni1 = vni(100);
        let vni2 = vni(200);
        let vni3 = vni(300);

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
            .add_peering(&overlay, &vpc1, &vpc1.peerings[0])
            .unwrap();

        let src_vpcd = vni1.into();
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.5".parse().unwrap(); // In overlapping segment

        let dst_vpcd = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_vpcd,
            Some(VpcdLookupResult::MultipleMatches(HashSet::from([
                RemoteData::new(vni2.into(), None, None),
                RemoteData::new(vni3.into(), None, None),
            ])))
        );

        let src_vpcd = vni1.into();
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.129".parse().unwrap(); // Not in overlapping segment

        let dst_vpcd = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_vpcd,
            // Note: We have a MultipleMatches variant with only one element: this happens because
            // we have overlapping prefixes with the same NAT mode, which is not usually allowed
            // outside of tests. Here it's OK.
            Some(VpcdLookupResult::MultipleMatches(HashSet::from([
                RemoteData::new(vni2.into(), None, None)
            ])))
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

        let dst_data = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_data,
            Some(VpcdLookupResult::Single(RemoteData::new(
                VpcDiscriminant::VNI(vni2),
                None,
                None
            )))
        );
    }
}
