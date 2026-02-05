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
use std::collections::BTreeSet;

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
            get_manifests_overlap(vpc, peering);

        // Get list of local prefixes, splitting to account for overlapping, if necessary
        let local_prefixes = get_prefixes_for_manifest(
            &peering.local,
            &dst_vpcd,
            |expose| &expose.ips,
            local_manifests_overlap,
        );

        // Get list of remote prefixes, splitting to account for overlapping, if necessary
        let remote_prefixes = get_prefixes_for_manifest(
            &peering.remote,
            &dst_vpcd,
            |expose| expose.public_ips(),
            remote_manifests_overlap,
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
                    VpcdLookupResult::MultipleMatches => {
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
                    VpcdLookupResult::MultipleMatches => {
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
                    (VpcdLookupResult::MultipleMatches, VpcdLookupResult::MultipleMatches) => {
                        VpcdLookupResult::MultipleMatches
                    }
                    (VpcdLookupResult::MultipleMatches, VpcdLookupResult::Single(dst_data)) => {
                        // If the remote prefix is ambiguous but we are able to tell what
                        // destination VPC to use based on the local prefix in use, do so
                        VpcdLookupResult::Single(RemoteData::new(
                            dst_data.vpcd,
                            *local_nat_req,
                            *remote_nat_req,
                        ))
                    }
                    (VpcdLookupResult::Single(dst_data), _) => VpcdLookupResult::Single(
                        RemoteData::new(dst_data.vpcd, *local_nat_req, *remote_nat_req),
                    ),
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
    vpc: &Vpc,
    peering: &Peering,
) -> (
    BTreeSet<PrefixWithOptionalPorts>,
    BTreeSet<PrefixWithOptionalPorts>,
) {
    let mut local_manifests_overlap = BTreeSet::new();
    let mut remote_manifests_overlap = BTreeSet::new();
    for other_peering in &vpc.peerings {
        if other_peering.name == peering.name {
            // Don't compare peering with itself
            continue;
        }
        // Get overlap for prefixes related to source address
        let local_overlap =
            get_manifest_ips_overlap(&peering.local, &other_peering.local, |expose| &expose.ips);
        // Get overlap for prefixes related to destination address
        let remote_overlap =
            get_manifest_ips_overlap(&peering.remote, &other_peering.remote, |expose| {
                expose.public_ips()
            });

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
    get_ips: fn(&VpcExpose) -> &BTreeSet<PrefixWithOptionalPorts>,
) -> BTreeSet<PrefixWithOptionalPorts> {
    let mut overlap = BTreeSet::new();
    for prefix_left in manifest_left
        .exposes
        .iter()
        .filter(|expose| !expose.default)
        .flat_map(|expose| get_ips(expose).iter())
    {
        for prefix_right in manifest_right
            .exposes
            .iter()
            .filter(|expose| !expose.default)
            .flat_map(|expose| get_ips(expose).iter())
        {
            if let Some(intersection) = prefix_left.intersection(prefix_right) {
                overlap.insert(intersection);
            }
        }
    }
    overlap
}

// Return all exposed prefixes for a manifest
fn get_prefixes_for_manifest(
    manifest: &VpcManifest,
    vpcd: &VpcDiscriminant,
    get_ips: fn(&VpcExpose) -> &BTreeSet<PrefixWithOptionalPorts>,
    overlaps: BTreeSet<PrefixWithOptionalPorts>,
) -> Vec<(
    PrefixWithOptionalPorts,
    VpcdLookupResult,
    Option<NatRequirement>,
)> {
    let mut prefixes_with_vpcd = Vec::new();
    for expose in &manifest.exposes {
        let nat_req = get_nat_requirement(expose);
        'next_prefix: for prefix in get_ips(expose) {
            for overlap_prefix in overlaps.iter() {
                if overlap_prefix == prefix {
                    prefixes_with_vpcd.push((
                        *prefix,
                        VpcdLookupResult::MultipleMatches,
                        nat_req,
                    ));
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

fn get_nat_requirement(expose: &VpcExpose) -> Option<NatRequirement> {
    let nat = expose.nat.as_ref()?;
    debug_assert!(!(nat.is_stateful() && nat.is_stateless())); // Only one NAT mode allowed

    if nat.is_stateful() {
        Some(NatRequirement::Stateful)
    } else if nat.is_stateless() {
        Some(NatRequirement::Stateless)
    } else {
        unreachable!("Unknown NAT mode")
    }
}

#[cfg(test)]
mod tests {
    use crate::tables::VpcdLookupResult;

    use super::*;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeeringTable};
    use net::packet::VpcDiscriminant;
    use net::vxlan::Vni;

    #[test]
    fn test_add_peering() {
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
