// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::FlowFilterTable;
use config::ConfigError;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Peering, Vpc};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use config::internal::interfaces::interface::InterfaceConfigTable;
use config::utils::{ConfigUtilError, collapse_prefixes_peering};
use lpm::prefix::{IpRangeWithPorts, PrefixWithOptionalPorts};
use net::packet::VpcDiscriminant;

impl FlowFilterTable {
    /// Build a [`FlowFilterTable`] from an overlay
    pub fn build_from_overlay(overlay: &Overlay) -> Result<Self, ConfigError> {
        let clean_vpc_table = cleanup_vpc_table(overlay.vpc_table.values().collect())?;
        let mut table = FlowFilterTable::new();

        for vpc in &clean_vpc_table {
            for peering in &vpc.peerings {
                // Get the destination VPC discriminant
                let src_vpcd = VpcDiscriminant::VNI(vpc.vni);
                let dst_vpcd = Self::get_dst_vpcd_for_peering(overlay, peering)?;
                table.add_peering(peering, src_vpcd, dst_vpcd)?;
            }
        }
        Ok(table)
    }

    fn get_dst_vpcd_for_peering(
        overlay: &Overlay,
        peering: &Peering,
    ) -> Result<VpcDiscriminant, ConfigError> {
        Ok(VpcDiscriminant::VNI(
            overlay
                .vpc_table
                .get_vpc_by_vpcid(&peering.remote_id)
                .ok_or_else(|| {
                    ConfigError::FailureApply(format!(
                        "Remote VPC {} not found in VPC table",
                        peering.remote_id
                    ))
                })?
                .vni,
        ))
    }

    fn add_peering(
        &mut self,
        peering: &Peering,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
    ) -> Result<(), ConfigError> {
        for local_prefix in peering.local.exposes.iter().flat_map(|expose| &expose.ips) {
            for remote_prefix in peering
                .remote
                .exposes
                .iter()
                .flat_map(VpcExpose::public_ips)
            {
                self.insert(
                    src_vpcd,
                    dst_vpcd,
                    local_prefix.prefix(),
                    local_prefix.ports().into(),
                    remote_prefix.prefix(),
                    remote_prefix.ports().into(),
                );
            }
        }
        Ok(())
    }
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

fn clone_skipping_local_exposes(peering: &Peering) -> Peering {
    Peering {
        name: peering.name.clone(),
        local: VpcManifest {
            name: peering.local.name.clone(),
            exposes: vec![],
        },
        remote: peering.remote.clone(),
        remote_id: peering.remote_id.clone(),
    }
}

fn cleanup_vpc_table(vpcs: Vec<&Vpc>) -> Result<Vec<Vpc>, ConfigError> {
    let mut new_set = Vec::new();
    for vpc in vpcs {
        let mut tmp_vpc = clone_skipping_peerings(vpc);

        for peering in &vpc.peerings {
            // "Collapse" prefixes to get rid of exclusion prefixes
            let collapsed_peering = collapse_prefixes_peering(peering).map_err(|e| match e {
                ConfigUtilError::SplitPrefixError(prefix) => {
                    ConfigError::FailureApply(format!("Failed to split prefix: {prefix}"))
                }
            })?;
            tmp_vpc.peerings.push(collapsed_peering);
        }

        let new_vpc = split_overlaps_in_src_prefixes(&mut tmp_vpc);

        new_set.push(new_vpc);
    }
    Ok(new_set)
}

fn split_overlaps_in_src_prefixes(vpc: &mut Vpc) -> Vpc {
    let mut new_vpc = clone_skipping_peerings(vpc);
    while let Some(mut peering) = vpc.peerings.pop() {
        let mut new_peering = clone_skipping_local_exposes(&peering);
        while let Some(mut expose) = peering.local.exposes.pop() {
            let mut new_expose = VpcExpose::default();
            'next_prefix: while let Some(prefix) = expose.ips.pop_first() {
                for other_peering in &vpc.peerings {
                    for other_expose in &other_peering.local.exposes {
                        for other_prefix in other_expose.ips.iter() {
                            if prefix.overlaps(other_prefix) && !other_prefix.covers(&prefix) {
                                expose.ips.extend(split_overlapping(prefix, *other_prefix));
                                continue 'next_prefix;
                            }
                        }
                    }
                }
                for new_peering in &new_vpc.peerings {
                    for new_expose in &new_peering.local.exposes {
                        for new_prefix in new_expose.ips.iter() {
                            if prefix.overlaps(new_prefix) && !new_prefix.covers(&prefix) {
                                expose.ips.extend(split_overlapping(prefix, *new_prefix));
                                continue 'next_prefix;
                            }
                        }
                    }
                }
                new_expose = new_expose.ip(prefix);
            }
            new_peering.local.exposes.push(new_expose);
        }
        new_vpc.peerings.push(new_peering);
    }
    new_vpc
}

fn split_overlapping(
    prefix_to_split: PrefixWithOptionalPorts,
    mask_prefix: PrefixWithOptionalPorts,
) -> Vec<PrefixWithOptionalPorts> {
    debug_assert!(prefix_to_split.overlaps(&mask_prefix) && !mask_prefix.covers(&prefix_to_split));
    let mut split_prefixes = prefix_to_split.subtract(&mask_prefix);
    split_prefixes.push(
        prefix_to_split
            .intersection(&mask_prefix)
            // Intersection non-empty given that prefixes overlap
            .unwrap_or_else(|| unreachable!()),
    );
    split_prefixes
}
