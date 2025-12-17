// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::FlowFilterTable;
use config::ConfigError;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::Peering;
use config::external::overlay::vpcpeering::VpcExpose;
use config::utils::{ConfigUtilError, collapse_prefixes_peering};
use net::packet::VpcDiscriminant;

impl FlowFilterTable {
    /// Build a [`FlowFilterTable`] from an overlay
    pub fn build_from_overlay(overlay: &Overlay) -> Result<Self, ConfigError> {
        let mut table = FlowFilterTable::new();
        for vpc in overlay.vpc_table.values() {
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
        // "Collapse" prefixes to get rid of exclusion prefixes
        let collapsed_peering = collapse_prefixes_peering(peering).map_err(|e| match e {
            ConfigUtilError::SplitPrefixError(prefix) => {
                ConfigError::FailureApply(format!("Failed to split prefix: {prefix}"))
            }
        })?;

        for local_prefix in collapsed_peering
            .local
            .exposes
            .iter()
            .flat_map(VpcExpose::public_ips)
        {
            for remote_prefix in collapsed_peering
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
