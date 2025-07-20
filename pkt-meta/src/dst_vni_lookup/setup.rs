// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::dst_vni_lookup::{DstVniLookupError, VniTable, VniTables};
use config::ConfigError;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Peering, VpcTable};
use config::utils::{ConfigUtilError, collapse_prefixes_peering};

fn process_peering(
    table: &mut VniTable,
    peering: &Peering,
    vpc_table: &VpcTable,
) -> Result<(), DstVniLookupError> {
    let new_peering = collapse_prefixes_peering(peering).map_err(|e| match e {
        ConfigUtilError::SplitPrefixError(prefix) => {
            DstVniLookupError::BuildError(prefix.to_string())
        }
    })?;

    /* get vni for remote manifest */
    let remote_vni = vpc_table
        .get_vpc_by_vpcid(&new_peering.remote_id)
        .unwrap_or_else(|| unreachable!())
        .vni;

    new_peering.remote.exposes.iter().for_each(|expose| {
        let remote_public_prefixes = expose.public_ips();
        for prefix in remote_public_prefixes {
            table.dst_vnis.insert(*prefix, remote_vni);
        }
    });
    Ok(())
}

/// Build the `dst_vni_lookup` configuration from an overlay.
///
/// # Errors
///
/// Returns an error if the configuration cannot be built.
pub fn build_dst_vni_lookup_configuration(overlay: &Overlay) -> Result<VniTables, ConfigError> {
    let mut vni_tables = VniTables::new();
    for vpc in overlay.vpc_table.values() {
        let mut table = VniTable::new();
        for peering in &vpc.peerings {
            process_peering(&mut table, peering, &overlay.vpc_table)
                .map_err(|e| ConfigError::FailureApply(e.to_string()))?;
        }
        vni_tables.tables_by_vni.insert(vpc.vni, table);
    }
    Ok(vni_tables)
}
