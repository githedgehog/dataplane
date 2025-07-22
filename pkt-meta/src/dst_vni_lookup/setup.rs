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

#[cfg(test)]
mod tests {
    use super::*;
    use config::external::overlay::Overlay;
    use config::external::overlay::vpc::{Peering, Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeeringTable};
    use lpm::prefix::Prefix;
    use net::vxlan::Vni;
    use std::net::IpAddr;

    fn build_overlay() -> (Vni, Vni, Overlay) {
        // Build VpcExpose objects
        //
        //     expose:
        //       - ips:
        //         - cidr: 1.1.0.0/16
        //         - cidr: 1.2.0.0/16 # <- 1.2.3.4 will match here
        //         - not: 1.1.5.0/24  # to account for when computing the offset
        //         - not: 1.1.3.0/24  # to account for when computing the offset
        //         - not: 1.1.1.0/24  # to account for when computing the offset
        //         - not: 1.2.2.0/24  # to account for when computing the offset
        //         as:
        //         - cidr: 2.2.0.0/16
        //         - cidr: 2.1.0.0/16 # <- corresp. target range, initially
        //                            # (prefixes in BTreeSet are sorted)
        //                            # offset for 2.1.255.4, before applying exlusions
        //                            # final offset is for 2.2.0.4 after accounting for the one
        //                            # relevant exclusion prefix
        //         - not: 2.1.8.0/24  # to account for when fetching the address in range
        //         - not: 2.2.10.0/24
        //         - not: 2.2.1.0/24  # ignored, offset too low
        //         - not: 2.2.2.0/24  # ignored, offset too low
        //       - ips:
        //         - cidr: 3.0.0.0/16
        //         as:
        //         - cidr: 4.0.0.0/16
        let expose1 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .not("1.1.5.0/24".into())
            .not("1.1.3.0/24".into())
            .not("1.1.1.0/24".into())
            .ip("1.2.0.0/16".into())
            .not("1.2.2.0/24".into())
            .as_range("2.2.0.0/16".into())
            .not_as("2.1.8.0/24".into())
            .not_as("2.2.10.0/24".into())
            .not_as("2.2.1.0/24".into())
            .not_as("2.2.2.0/24".into())
            .as_range("2.1.0.0/16".into());
        let expose2 = VpcExpose::empty()
            .ip("3.0.0.0/16".into())
            .as_range("4.0.0.0/16".into());

        let manifest1 = VpcManifest {
            name: "VPC-1".into(),
            exposes: vec![expose1, expose2],
        };

        //     expose:
        //       - ips: # Note the lack of "as" here
        //         - cidr: 8.0.0.0/17
        //         - cidr: 9.0.0.0/17
        //         - not: 8.0.0.0/24
        //       - ips:
        //         - cidr: 10.0.0.0/16 # <- corresponding target range
        //         - not: 10.0.1.0/24  # to account for when fetching the address in range
        //         - not: 10.0.2.0/24  # to account for when fetching the address in range
        //         as:
        //         - cidr: 5.5.0.0/17
        //         - cidr: 5.6.0.0/17  # <- 5.6.7.8 will match here
        //         - not: 5.6.0.0/24   # to account for when computing the offset
        //         - not: 5.6.8.0/24
        let expose3 = VpcExpose::empty()
            .ip("8.0.0.0/17".into())
            .not("8.0.0.0/24".into())
            .ip("9.0.0.0/17".into());
        let expose4 = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("10.0.1.0/24".into())
            .not("10.0.2.0/24".into())
            .as_range("5.5.0.0/17".into())
            .as_range("5.6.0.0/17".into())
            .not_as("5.6.0.0/24".into())
            .not_as("5.6.8.0/24".into());

        let manifest2 = VpcManifest {
            name: "VPC-2".into(),
            exposes: vec![expose3, expose4],
        };

        let peering1 = Peering {
            name: "test_peering1".into(),
            local: manifest1.clone(),
            remote: manifest2.clone(),
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };
        let peering2 = Peering {
            name: "test_peering2".into(),
            local: manifest2,
            remote: manifest1,
            remote_id: "67890".try_into().expect("Failed to create VPC ID"),
        };

        let mut vpctable = VpcTable::new();

        // vpc-1
        let vni1 = Vni::new_checked(100).unwrap();
        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1.as_u32()).unwrap();
        vpc1.peerings.push(peering1.clone());
        vpctable.add(vpc1).unwrap();

        // vpc-2
        let vni2 = Vni::new_checked(200).unwrap();
        let mut vpc2 = Vpc::new("VPC-2", "12345", vni2.as_u32()).unwrap();
        vpc2.peerings.push(peering2.clone());
        vpctable.add(vpc2).unwrap();

        // Now test building the dst_vni_lookup configuration
        let overlay = Overlay {
            vpc_table: vpctable,
            peering_table: VpcPeeringTable::new(),
        };

        (vni1, vni2, overlay)
    }

    #[test]
    fn test_setup() {
        let (vni1, vni2, overlay) = build_overlay();
        let result = build_dst_vni_lookup_configuration(&overlay);
        assert!(
            result.is_ok(),
            "Failed to build dst_vni_lookup configuration:\n{:#?}",
            result.err()
        );

        let vni_tables = result.unwrap();
        assert_eq!(vni_tables.tables_by_vni.len(), 2);
        println!(
            "vni_tables: {:?}",
            vni_tables.tables_by_vni.get(&vni1).unwrap().dst_vnis
        );

        //////////////////////
        // table for vni 1 (uses second expose block, ensures we look at them all)
        assert_eq!(
            vni_tables
                .tables_by_vni
                .get(&vni1)
                .unwrap()
                .dst_vnis
                .lookup("5.5.5.1".parse::<IpAddr>().unwrap()),
            Some((Prefix::from("5.5.0.0/17"), &vni2))
        );

        assert_eq!(
            vni_tables
                .tables_by_vni
                .get(&vni1)
                .unwrap()
                .dst_vnis
                .lookup("5.6.0.1".parse::<IpAddr>().unwrap()),
            None
        );

        // Make sure dst VNI lookup for non-NAT stuff works
        assert_eq!(
            vni_tables
                .tables_by_vni
                .get(&vni1)
                .unwrap()
                .dst_vnis
                .lookup("8.0.1.1".parse::<IpAddr>().unwrap()),
            Some((Prefix::from("8.0.1.0/24"), &vni2))
        );

        //////////////////////
        // table for vni 2 (uses first expose block, ensures we look at them all)
        assert_eq!(
            vni_tables
                .tables_by_vni
                .get(&vni2)
                .unwrap()
                .dst_vnis
                .lookup("2.2.0.1".parse::<IpAddr>().unwrap()),
            Some((Prefix::from("2.2.0.0/24"), &vni1))
        );

        assert_eq!(
            vni_tables
                .tables_by_vni
                .get(&vni2)
                .unwrap()
                .dst_vnis
                .lookup("2.2.2.1".parse::<IpAddr>().unwrap()),
            None
        );
    }
}
