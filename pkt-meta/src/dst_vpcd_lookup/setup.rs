// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::dst_vpcd_lookup::{DstVpcdLookupError, VpcDiscriminantTable, VpcDiscriminantTables};
use config::ConfigError;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Peering, VpcTable};
use config::utils::{ConfigUtilError, collapse_prefixes_peering};
use lpm::prefix::Prefix;
use lpm::prefix::ip::IpPrefixColliding;
use net::packet::VpcDiscriminant;
use tracing::debug;

fn insert_prefix_or_update_duplicates(
    table: &mut VpcDiscriminantTable,
    dst_vpcd: VpcDiscriminant,
    prefix: &Prefix,
    colliding_prefixes: Vec<Prefix>,
) {
    println!("colliding_prefixes: {colliding_prefixes:?}");
    if colliding_prefixes.is_empty() {
        // No collision, insert new entry
        table.dst_vpcds.insert(*prefix, Some(dst_vpcd));
    } else {
        // For a given source VPC discriminant, for a given, we have overlapping destination
        // prefixes with different destination VPC discriminants, meaning we cannot uniquely
        // determine the destination VPC discriminant for a packet based on source VPC and
        // an address from the intersection of these prefixes.
        //
        // Set the value as None, to indicate that we cannot tell for now.
        //
        // This value may be changed later, based on stateful NAT allocations.
        for p in colliding_prefixes {
            table.dst_vpcds.insert(p, None);
        }
        debug!(
            "Destination VPC discriminant table: duplicate prefix {} for destination discriminant {}",
            prefix, dst_vpcd
        );
        table.dst_vpcds.insert(*prefix, None);
    }
}

fn process_prefix(table: &mut VpcDiscriminantTable, dst_vpcd: VpcDiscriminant, prefix: &Prefix) {
    match prefix {
        Prefix::IPV4(prefix_v4) => {
            let colliding_prefixes = table
                .dst_vpcds
                .iter_v4()
                .filter(|(k, v)| k.collides_with(prefix_v4) && v.is_none_or(|v| v != dst_vpcd))
                .map(|(k, _)| Prefix::IPV4(*k))
                .collect::<Vec<_>>();
            insert_prefix_or_update_duplicates(table, dst_vpcd, prefix, colliding_prefixes);
        }
        Prefix::IPV6(prefix_v6) => {
            let colliding_prefixes = table
                .dst_vpcds
                .iter_v6()
                .filter(|(k, v)| k.collides_with(prefix_v6) && v.is_none_or(|v| v != dst_vpcd))
                .map(|(k, _)| Prefix::IPV6(*k))
                .collect::<Vec<_>>();
            insert_prefix_or_update_duplicates(table, dst_vpcd, prefix, colliding_prefixes);
        }
    }
}

fn process_peering(
    table: &mut VpcDiscriminantTable,
    peering: &Peering,
    vpc_table: &VpcTable,
) -> Result<(), DstVpcdLookupError> {
    let new_peering = collapse_prefixes_peering(peering).map_err(|e| match e {
        ConfigUtilError::SplitPrefixError(prefix) => {
            DstVpcdLookupError::BuildError(prefix.to_string())
        }
    })?;

    // Get VPC discrimminant for remote manifest
    let remote_vpcd = VpcDiscriminant::VNI(
        vpc_table
            .get_vpc_by_vpcid(&new_peering.remote_id)
            .unwrap_or_else(|| unreachable!())
            .vni,
    );

    new_peering.remote.exposes.iter().for_each(|expose| {
        for prefix in expose.public_ips() {
            process_prefix(table, remote_vpcd, prefix);
        }
    });
    Ok(())
}

/// Build the `dst_vni_lookup` configuration from an overlay.
///
/// # Errors
///
/// Returns an error if the configuration cannot be built.
pub fn build_dst_vni_lookup_configuration(
    overlay: &Overlay,
) -> Result<VpcDiscriminantTables, ConfigError> {
    let mut vni_tables = VpcDiscriminantTables::new();
    for vpc in overlay.vpc_table.values() {
        let mut table = VpcDiscriminantTable::new();
        for peering in &vpc.peerings {
            process_peering(&mut table, peering, &overlay.vpc_table)
                .map_err(|e| ConfigError::FailureApply(e.to_string()))?;
        }
        vni_tables
            .tables_by_discriminant
            .insert(VpcDiscriminant::VNI(vpc.vni), table);
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

    fn dst_vpcd_lookup(
        vpcd_tables: &'_ VpcDiscriminantTables,
        vpcd: VpcDiscriminant,
        ip: IpAddr,
    ) -> Option<(Prefix, &'_ Option<VpcDiscriminant>)> {
        vpcd_tables
            .tables_by_discriminant
            .get(&vpcd)
            .unwrap()
            .dst_vpcds
            .lookup(ip)
    }

    fn addr(addr: &str) -> IpAddr {
        addr.parse::<IpAddr>().unwrap()
    }

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
        let (vpcd1, vpcd2) = (VpcDiscriminant::VNI(vni1), VpcDiscriminant::VNI(vni2));
        let result = build_dst_vni_lookup_configuration(&overlay);
        assert!(
            result.is_ok(),
            "Failed to build dst_vni_lookup configuration:\n{:#?}",
            result.err()
        );

        let vpcd_tables = result.unwrap();
        assert_eq!(vpcd_tables.tables_by_discriminant.len(), 2);
        println!(
            "vni_tables: {:?}",
            vpcd_tables
                .tables_by_discriminant
                .get(&vpcd1)
                .unwrap()
                .dst_vpcds
        );

        //////////////////////
        // table for vni 1 (uses second expose block, ensures we look at them all)
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd1, addr("5.5.5.1")),
            Some((Prefix::from("5.5.0.0/17"), &Some(vpcd2)))
        );

        assert_eq!(dst_vpcd_lookup(&vpcd_tables, vpcd1, addr("5.6.0.1")), None);

        // Make sure dst VNI lookup for non-NAT stuff works
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd1, addr("8.0.1.1")),
            Some((Prefix::from("8.0.1.0/24"), &Some(vpcd2)))
        );

        //////////////////////
        // table for vni 2 (uses first expose block, ensures we look at them all)
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd2, addr("2.2.0.1")),
            Some((Prefix::from("2.2.0.0/24"), &Some(vpcd1)))
        );

        assert_eq!(dst_vpcd_lookup(&vpcd_tables, vpcd2, addr("2.2.2.1")), None);
    }

    fn build_overlay_overlap() -> Overlay {
        let mut manifest12 = VpcManifest::new("VPC-1");
        let mut manifest21 = VpcManifest::new("VPC-2");
        let mut manifest23 = VpcManifest::new("VPC-2");
        let mut manifest32 = VpcManifest::new("VPC-3");

        manifest12
            .add_expose(
                VpcExpose::empty()
                    .ip("1.0.0.0/24".into())
                    .as_range("20.0.0.0/24".into())
                    .as_range("21.0.0.0/16".into())
                    .as_range("22.0.0.0/24".into()),
            )
            .unwrap();

        manifest21
            .add_expose(VpcExpose::empty().ip("2.0.0.0/24".into()))
            .unwrap();

        manifest23
            .add_expose(VpcExpose::empty().ip("3.0.0.0/24".into()))
            .unwrap();

        manifest32
            .add_expose(
                VpcExpose::empty()
                    .ip("4.0.0.0/24".into())
                    .as_range("20.0.0.0/24".into()) // Same as manifest12's 20.0.0.0/24
                    .as_range("21.0.0.0/24".into()) // Overlap with manifest12's 21.0.0.0/16
                    .as_range("25.0.0.0/24".into()), // No overlap with manifest12
            )
            .unwrap();

        let peering12 = Peering {
            name: "VPC-1--VPC-2".into(),
            local: manifest12.clone(),
            remote: manifest21.clone(),
            remote_id: "VPC02".try_into().unwrap(),
        };
        let peering21 = Peering {
            name: "VPC-2--VPC-1".into(),
            local: manifest21.clone(),
            remote: manifest12.clone(),
            remote_id: "VPC01".try_into().unwrap(),
        };
        let peering23 = Peering {
            name: "VPC-2--VPC-3".into(),
            local: manifest23.clone(),
            remote: manifest32.clone(),
            remote_id: "VPC03".try_into().unwrap(),
        };
        let peering32 = Peering {
            name: "VPC-3--VPC-2".into(),
            local: manifest32.clone(),
            remote: manifest23.clone(),
            remote_id: "VPC02".try_into().unwrap(),
        };

        let mut vpc_table = VpcTable::new();

        let mut vpc1 = Vpc::new("VPC-1", "VPC01", 100).unwrap();
        vpc1.peerings.push(peering12);
        vpc_table.add(vpc1).unwrap();

        let mut vpc2 = Vpc::new("VPC-2", "VPC02", 200).unwrap();
        vpc2.peerings.push(peering21);
        vpc2.peerings.push(peering23);
        vpc_table.add(vpc2).unwrap();

        let mut vpc3 = Vpc::new("VPC-3", "VPC03", 300).unwrap();
        vpc3.peerings.push(peering32);
        vpc_table.add(vpc3).unwrap();

        Overlay::new(vpc_table, VpcPeeringTable::new())
    }

    #[test]
    fn test_setup_overlap() {
        let overlay = build_overlay_overlap();
        let vpcd_tables = build_dst_vni_lookup_configuration(&overlay).unwrap();
        println!("vpcd_tables: {vpcd_tables:#?}");

        assert_eq!(vpcd_tables.tables_by_discriminant.len(), 3);

        let (vpcd1, vpcd2, vpcd3) = (
            VpcDiscriminant::VNI(Vni::new_checked(100).unwrap()),
            VpcDiscriminant::VNI(Vni::new_checked(200).unwrap()),
            VpcDiscriminant::VNI(Vni::new_checked(300).unwrap()),
        );

        // Check lookup with vpc-1 or vpc-3 as source
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd1, addr("2.0.0.2")),
            Some((Prefix::from("2.0.0.0/24"), &Some(vpcd2)))
        );

        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd3, addr("3.0.0.2")),
            Some((Prefix::from("3.0.0.0/24"), &Some(vpcd2)))
        );

        // Check overlap: same prefixes
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd2, addr("20.0.0.2")),
            Some((Prefix::from("20.0.0.0/24"), &None)) // No destination VPC discriminant
        );

        // Check overlap: different but overlapping prefixes
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd2, addr("21.0.0.2")),
            Some((Prefix::from("21.0.0.0/24"), &None)) // No destination VPC discriminant
        );
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd2, addr("21.0.255.2")),
            Some((Prefix::from("21.0.0.0/16"), &None)) // No destination VPC discriminant
        );

        // Check overlap: overlapping VpcExpose, but prefixes with no overlap
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd2, addr("22.0.0.2")),
            Some((Prefix::from("22.0.0.0/24"), &Some(vpcd1)))
        );
        assert_eq!(
            dst_vpcd_lookup(&vpcd_tables, vpcd2, addr("25.0.0.2")),
            Some((Prefix::from("25.0.0.0/24"), &Some(vpcd3)))
        );
    }
}
