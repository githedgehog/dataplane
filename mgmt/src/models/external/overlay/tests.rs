// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration tests and samples

#[cfg(test)]
#[allow(dead_code)]
pub mod test {
    use crate::models::external::ConfigError;
    use crate::models::external::overlay::Overlay;
    use crate::models::external::overlay::VpcIdMap;
    use crate::models::external::overlay::display::VpcDetailed;
    use crate::models::external::overlay::vpc::{Vpc, VpcTable};
    use crate::models::external::overlay::vpcpeering::VpcExpose;
    use crate::models::external::overlay::vpcpeering::VpcManifest;
    use crate::models::external::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};

    use lpm::prefix::{Prefix, PrefixSize};

    /* Build sample manifests for a peering */
    fn build_manifest_vpc1() -> VpcManifest {
        let mut m1 = VpcManifest::new("VPC-1");
        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("10.0.0.0", 25)))
            .ip(Prefix::expect_from(("10.0.2.128", 25)))
            .not(Prefix::expect_from(("10.0.0.13", 32)))
            .not(Prefix::expect_from(("10.0.2.130", 32)))
            .as_range(Prefix::expect_from(("100.64.1.0", 24)))
            .not_as(Prefix::expect_from(("100.64.1.13", 32)))
            .not_as(Prefix::expect_from(("100.64.1.14", 32)));
        m1.add_expose(expose).expect("Should succeed");
        m1
    }
    fn build_manifest_vpc2() -> VpcManifest {
        let mut m2 = VpcManifest::new("VPC-2");
        let expose = VpcExpose::empty()
            .ip(Prefix::expect_from(("10.0.0.0", 24)))
            .as_range(Prefix::expect_from(("100.64.2.0", 24)));

        m2.add_expose(expose).expect("Should succeed");
        m2
    }

    /* build sample peering between VPC-1 and VPC-2 */
    fn build_vpc_peering() -> VpcPeering {
        // build vpc manifests
        let m1 = build_manifest_vpc1();
        let m2 = build_manifest_vpc2();
        // build vpc peering with the manifests
        VpcPeering::new("VPC-1--VPC-2", m1, m2)
    }

    #[test]
    fn test_vpc_checks() {
        let mut vpc_table = VpcTable::new();

        /* invalid vni should be rejected */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 0);
        assert_eq!(vpc1, Err(ConfigError::InvalidVpcVni(0)));

        /* add vpc with valid vni 3000 */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed");
        vpc_table.add(vpc1).expect("Should succeed");

        /* vpc with duplicate name should be rejected */
        let bad = Vpc::new("VPC-1", "BBBBB", 2000).expect("Should succeed");
        assert_eq!(
            vpc_table.add(bad),
            Err(ConfigError::DuplicateVpcName("VPC-1".to_string()))
        );

        /* vpc with colliding VNI should be rejected */
        let bad = Vpc::new("VPC-2", "CCCCC", 3000).expect("Should succeed");
        assert_eq!(vpc_table.add(bad), Err(ConfigError::DuplicateVpcVni(3000)));

        /* vpc with colliding Id should be rejected */
        let bad = Vpc::new("VPC-2", "AAAAA", 9000).expect("Should succeed");
        assert_eq!(
            vpc_table.add(bad),
            Err(ConfigError::DuplicateVpcId("AAAAA".try_into().unwrap()))
        );

        /* vpc with bad Id should not build */
        let bad = Vpc::new("VPC-2", "AAA", 9000);
        assert_eq!(bad, Err(ConfigError::BadVpcId("AAA".to_string())));

        /* vpc with bad Id should not build */
        let bad = Vpc::new("VPC-2", "!1234", 9000);
        assert_eq!(bad, Err(ConfigError::BadVpcId("!1234".to_string())));
    }

    #[test]
    fn test_expose_validate() {
        let expose = VpcExpose::empty();
        assert_eq!(expose.validate(), Ok(()));

        let expose = VpcExpose::empty().ip("10.0.0.0/16".into());
        assert_eq!(expose.validate(), Ok(()));

        // Empty ips but non-empty nots - Currently not supported
        /*
        let expose = VpcExpose::empty().not("10.0.1.0/24".into());
        assert_eq!(expose.validate(), Ok(()));
        */

        // Empty as_range but non-empty not_as - Currently not supported
        /*
        let expose = VpcExpose::empty().not_as("2.0.1.0/24".into());
        assert_eq!(expose.validate(), Ok(()));
        */

        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .as_range("2.0.0.0/16".into());
        assert_eq!(expose.validate(), Ok(()));

        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("10.0.0.0/24".into())
            .as_range("2.0.0.0/16".into())
            .not_as("2.0.0.0/24".into());
        assert_eq!(expose.validate(), Ok(()));

        let expose = VpcExpose::empty()
            .ip("1::/64".into())
            .as_range("2::/64".into());
        assert_eq!(expose.validate(), Ok(()));

        // Empty ips/as_range but non-empty nots/not_as - Currently not supported
        /*
        let expose = VpcExpose::empty()
            .not("10.0.0.0/16".into())
            .not_as("2.0.0.0/16".into());
        assert_eq!(expose.validate(), Ok(()));
        */

        // Incorrect: mixed IP versions
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .ip("1::/64".into())
            .as_range("2.0.0.0/16".into())
            .as_range("2::/64".into());
        assert_eq!(
            expose.validate(),
            Err(ConfigError::InconsistentIpVersion(expose.clone()))
        );

        // Incorrect: mixed IP versions
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .as_range("1::/112".into());
        assert_eq!(
            expose.validate(),
            Err(ConfigError::InconsistentIpVersion(expose.clone()))
        );

        // Incorrect: mixed IP versions
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("1::/120".into())
            .as_range("2.0.0.0/16".into())
            .not_as("2::/120".into());
        assert_eq!(
            expose.validate(),
            Err(ConfigError::InconsistentIpVersion(expose.clone()))
        );

        // Incorrect: prefix overlapping
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .ip("10.0.0.0/17".into())
            .as_range("2.0.0.0/16".into())
            .as_range("3.0.0.0/17".into());
        assert_eq!(
            expose.validate(),
            Err(ConfigError::OverlappingPrefixes(
                "10.0.0.0/16".into(),
                "10.0.0.0/17".into(),
            ))
        );

        // Incorrect: out-of-range exclusion prefix
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("8.0.0.0/24".into())
            .as_range("2.0.0.0/16".into())
            .not_as("2.0.1.0/24".into());
        assert_eq!(
            expose.validate(),
            Err(ConfigError::OutOfRangeExclusionPrefix("8.0.0.0/24".into()))
        );

        // Incorrect: all prefixes excluded
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("10.0.0.0/17".into())
            .not("10.0.128.0/17".into())
            .as_range("2.0.0.0/16".into())
            .not_as("2.0.0.0/17".into())
            .not_as("2.0.128.0/17".into());
        assert_eq!(
            expose.validate(),
            Err(ConfigError::ExcludedAllPrefixes(expose.clone()))
        );

        // Incorrect: mismatched prefix lists sizes
        let expose = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("10.0.1.0/24".into())
            .as_range("2.0.0.0/24".into());
        assert_eq!(
            expose.validate(),
            Err(ConfigError::MismatchedPrefixSizes(
                PrefixSize::U128(65536 - 256),
                PrefixSize::U128(256)
            ))
        );
    }

    #[test]
    fn test_manifest_expose_overlap() {
        let expose1 = VpcExpose::empty()
            .ip("1.0.0.0/16".into()) // expose3 overlaps with this
            .ip("2.0.0.0/16".into())
            .ip("3.0.0.0/16".into())
            .as_range("11.0.0.0/16".into())
            .as_range("12.0.0.0/16".into())
            .as_range("13.0.0.0/16".into());
        let expose2 = VpcExpose::empty()
            .ip("4.0.0.0/16".into())
            .as_range("14.0.0.0/16".into());
        let expose3 = VpcExpose::empty()
            .ip("5.0.0.0/16".into())
            .ip("1.0.1.0/24".into()) // overlaps with expose1.ips
            .as_range("15.0.0.0/16".into())
            .as_range("16.0.0.0/24".into());
        let expose4 = VpcExpose::empty()
            .ip("6.0.0.0/16".into())
            .ip("12.0.2.0/24".into()); // overlaps with expose1.as_range (no as_range for expose4)
        let expose5 = VpcExpose::empty()
            .ip("7.0.0.0/16".into())
            .ip("3.0.3.0/24".into()); // overlaps with expose1.ips (even without as_range)

        let mut manifest = VpcManifest::new("VPC-1");
        manifest.add_expose(expose1).expect("Should succeed");
        manifest.add_expose(expose2).expect("Should succeed");
        assert_eq!(manifest.validate(), Ok(()));

        // Overlap between a manifest's exposes prefixes is not allowed
        let mut invalid_manifest = manifest.clone();
        invalid_manifest
            .add_expose(expose3)
            .expect("Should succeed");
        assert_eq!(
            invalid_manifest.validate(),
            Err(ConfigError::OverlappingPrefixes(
                "1.0.0.0/16".into(),
                "1.0.1.0/24".into()
            ))
        );

        // Overlap between a manifest's exposes prefixes is not allowed (ips / as_range collision)
        let mut invalid_manifest = manifest.clone();
        invalid_manifest
            .add_expose(expose4)
            .expect("Should succeed");
        assert_eq!(
            invalid_manifest.validate(),
            Err(ConfigError::OverlappingPrefixes(
                "12.0.0.0/16".into(),
                "12.0.2.0/24".into()
            ))
        );

        // Overlap between a manifest's exposes prefixes is not allowed (ips / ips collision)
        let mut invalid_manifest = manifest.clone();
        invalid_manifest
            .add_expose(expose5)
            .expect("Should succeed");
        assert_eq!(
            invalid_manifest.validate(),
            Err(ConfigError::OverlappingPrefixes(
                "3.0.0.0/16".into(),
                "3.0.3.0/24".into()
            ))
        );
    }

    #[test]
    fn test_overlay_missing_vpc() {
        /* build VPCs */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed");

        /* build VPC table */
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).expect("Should succeed");

        /* build peering, referring to non-declared VPC VPC-2 */
        let peering = build_vpc_peering();

        /* build VPC pering table and add one peering */
        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering).expect("Should succeed");

        /* build overlay object and validate it */
        let mut overlay = Overlay::new(vpc_table, peering_table);
        assert_eq!(
            overlay.validate(),
            Err(ConfigError::NoSuchVpc("VPC-2".to_owned()))
        );
    }

    #[test]
    fn test_overlay_duplicate_peering() {
        /* build VPCs */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed");
        let vpc2 = Vpc::new("VPC-2", "BBBBB", 4000).expect("Should succeed");

        /* build VPC table */
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).expect("Should succeed");
        vpc_table.add(vpc2).expect("Should succeed");

        /* build peerings */
        let peering1 = build_vpc_peering();
        let mut peering2 = build_vpc_peering();
        peering2.name = "Peering-2".to_owned();

        let name1 = peering1.name.clone();

        assert_eq!(peering1.validate(), Ok(()));
        assert_eq!(peering2.validate(), Ok(()));

        /* build peering table */
        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering1).expect("Should succeed");
        peering_table.add(peering2).expect("Should succeed");

        /* build overlay object and validate it */
        let mut overlay = Overlay::new(vpc_table, peering_table);
        assert_eq!(
            overlay.validate(),
            Err(ConfigError::DuplicateVpcPeerings(name1))
        );
    }

    #[test]
    fn test_overlay() {
        /* build VPCs */
        let vpc1 = Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed");
        let vpc2 = Vpc::new("VPC-2", "BBBBB", 4000).expect("Should succeed");

        /* build peering */
        let peering = build_vpc_peering();

        /* build VPC table */
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).expect("Should succeed");
        vpc_table.add(vpc2).expect("Should succeed");

        /* build VPC pering table and add one peering */
        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering).expect("Should succeed");

        println!("{peering_table}");

        /* build overlay object and validate it */
        let mut overlay = Overlay::new(vpc_table, peering_table);
        assert_eq!(overlay.validate(), Ok(()));
    }

    #[test]
    fn test_peering_iter() {
        let mut peering_table = VpcPeeringTable::new();

        let m1 = VpcManifest::new("VPC-1");
        let m2 = VpcManifest::new("VPC-2");
        let peering = VpcPeering::new("Peering-1", m1, m2);
        peering_table.add(peering).unwrap();

        let m1 = VpcManifest::new("VPC-1");
        let m2 = VpcManifest::new("VPC-3");
        let peering = VpcPeering::new("Peering-2", m1, m2);
        peering_table.add(peering).unwrap();

        let m1 = VpcManifest::new("VPC-2");
        let m2 = VpcManifest::new("VPC-4");
        let peering = VpcPeering::new("Peering-3", m1, m2);
        peering_table.add(peering).unwrap();

        let m1 = VpcManifest::new("VPC-1");
        let m2 = VpcManifest::new("VPC-4");
        let peering = VpcPeering::new("Peering-4", m1, m2);
        peering_table.add(peering).unwrap();

        // all peerings of VPC-1
        let x: Vec<String> = peering_table
            .peerings_vpc("VPC-1")
            .map(|p| p.name.clone())
            .collect();

        assert!(x.contains(&"Peering-1".to_owned()));
        assert!(x.contains(&"Peering-2".to_owned()));
        assert!(x.contains(&"Peering-4".to_owned()));
        assert!(!x.contains(&"Peering-3".to_owned()), "not there");
    }

    #[test]
    fn test_vpc_collect_peerings() {
        fn man_vpc1_with_vpc2() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-1");
            let expose = VpcExpose::empty()
                .ip(Prefix::expect_from(("192.168.50.0", 24)))
                .not(Prefix::expect_from(("192.168.50.13", 32)));
            m1.add_expose(expose).expect("Should succeed");

            let expose = VpcExpose::empty()
                .ip(Prefix::expect_from(("192.168.111.0", 24)))
                .not(Prefix::expect_from(("192.168.111.2", 32)))
                .not(Prefix::expect_from(("192.168.111.254", 32)))
                .as_range(Prefix::expect_from(("100.64.200.0", 24)))
                .not_as(Prefix::expect_from(("100.64.200.12", 31)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc1_with_vpc3() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-1");
            let expose = VpcExpose::empty().ip(Prefix::expect_from(("192.168.60.0", 24)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc1_with_vpc4() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-1");
            let expose = VpcExpose::empty().ip(Prefix::expect_from(("192.168.60.0", 24)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc2() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-2");
            let expose = VpcExpose::empty().ip(Prefix::expect_from(("192.168.80.0", 24)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc2_with_vpc3() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-2");
            let expose = VpcExpose::empty().ip(Prefix::expect_from(("192.168.80.0", 24)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc3() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-3");
            let expose = VpcExpose::empty().ip(Prefix::expect_from(("192.168.128.0", 27)));
            m1.add_expose(expose).expect("Should succeed");
            m1
        }
        fn man_vpc4() -> VpcManifest {
            let mut m1 = VpcManifest::new("VPC-4");
            let expose = VpcExpose::empty()
                .ip(Prefix::expect_from(("192.168.201.1", 32)))
                .ip(Prefix::expect_from(("192.168.202.2", 32)))
                .ip(Prefix::expect_from(("192.168.203.3", 32)));
            m1.add_expose(expose).expect("Should succeed");

            let expose = VpcExpose::empty()
                .ip(Prefix::expect_from(("192.168.204.4", 32)))
                .as_range(Prefix::expect_from(("100.64.204.4", 32)));
            m1.add_expose(expose).expect("Should succeed");

            let expose = VpcExpose::empty()
                .ip(Prefix::expect_from(("192.168.210.0", 29)))
                .not(Prefix::expect_from(("192.168.210.1", 32)));
            m1.add_expose(expose).expect("Should succeed");

            m1
        }

        /* build VPC table with 3 vpcs */
        let mut vpc_table = VpcTable::new();
        let _ = vpc_table.add(Vpc::new("VPC-1", "AAAAA", 3000).expect("Should succeed"));
        let _ = vpc_table.add(Vpc::new("VPC-2", "BBBBB", 4000).expect("Should succeed"));
        let _ = vpc_table.add(Vpc::new("VPC-3", "CCCCC", 2000).expect("Should succeed"));
        let _ = vpc_table.add(Vpc::new("VPC-4", "DDDDD", 6000).expect("Should succeed"));

        /* build peering table with 4 peerings */
        let mut peering_table = VpcPeeringTable::new();
        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-2",
                man_vpc1_with_vpc2(),
                man_vpc2(),
            ))
            .expect("Should succeed");

        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-3",
                man_vpc1_with_vpc3(),
                man_vpc3(),
            ))
            .expect("Should succeed");

        peering_table
            .add(VpcPeering::new(
                "VPC-1--VPC-4",
                man_vpc1_with_vpc4(),
                man_vpc4(),
            ))
            .expect("Should succeed");

        peering_table
            .add(VpcPeering::new(
                "VPC-2--VPC-3",
                man_vpc2_with_vpc3(),
                man_vpc3(),
            ))
            .expect("Should succeed");

        assert_eq!(peering_table.len(), 4);

        /* peering with empty name cannot be added to the table */
        let peering_empty_name = VpcPeering::new("", man_vpc1_with_vpc2(), man_vpc2());
        assert_eq!(
            peering_table.add(peering_empty_name),
            Err(ConfigError::MissingIdentifier("Peering name"))
        );
        assert_eq!(peering_table.len(), 4);

        /* peering with duplicate name cannot be added to the table */
        let peering_duplicate_name =
            VpcPeering::new("VPC-1--VPC-2", man_vpc1_with_vpc2(), man_vpc2());
        assert_eq!(
            peering_table.add(peering_duplicate_name),
            Err(ConfigError::DuplicateVpcPeeringId(
                "VPC-1--VPC-2".to_string()
            ))
        );

        /* make sure erroneous entries were not inserted */
        assert_eq!(peering_table.len(), 4);

        /* display peering table */
        println!("{peering_table}");

        /* collect ids */
        let id_map: VpcIdMap = vpc_table
            .values()
            .map(|vpc| (vpc.name.clone(), vpc.id.clone()))
            .collect();

        /* collect the peerings for each VPC */
        vpc_table.collect_peerings(&peering_table, &id_map);

        /* display VPC table */
        println!("{vpc_table}");

        /* get vpc VPC1 */
        if let Some(vpc) = vpc_table.get_vpc("VPC-1") {
            println!("{}", VpcDetailed(vpc));
        }
    }
}
