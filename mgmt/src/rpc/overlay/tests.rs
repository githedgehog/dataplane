// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: overlay configuration tests and samples

#[cfg(test)]
#[allow(dead_code)]
pub mod test {
    use crate::rpc::overlay::vpc::{Vpc, VpcTable};
    use crate::rpc::overlay::vpcpeering::VpcExpose;
    use crate::rpc::overlay::vpcpeering::VpcExposeManifest;
    use crate::rpc::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};
    use crate::rpc::overlay::Overlay;
    use crate::rpc::ApiError;

    use routing::prefix::Prefix;

    /* Build sample manifests for a peering */
    fn build_manifest_vpc1() -> VpcExposeManifest {
        let mut vpc1 = VpcExposeManifest::new("VPC-1");
        let expose = VpcExpose::empty()
            .ip(Prefix::from(("10.0.0.0", 25)))
            .ip(Prefix::from(("10.0.2.128", 25)))
            .not(Prefix::from(("10.0.1.13", 32)))
            .not(Prefix::from(("10.0.2.130", 32)))
            .as_range(Prefix::from(("100.64.1.0", 24)))
            .not_as(Prefix::from(("100.64.1.13", 32)));
        vpc1.add_expose(expose).expect("Should succeed");
        vpc1
    }
    fn build_manifest_vpc2() -> VpcExposeManifest {
        let mut vpc1 = VpcExposeManifest::new("VPC-2");
        let expose = VpcExpose::empty()
            .ip(Prefix::from(("10.0.0.0", 24)))
            .as_range(Prefix::from(("100.64.2.0", 24)));

        vpc1.add_expose(expose).expect("Should succeed");
        vpc1
    }
    /* build sample peering between VPC-1 and VPC-2 */
    fn build_vpc_peering() -> VpcPeering {
        // build vpc manifests
        let m1 = build_manifest_vpc1();
        let m2 = build_manifest_vpc2();
        // build vpc peering with the manifests
        let mut peering = VpcPeering::new("VPC-1-to-VPC-2");
        peering.set_one(m1);
        peering.set_two(m2);
        peering
    }

    #[test]
    fn test_vpc_checks() {
        let mut vpc_table = VpcTable::new();

        /* invalid vni should be rejected */
        let vpc1 = Vpc::new("VPC-1", 0);
        assert_eq!(vpc1, Err(ApiError::InvalidVpcVni(0)));

        /* add vpc with valid vni 3000 */
        let vpc1 = Vpc::new("VPC-1", 3000).expect("Should succeed");
        vpc_table.add(vpc1).expect("Should succeed");

        /* vpc with duplicate name should be rejected */
        let vpc2 = Vpc::new("VPC-1", 2000).expect("Should succeed");
        assert_eq!(
            vpc_table.add(vpc2),
            Err(ApiError::DuplicateVpcId("VPC-1".to_string()))
        );

        /* vpc with colliding VNI should be rejected */
        let vpc2 = Vpc::new("VPC-2", 3000).expect("Should succeed");
        assert_eq!(vpc_table.add(vpc2), Err(ApiError::DuplicateVpcVni(3000)));
    }

    #[test]
    fn test_vpc_peering_checks() {
        /* must have name */
        let peering = VpcPeering::new("");
        assert_eq!(peering.validate(), Err(ApiError::MissingPeeringName));

        /* VPC data can't me missing */
        let mut peering = VpcPeering::new("Some-peering");
        peering.set_one(build_manifest_vpc1());
        assert_eq!(
            peering.validate(),
            Err(ApiError::IncompletePeeringData("Some-peering".to_owned()))
        );

        let mut peering = VpcPeering::new("Some-peering");
        peering.set_one(build_manifest_vpc1());
        peering.set_two(build_manifest_vpc1());
        assert_eq!(peering.validate(), Ok(()));
    }

    #[test]
    fn test_overlay_missing_vpc() {
        /* build VPCs */
        let vpc1 = Vpc::new("VPC-1", 3000).expect("Should succeed");

        /* build VPC table */
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).expect("Should succeed");

        /* build peering, referring to non-declared VPC VPC-2 */
        let peering = build_vpc_peering();

        /* build VPC pering table and add one peering */
        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering).expect("Should succeed");

        /* build overlay object and validate it */
        let overlay = Overlay::new(vpc_table, peering_table);
        assert_eq!(
            overlay.validate(),
            Err(ApiError::NoSuchVpc("VPC-2".to_owned()))
        );
    }

    #[test]
    fn test_overlay() {
        /* build VPCs */
        let vpc1 = Vpc::new("VPC-1", 3000).expect("Should succeed");
        let vpc2 = Vpc::new("VPC-2", 4000).expect("Should succeed");

        /* build peering */
        let peering = build_vpc_peering();

        /* build VPC table */
        let mut vpc_table = VpcTable::new();
        vpc_table.add(vpc1).expect("Should succeed");
        vpc_table.add(vpc2).expect("Should succeed");

        /* build VPC pering table and add one peering */
        let mut peering_table = VpcPeeringTable::new();
        peering_table.add(peering).expect("Should succeed");

        /* build overlay object and validate it */
        let overlay = Overlay::new(vpc_table, peering_table);
        assert_eq!(overlay.validate(), Ok(()));
        println!("{overlay:#?}");
    }
}
