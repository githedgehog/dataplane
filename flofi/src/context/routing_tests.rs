// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use std::panic;

use super::FlofiContext;
use config::external::overlay::vpc::{Vpc, VpcTable};
use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeering, VpcPeeringTable};
use config::external::overlay::{Overlay, ValidatedOverlay};
use net::vxlan::Vni;

fn build_overlay() -> ValidatedOverlay {
    let vni1 = Vni::new_checked(100).unwrap();
    let vni2 = Vni::new_checked(200).unwrap();
    let vni3 = Vni::new_checked(300).unwrap();

    let mut vpc_table = VpcTable::new();
    vpc_table
        .add(Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap())
        .unwrap();
    vpc_table
        .add(Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap())
        .unwrap();
    vpc_table
        .add(Vpc::new("vpc3", "VPC03", vni3.as_u32()).unwrap())
        .unwrap();

    let mut peering_table = VpcPeeringTable::new();
    peering_table
        .add(VpcPeering::with_default_group(
            "vpc1-to-vpc2",
            VpcManifest::with_exposes("vpc1", vec![VpcExpose::empty().ip("1.0.0.0/24".into())]),
            VpcManifest::with_exposes(
                "vpc2",
                vec![
                    VpcExpose::empty().ip("5.0.0.0/24".into()),
                    VpcExpose::empty().set_default(),
                ],
            ),
        ))
        .unwrap();

    peering_table
        .add(VpcPeering::with_default_group(
            "vpc1-to-vpc3",
            VpcManifest::with_exposes(
                "vpc1",
                vec![
                    VpcExpose::empty().ip("1.0.0.0/24".into()),
                    VpcExpose::empty().ip("2.0.0.0/24".into()),
                ],
            ),
            VpcManifest::with_exposes("vpc3", vec![VpcExpose::empty().ip("6.0.0.0/24".into())]),
        ))
        .unwrap();

    Overlay::new(vpc_table, peering_table).validate().unwrap()
}

#[test]
fn build_context() {
    let overlay = build_overlay();
    let context = FlofiContext::try_from(&overlay).unwrap();
    println!("{}", context.routes);
    panic!("Context built successfully");
}
