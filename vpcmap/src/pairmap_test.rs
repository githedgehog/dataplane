// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tests and sample usage for VpcPairMap

#[cfg(test)]
mod tests {
    use crate::pairmap::*;
    use crate::*;
    use net::vxlan::Vni;
    use std::{net::IpAddr, str::FromStr};

    // sample data related to a VPC
    #[derive(Debug, Clone, PartialEq)]
    struct VpcData {
        disc: VpcDiscriminant,
        name: String,
        address: IpAddr,
    }
    impl VpcData {
        fn new(disc: VpcDiscriminant, name: &str, addr: &str) -> Self {
            Self {
                disc,
                name: name.to_owned(),
                address: IpAddr::from_str(addr).unwrap(),
            }
        }
    }

    // sample data related to a pair of VPCs
    #[derive(Debug, Clone, PartialEq)]
    struct VpcPairSample {
        east: VpcData,
        west: VpcData,
    }
    impl VpcPairSample {
        fn new(east: VpcData, west: VpcData) -> Self {
            Self { east, west }
        }
    }

    // implement `VpcPair` trait
    impl VpcPair for VpcPairSample {
        type SidedData = VpcData;
        fn get_east_data(&self) -> &Self::SidedData {
            &self.east
        }
        fn get_west_data(&self) -> &Self::SidedData {
            &self.west
        }
        fn get_east_disc(&self) -> VpcDiscriminant {
            self.east.disc
        }
        fn get_west_disc(&self) -> VpcDiscriminant {
            self.west.disc
        }
    }

    #[test]
    fn test_vpc_pair_map_sided() {
        let mut map: VpcPairMap<VpcPairSample> = VpcPairMap::new();

        // create two discriminants
        let disc1 = VpcDiscriminant::from_vni(Vni::new_checked(3000).unwrap());
        let disc2 = VpcDiscriminant::from_vni(Vni::new_checked(4000).unwrap());

        // create two vpc data
        let vpc1 = VpcData::new(disc1, "VPC-1", "192.168.10.1");
        let vpc2 = VpcData::new(disc2, "VPC-2", "192.168.20.2");

        // create the pair object and add it to map
        let pair = VpcPairSample::new(vpc1, vpc2);
        map.add(pair);

        // retrieve
        let lookup1 = map.get(disc1, disc2).expect("Should be found");
        let lookup2 = map.get(disc2, disc1).expect("Should be found");
        assert_eq!(lookup1, lookup2, "Should get the same object");

        // ordered lookup
        let (first, second) = map.ordered_get(disc1, disc2).expect("Should be found");
        assert_eq!(first.name, "VPC-1");
        assert_eq!(second.name, "VPC-2");

        let (first, second) = map.ordered_get(disc2, disc1).expect("Should be found");
        assert_eq!(first.name, "VPC-2");
        assert_eq!(second.name, "VPC-1");
    }

    /// Sample usage of data struct that does not require directionality
    #[derive(Debug, Clone, PartialEq)]
    struct VpcPairNonSided {
        disc1: VpcDiscriminant,
        disc2: VpcDiscriminant,
        data: String,
    }
    impl VpcPairNonSided {
        fn new(disc1: VpcDiscriminant, disc2: VpcDiscriminant, data: &str) -> Self {
            Self {
                disc1,
                disc2,
                data: data.to_string(),
            }
        }
    }
    impl VpcPair for VpcPairNonSided {
        type SidedData = Self;
        fn get_east_data(&self) -> &Self::SidedData {
            self
        }
        fn get_west_data(&self) -> &Self::SidedData {
            self
        }
        fn get_east_disc(&self) -> VpcDiscriminant {
            self.disc1
        }
        fn get_west_disc(&self) -> VpcDiscriminant {
            self.disc2
        }
    }

    #[test]
    fn test_vpc_pair_map_non_sided() {
        let mut map: VpcPairMap<VpcPairNonSided> = VpcPairMap::new();
        let some_data = "SOME DATA";

        // create two discriminants
        let disc1 = VpcDiscriminant::from_vni(Vni::new_checked(3000).unwrap());
        let disc2 = VpcDiscriminant::from_vni(Vni::new_checked(4000).unwrap());

        // create the pair object and add it to map
        let pair = VpcPairNonSided::new(disc1, disc2, some_data);
        map.add(pair);

        // retrieve
        let lookup1 = map.get(disc1, disc2).expect("Should be found");
        let lookup2 = map.get(disc2, disc1).expect("Should be found");
        assert_eq!(lookup1, lookup2, "Should get the same object");

        // ordered lookup
        let (first, second) = map.ordered_get(disc1, disc2).expect("Should be found");
        assert_eq!(first.data, some_data);
        assert_eq!(second.data, some_data);
    }
}
