// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tests and sample usage for VpcMap

#[cfg(test)]
mod tests {
    use crate::map::*;
    use crate::*;
    use net::vxlan::Vni;

    /// Sample mapping that maps a discriminant to a string (e.g. Vpc name)
    #[derive(Debug, Clone)]
    pub struct VpcName {
        #[allow(unused)]
        disc: VpcDiscriminant,
        name: String,
    }
    impl VpcName {
        pub fn new(disc: VpcDiscriminant, name: &str) -> Self {
            Self {
                disc,
                name: name.to_string(),
            }
        }
    }

    #[test]
    fn test_vpcmap_vpcname() {
        let mut map: VpcMap<VpcName> = VpcMap::new();
        let disc = VpcDiscriminant::from_vni(Vni::new_checked(3000).unwrap());

        // add entry and look it up
        let entry = VpcName::new(disc, "VPC-1");
        assert_eq!(map.add(disc, entry), Ok(()));
        let query = map.get(disc);
        assert!(query.is_some());
        assert_eq!(query.unwrap().name, "VPC-1");

        // attempt insertion with duplicate discriminant
        let entry = VpcName::new(disc, "VPC-2");
        assert!(
            map.add(disc, entry)
                .is_err_and(|e| e == VpcMapError::EntryExists(disc))
        );

        // lookup entry for non-existent discriminant
        let nonexistent = VpcDiscriminant::from_vni(Vni::new_checked(4000).unwrap());
        assert!(map.get(nonexistent).is_none());

        // deletion
        map.del(disc);
        assert!(map.get(disc).is_none());
    }
}
