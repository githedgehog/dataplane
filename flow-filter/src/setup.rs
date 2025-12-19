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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VpcdLookupResult;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeeringTable};
    use lpm::prefix::{PortRange, Prefix, PrefixWithPortsSize};
    use net::vxlan::Vni;
    use std::collections::BTreeSet;
    use std::ops::Bound;

    #[test]
    fn test_split_overlapping_basic() {
        // Test splitting 10.0.0.0/16 with mask 10.0.1.0/24
        let prefix_to_split = PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/16"), None);
        let mask_prefix = PrefixWithOptionalPorts::new(Prefix::from("10.0.1.0/24"), None);

        let result: BTreeSet<_> = split_overlapping(prefix_to_split, mask_prefix)
            .into_iter()
            .collect();

        // Should produce the intersection (10.0.1.0/24) and the remainder parts
        assert!(!result.is_empty());

        // Verify that one of the results is the intersection
        assert!(result.contains(&mask_prefix));

        // Verify all results together are the same size as the original prefix
        let total_ips = result
            .iter()
            .fold(PrefixWithPortsSize::from(0u8), |sum, prefix| {
                sum + prefix.size()
            });
        let original_ips = prefix_to_split.size();
        assert_eq!(total_ips, original_ips);

        // Verify all results are within the original prefix
        for prefix in &result {
            assert!(prefix_to_split.covers(prefix));
        }

        // Verify results do not overlap
        for i in &result.clone() {
            for j in result.range((Bound::Excluded(i), Bound::Unbounded)) {
                assert!(!i.overlaps(j));
            }
        }

        // Just to be on the safe side for this test, check the list manually
        let expected = BTreeSet::from([
            PrefixWithOptionalPorts::new(Prefix::from("10.0.128.0/17"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.64.0/18"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.32.0/19"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.16.0/20"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.8.0/21"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.4.0/22"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.3.0/23"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.1.0/24"), None),
            PrefixWithOptionalPorts::new(Prefix::from("10.0.0.0/24"), None),
        ]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_split_overlapping_with_ports() {
        // Test splitting with port ranges
        let port_range1 = PortRange::new(80, 443).unwrap();
        let port_range2 = PortRange::new(100, 200).unwrap();

        let prefix_to_split =
            PrefixWithOptionalPorts::new(Prefix::from("192.168.0.0/16"), Some(port_range1));
        let mask_prefix =
            PrefixWithOptionalPorts::new(Prefix::from("192.168.1.0/24"), Some(port_range2));

        let result: BTreeSet<_> = split_overlapping(prefix_to_split, mask_prefix)
            .into_iter()
            .collect();

        // Should produce multiple prefixes including the intersection
        assert!(!result.is_empty());

        // The intersection should have the intersection of both IP prefix and port range
        let intersection = prefix_to_split.intersection(&mask_prefix).unwrap();
        assert!(result.contains(&intersection));

        // Check the list manually
        let expected = BTreeSet::from([
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.0.0/16"),
                Some(PortRange::new(80, 99).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.0.0/16"),
                Some(PortRange::new(201, 443).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.128.0/17"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.64.0/18"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.32.0/19"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.16.0/20"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.8.0/21"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.4.0/22"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.3.0/23"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.1.0/24"),
                Some(PortRange::new(100, 200).unwrap()), // Corresponds to the mask
            ),
            PrefixWithOptionalPorts::new(
                Prefix::from("192.168.0.0/24"),
                Some(PortRange::new(100, 200).unwrap()),
            ),
        ]);
        assert_eq!(result, expected, "{result:#?},\n {expected:#?}");
    }

    #[test]
    fn test_split_overlaps_in_src_prefixes_no_overlap() {
        // Create a VPC with non-overlapping peerings
        let mut vpc = Vpc::new("test-vpc", "VPC01", 100).unwrap();

        let manifest1 = VpcManifest {
            name: "remote1".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };
        let manifest2 = VpcManifest {
            name: "remote2".to_string(),
            exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
        };

        vpc.peerings.push(Peering {
            name: "peering1".to_string(),
            local: VpcManifest {
                name: "local1".to_string(),
                exposes: vec![VpcExpose::empty().ip("192.168.1.0/24".into())],
            },
            remote: manifest1,
            remote_id: "VPC02".try_into().unwrap(),
        });

        vpc.peerings.push(Peering {
            name: "peering2".to_string(),
            local: VpcManifest {
                name: "local2".to_string(),
                exposes: vec![VpcExpose::empty().ip("192.168.2.0/24".into())],
            },
            remote: manifest2,
            remote_id: "VPC02".try_into().unwrap(),
        });

        let mut expected = vpc.clone();
        expected.peerings.sort_by_key(|p| p.name.clone());

        let mut result = split_overlaps_in_src_prefixes(&mut vpc);
        result.peerings.sort_by_key(|p| p.name.clone());

        // No overlaps, so peerings should remain the same
        assert_eq!(result, expected);
    }

    #[test]
    fn test_split_overlaps_in_src_prefixes_with_overlap() {
        // Create a VPC with overlapping peerings
        let mut vpc = Vpc::new("test-vpc", "VPC01", 100).unwrap();

        let manifest1 = VpcManifest {
            name: "remote1".to_string(),
            exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
        };
        let manifest2 = VpcManifest {
            name: "remote2".to_string(),
            exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
        };

        // These two local prefixes overlap: 192.168.0.0/16 contains 192.168.1.0/24
        vpc.peerings.push(Peering {
            name: "peering1".to_string(),
            local: VpcManifest {
                name: "local1".to_string(),
                exposes: vec![VpcExpose::empty().ip("192.168.0.0/16".into())],
            },
            remote: manifest1,
            remote_id: "VPC02".try_into().unwrap(),
        });

        vpc.peerings.push(Peering {
            name: "peering2".to_string(),
            local: VpcManifest {
                name: "local2".to_string(),
                exposes: vec![VpcExpose::empty().ip("192.168.1.0/24".into())],
            },
            remote: manifest2,
            remote_id: "VPC02".try_into().unwrap(),
        });

        let mut result = split_overlaps_in_src_prefixes(&mut vpc);
        assert_eq!(result.peerings.len(), 2);
        result.peerings.sort_by_key(|p| p.name.clone());

        // The broader prefix (192.168.0.0/16) should be split into multiple parts
        // to avoid overlap with the more specific prefix (192.168.1.0/24)
        let peering1_prefixes = &result.peerings[0].local.exposes[0].ips;

        let expected = BTreeSet::from([
            PrefixWithOptionalPorts::new(Prefix::from("192.168.128.0/17"), None),
            PrefixWithOptionalPorts::new(Prefix::from("192.168.64.0/18"), None),
            PrefixWithOptionalPorts::new(Prefix::from("192.168.32.0/19"), None),
            PrefixWithOptionalPorts::new(Prefix::from("192.168.16.0/20"), None),
            PrefixWithOptionalPorts::new(Prefix::from("192.168.8.0/21"), None),
            PrefixWithOptionalPorts::new(Prefix::from("192.168.4.0/22"), None),
            PrefixWithOptionalPorts::new(Prefix::from("192.168.2.0/23"), None),
            PrefixWithOptionalPorts::new(Prefix::from("192.168.1.0/24"), None),
            PrefixWithOptionalPorts::new(Prefix::from("192.168.0.0/24"), None),
        ]);
        assert_eq!(peering1_prefixes, &expected);

        let peering2_prefixes = &result.peerings[1].local.exposes[0].ips;
        let expected = BTreeSet::from([PrefixWithOptionalPorts::new(
            Prefix::from("192.168.1.0/24"),
            None,
        )]);
        assert_eq!(peering2_prefixes, &expected);
    }

    #[test]
    fn test_clone_skipping_peerings() {
        let mut vpc = Vpc::new("test-vpc", "VPC01", 100).unwrap();

        vpc.peerings.push(Peering {
            name: "peering1".to_string(),
            local: VpcManifest {
                name: "local1".to_string(),
                exposes: vec![],
            },
            remote: VpcManifest {
                name: "remote1".to_string(),
                exposes: vec![],
            },
            remote_id: "VPC02".try_into().unwrap(),
        });

        let cloned = clone_skipping_peerings(&vpc);

        assert_eq!(cloned.name, vpc.name);
        assert_eq!(cloned.id, vpc.id);
        assert_eq!(cloned.vni, vpc.vni);
        assert_eq!(cloned.peerings.len(), 0);
    }

    #[test]
    fn test_cleanup_vpc_table() {
        let mut vpc = Vpc::new("test-vpc", "VPC01", 100).unwrap();

        // Add a peering with some exposes
        vpc.peerings.push(Peering {
            name: "peering1".to_string(),
            local: VpcManifest {
                name: "local1".to_string(),
                exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
            },
            remote: VpcManifest {
                name: "remote1".to_string(),
                exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
            },
            remote_id: "VPC02".try_into().unwrap(),
        });

        let vpcs = vec![&vpc];
        let result = cleanup_vpc_table(vpcs);

        assert!(result.is_ok());
        let cleaned_vpcs = result.unwrap();
        assert_eq!(cleaned_vpcs.len(), 1);
        assert_eq!(cleaned_vpcs[0].name, vpc.name);
    }

    #[test]
    fn test_build_from_overlay() {
        // Create a simple overlay with two VPCs and a peering
        let mut vpc_table = VpcTable::new();

        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();

        let mut vpc1 = Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap();
        let vpc2 = Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap();

        // Add peering from vpc1 to vpc2
        vpc1.peerings.push(Peering {
            name: "vpc1-to-vpc2".to_string(),
            local: VpcManifest {
                name: "vpc1-local".to_string(),
                exposes: vec![VpcExpose::empty().ip("10.0.0.0/24".into())],
            },
            remote: VpcManifest {
                name: "vpc2-remote".to_string(),
                exposes: vec![VpcExpose::empty().ip("20.0.0.0/24".into())],
            },
            remote_id: "VPC02".try_into().unwrap(),
        });

        vpc_table.add(vpc1).unwrap();
        vpc_table.add(vpc2).unwrap();

        let overlay = Overlay {
            vpc_table,
            peering_table: VpcPeeringTable::new(),
        };

        let result = FlowFilterTable::build_from_overlay(&overlay);
        assert!(result.is_ok());

        let table = result.unwrap();
        // Should be able to look up flows
        let src_vpcd = VpcDiscriminant::VNI(vni1);
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.5".parse().unwrap();

        let (allowed, dst_vpcd) = table.contains(src_vpcd, &src_addr, &dst_addr, None);
        assert!(allowed);
        assert_eq!(dst_vpcd, VpcdLookupResult::Some(VpcDiscriminant::VNI(vni2)));
    }
}
