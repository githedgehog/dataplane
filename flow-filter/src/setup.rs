// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::FlowFilterTable;
use crate::tables::{NatRequirement, RemoteData, VpcdLookupResult};
use config::ConfigError;
use config::external::overlay::Overlay;
use config::external::overlay::vpc::{Peering, Vpc};
use config::external::overlay::vpcpeering::{VpcExpose, VpcExposeNat};
use config::internal::interfaces::interface::InterfaceConfigTable;
use config::utils::{ConfigUtilError, collapse_prefixes_peering};
use net::packet::VpcDiscriminant;

use tracectl::trace_target;
use tracing::debug;
trace_target!("flow-filter-setup", LevelFilter::INFO, &[]);

impl FlowFilterTable {
    /// Build a [`FlowFilterTable`] from an overlay
    pub fn build_from_overlay(overlay: &Overlay) -> Result<Self, ConfigError> {
        let clean_vpc_table = cleanup_vpc_table(overlay.vpc_table.values().collect())?;
        let mut table = FlowFilterTable::new();

        for vpc in &clean_vpc_table {
            for peering in &vpc.peerings {
                table.add_peering(overlay, vpc, peering)?;
            }
        }
        debug!("Flow filter table successfully built: {table:?}");
        Ok(table)
    }

    fn add_peering(
        &mut self,
        overlay: &Overlay,
        vpc: &Vpc,
        peering: &Peering,
    ) -> Result<(), ConfigError> {
        let local_vpcd = VpcDiscriminant::VNI(vpc.vni);
        let dst_vpcd = VpcDiscriminant::VNI(overlay.vpc_table.get_remote_vni(peering));

        for remote_expose in &peering.remote.exposes {
            if remote_expose.default {
                for local_expose in &peering.local.exposes {
                    let dst_data = build_dst_data(dst_vpcd, local_expose, remote_expose);
                    if local_expose.default {
                        // Both the local and remote expose are default exposes
                        self.insert_default_source_to_default_remote(
                            local_vpcd,
                            VpcdLookupResult::Single(dst_data),
                        )?;
                    } else {
                        // Only the remote expose is a default expose
                        for local_prefix in &local_expose.ips {
                            self.insert_default_remote(
                                local_vpcd,
                                VpcdLookupResult::Single(dst_data),
                                local_prefix.prefix(),
                                local_prefix.ports(),
                            )?;
                        }
                    }
                }
            } else {
                for local_expose in &peering.local.exposes {
                    let dst_data = build_dst_data(dst_vpcd, local_expose, remote_expose);
                    if local_expose.default {
                        // Only the local expose is a default expose
                        for remote_prefix in remote_expose.public_ips() {
                            self.insert_default_source(
                                local_vpcd,
                                VpcdLookupResult::Single(dst_data),
                                remote_prefix.prefix(),
                                remote_prefix.ports(),
                            )?;
                        }
                    } else {
                        // No default expose
                        for local_prefix in &local_expose.ips {
                            for remote_prefix in remote_expose.public_ips() {
                                self.insert(
                                    local_vpcd,
                                    VpcdLookupResult::Single(dst_data),
                                    local_prefix.prefix(),
                                    local_prefix.ports(),
                                    remote_prefix.prefix(),
                                    remote_prefix.ports(),
                                )?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn cleanup_vpc_table(vpcs: Vec<&Vpc>) -> Result<Vec<Vpc>, ConfigError> {
    let mut new_set = Vec::new();
    for vpc in vpcs {
        let mut new_vpc = clone_skipping_peerings(vpc);

        for peering in &vpc.peerings {
            // "Collapse" prefixes to get rid of exclusion prefixes
            let collapsed_peering = collapse_prefixes_peering(peering).map_err(|e| match e {
                ConfigUtilError::SplitPrefixError(prefix) => {
                    ConfigError::FailureApply(format!("Failed to split prefix: {prefix}"))
                }
            })?;
            new_vpc.peerings.push(collapsed_peering);
        }
        new_set.push(new_vpc);
    }
    Ok(new_set)
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

fn build_dst_data(
    dst_vpcd: VpcDiscriminant,
    local_expose: &VpcExpose,
    remote_expose: &VpcExpose,
) -> RemoteData {
    RemoteData::new(
        dst_vpcd,
        get_nat_requirement(&local_expose.nat),
        get_nat_requirement(&remote_expose.nat),
    )
}

fn get_nat_requirement(nat_opt: &Option<VpcExposeNat>) -> Option<NatRequirement> {
    let nat = nat_opt.as_ref()?;
    debug_assert!(!(nat.is_stateful() && nat.is_stateless())); // Only one NAT mode allowed

    if nat.is_stateful() {
        Some(NatRequirement::Stateful)
    } else if nat.is_stateless() {
        Some(NatRequirement::Stateless)
    } else {
        unreachable!("Unknown NAT mode")
    }
}

#[cfg(test)]
mod tests {
    use crate::tables::VpcdLookupResult;

    use super::*;
    use config::external::overlay::vpc::{Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest, VpcPeeringTable};
    use net::packet::VpcDiscriminant;
    use net::vxlan::Vni;

    #[test]
    fn test_add_peering() {
        let mut vpc_table = VpcTable::new();

        let vni1 = Vni::new_checked(100).unwrap();
        let vni2 = Vni::new_checked(200).unwrap();

        let mut vpc1 = Vpc::new("vpc1", "VPC01", vni1.as_u32()).unwrap();
        let vpc2 = Vpc::new("vpc2", "VPC02", vni2.as_u32()).unwrap();

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
            gwgroup: None,
        });

        vpc_table.add(vpc1.clone()).unwrap();
        vpc_table.add(vpc2).unwrap();

        let overlay = Overlay {
            vpc_table,
            peering_table: VpcPeeringTable::new(),
        };

        let mut table = FlowFilterTable::new();
        table
            .add_peering(&overlay, &vpc1, &vpc1.peerings[0])
            .unwrap();

        let src_vpcd = VpcDiscriminant::VNI(vni1);
        let src_addr = "10.0.0.5".parse().unwrap();
        let dst_addr = "20.0.0.5".parse().unwrap();

        let dst_data = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_data,
            Some(VpcdLookupResult::Single(RemoteData::new(
                VpcDiscriminant::VNI(vni2),
                None,
                None
            )))
        );
    }

    #[test]
    fn test_cleanup_vpc_table() {
        let mut vpc = Vpc::new("test-vpc", "VPC01", 100).unwrap();

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
            gwgroup: None,
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
            gwgroup: None,
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

        let dst_data = table.lookup(src_vpcd, &src_addr, &dst_addr, None);
        assert_eq!(
            dst_data,
            Some(VpcdLookupResult::Single(RemoteData::new(
                VpcDiscriminant::VNI(vni2),
                None,
                None
            )))
        );
    }
}
