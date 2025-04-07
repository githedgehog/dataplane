// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane gRPC handling module.
//! Implements gRPC request reception and response building.

use config::*;
use serde_yml;

mod config;

#[allow(dead_code)]
fn load_yaml_gwc() -> Result<GatewayConfig, Box<dyn std::error::Error>> {
    const YAML_FILE: &str = "src/grpc/gwc.yml";

    let yaml_from_file = std::fs::read_to_string(YAML_FILE)?;
    let gwc = serde_yml::from_str(&yaml_from_file)?;
    Ok(gwc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_config() -> GatewayConfig {
        GatewayConfig {
            generation: 1,
            devices: vec![
                Device {
                    index: 0,
                    ipaddr: "192.168.1.1".to_string(),
                    name: "device1".to_string(),
                    pciaddr: "0000:00:01.0".to_string(),
                    r#type: IfType::Vxlan as i32,
                },
                Device {
                    index: 1,
                    ipaddr: "192.168.1.2".to_string(),
                    name: "device2".to_string(),
                    pciaddr: "0000:00:02.0".to_string(),
                    r#type: IfType::Vxlan as i32,
                },
            ],
            peerings: vec![Peering {
                name: "peering1".to_string(),
                entries: {
                    let mut entries_map = HashMap::new();
                    entries_map.insert(
                        "vpc1.1".to_string(),
                        PeeringEntry {
                            r#as: vec![PeeringAs {
                                cidr: "10.1.1.0/24".to_string(),
                                not: "10.1.1.4/30".to_string(),
                            }],
                            ips: vec![PeeringIPs {
                                cidr: "192.168.1.0/24".to_string(),
                                not: "192.168.1.4/30".to_string(),
                            }],
                        },
                    );
                    entries_map.insert(
                        "vpc2.1".to_string(),
                        PeeringEntry {
                            r#as: vec![PeeringAs {
                                cidr: "10.2.1.0/24".to_string(),
                                not: "10.2.1.4/30".to_string(),
                            }],
                            ips: vec![PeeringIPs {
                                cidr: "192.168.2.0/24".to_string(),
                                not: "192.168.2.4/30".to_string(),
                            }],
                        },
                    );
                    entries_map
                },
            }],
            vrfs: vec![
                Vrf {
                    name: "vrf1".to_string(),
                    router: Some(RouterConfig {
                        asn: "65000".to_string(),
                        router_id: "10.1.0.1".to_string(),
                        neighbors: vec![BgpNeighbor {
                            address: "10.1.0.2".to_string(),
                            remote_asn: "65001".to_string(),
                            address_families: vec!["ipv4".to_string(), "l2vpn".to_string()],
                        }],
                        options: vec![BgpAddressFamilyOptions {
                            redistribute_connected: true,
                            redistribute_static: false,
                            send_community: true,
                            advertise_all_vni: true,
                            ipv4_enable: true,
                            l2vpn_enable: true,
                        }],
                        route_maps: vec![RouteMap {
                            name: "route-map1.1".to_string(),
                            match_prefix_lists: vec!["prefix-list1.1".to_string()],
                            action: "permit".to_string(),
                            sequence: 10,
                        }],
                    }),
                    vpc: Some(Vpc {
                        id: "vpc-011".to_string(),
                        name: "vpc1.1".to_string(),
                        vni: "10001".to_string(),
                        subnets: vec![
                            Subnet {
                                cidr: "10.1.1.0/24".to_string(),
                                name: "subnet1.1".to_string(),
                            },
                            Subnet {
                                cidr: "10.1.2.0/24".to_string(),
                                name: "subnet1.2".to_string(),
                            },
                        ],
                    }),
                },
                Vrf {
                    name: "vrf2".to_string(),
                    router: Some(RouterConfig {
                        asn: "75000".to_string(),
                        router_id: "10.2.0.1".to_string(),
                        neighbors: vec![BgpNeighbor {
                            address: "10.2.0.2".to_string(),
                            remote_asn: "75001".to_string(),
                            address_families: vec!["ipv4".to_string(), "l2vpn".to_string()],
                        }],
                        options: vec![BgpAddressFamilyOptions {
                            redistribute_connected: true,
                            redistribute_static: false,
                            send_community: true,
                            advertise_all_vni: true,
                            ipv4_enable: true,
                            l2vpn_enable: true,
                        }],
                        route_maps: vec![RouteMap {
                            name: "route-map2.1".to_string(),
                            match_prefix_lists: vec!["prefix-list2.1".to_string()],
                            action: "permit".to_string(),
                            sequence: 10,
                        }],
                    }),
                    vpc: Some(Vpc {
                        id: "vpc-021".to_string(),
                        name: "vpc2.1".to_string(),
                        vni: "20001".to_string(),
                        subnets: vec![
                            Subnet {
                                cidr: "10.2.1.0/24".to_string(),
                                name: "subnet2.1".to_string(),
                            },
                            Subnet {
                                cidr: "10.2.2.0/24".to_string(),
                                name: "subnet2.2".to_string(),
                            },
                        ],
                    }),
                },
            ],
        }
    }

    #[test]
    fn test_load_yaml_gwc() {
        let gwc = sample_config();
        let gwc_from_yaml = load_yaml_gwc().expect("Failed to load YAML config");
        assert_eq!(gwc, gwc_from_yaml);
    }
}
