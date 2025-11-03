// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)] // Do not want to remove pub methods yet

mod bgp;
mod device;
mod expose;
mod gateway_config;
mod interface;
mod overlay;
mod peering;
mod status;
mod tracecfg;
mod underlay;
mod vpc;
mod vrf;

pub use bgp::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use device::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use expose::*;
pub use gateway_config::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use interface::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use overlay::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use peering::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use status::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use tracecfg::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use underlay::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use vpc::*;
#[allow(unused)] // Remove if we do anything but implement traits
pub use vrf::*;

#[cfg(test)]
mod test {
    use gateway_config::GatewayConfig;
    use gateway_config::config::TracingConfig as ApiTracingConfig;
    use pretty_assertions::assert_eq;

    use crate::converters::grpc::convert_gateway_config_from_grpc_with_defaults;
    use crate::converters::grpc::{
        convert_dataplane_status_from_grpc, convert_dataplane_status_to_grpc,
    };
    use crate::internal::device::DeviceConfig;
    use crate::internal::interfaces::interface::InterfaceConfig;

    fn normalize_order(config: &GatewayConfig) -> GatewayConfig {
        let mut config = config.clone();
        if let Some(overlay) = &mut config.overlay {
            overlay.vpcs.sort_by_key(|vpc| vpc.name.clone());
            overlay.vpcs.iter_mut().for_each(|vpc| {
                vpc.interfaces.sort_by_key(|iface| iface.name.clone());
                vpc.interfaces.iter_mut().for_each(|iface| {
                    iface.ipaddrs.sort_by_key(String::clone);
                });
            });
            overlay.peerings.sort_by_key(|peering| peering.name.clone());
            overlay.peerings.iter_mut().for_each(|peering| {
                peering.r#for.iter_mut().for_each(|peering_config| {
                    peering_config.expose.iter_mut().for_each(|expose| {
                        expose.ips.sort_by_key(|pip| format!("{pip:?}"));
                        expose
                            .r#as
                            .sort_by_key(|as_config| format!("{as_config:?}"));
                    });
                });
            });
        }

        if let Some(underlay) = &mut config.underlay {
            underlay.vrfs.sort_by_key(|vrf| vrf.name.clone());
            underlay.vrfs.iter_mut().for_each(|vrf| {
                vrf.interfaces.sort_by_key(|iface| iface.name.clone());
                vrf.interfaces.iter_mut().for_each(|iface| {
                    iface.ipaddrs.sort_by_key(String::clone);
                });
                if let Some(router) = &mut vrf.router {
                    router.neighbors.iter_mut().for_each(|neighbor| {
                        neighbor.af_activate.sort_by_key(|af| *af);
                    });
                }
            });
        }

        config
    }

    #[test]
    fn test_bolero_gateway_config_to_external() {
        bolero::check!()
            .with_type::<GatewayConfig>()
            .for_each(|config| {
                let external = convert_gateway_config_from_grpc_with_defaults(config).unwrap();
                let reserialized = gateway_config::GatewayConfig::try_from(&external).unwrap();
                assert_eq!(normalize_order(config), normalize_order(&reserialized));
            });
    }

    // Helper function to create a test ApiTracingConfig
    fn create_tracing_config() -> ApiTracingConfig {
        ApiTracingConfig {
            default: 4,
            taglevel: [
                ("tag0".to_string(), 0),
                ("tag1".to_string(), 1),
                ("tag2".to_string(), 2),
                ("tag3".to_string(), 3),
                ("tag4".to_string(), 4),
            ]
            .iter()
            .cloned()
            .collect(),
        }
    }

    // Helper function to create a test GatewayConfig
    #[allow(clippy::too_many_lines)]
    fn create_test_gateway_config() -> GatewayConfig {
        // Create device
        let device = gateway_config::Device {
            driver: 0, // Kernel
            hostname: "test-gateway".to_string(),
            ports: Vec::new(),
            eal: None,
            tracing: Some(create_tracing_config()),
        };

        // Create interfaces for VRF
        let eth0 = gateway_config::Interface {
            name: "eth0".to_string(),
            ipaddrs: vec!["192.168.1.1/24".to_string(), "192.168.2.1/24".to_string()],
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("00:11:22:33:44:55".to_string()),
            system_name: None,
            ospf: None,
            mtu: Some(1500),
            pci: Some("0000:02:00.1".to_string()),
        };

        let lo0 = gateway_config::Interface {
            name: "lo0".to_string(),
            ipaddrs: vec!["10.0.0.1/32".to_string()],
            r#type: 2, // Loopback
            role: 0,   // Fabric
            vlan: None,
            macaddr: None,
            system_name: None,
            ospf: None,
            mtu: None,
            pci: None,
        };

        // Create BGP neighbor
        let bgp_neighbor = gateway_config::BgpNeighbor {
            address: "192.168.1.2".to_string(),
            remote_asn: "65002".to_string(),
            af_activate: vec![0, 2], // IPv4 Unicast and L2VPN EVPN
            update_source: Some(gateway_config::config::BgpNeighborUpdateSource {
                source: Some(
                    gateway_config::config::bgp_neighbor_update_source::Source::Address(
                        "192.168.1.2".to_string(),
                    ),
                ),
            }),
        };

        // Create BGP router config
        let router_config = gateway_config::RouterConfig {
            asn: "65001".to_string(),
            router_id: "10.0.0.1".to_string(),
            neighbors: vec![bgp_neighbor],
            ipv4_unicast: Some(gateway_config::BgpAddressFamilyIPv4 {
                redistribute_connected: true,
                redistribute_static: false,
                networks: vec!["192.168.1.0/24".to_string()],
            }),
            ipv6_unicast: None,
            l2vpn_evpn: Some(gateway_config::BgpAddressFamilyL2vpnEvpn {
                advertise_all_vni: true,
            }),
            route_maps: Vec::new(),
        };

        // Create VRF
        let vrf = gateway_config::Vrf {
            name: "default".to_string(),
            interfaces: vec![eth0, lo0],
            router: Some(router_config),
            ospf: None,
        };

        // Create Underlay
        let underlay = gateway_config::Underlay { vrfs: vec![vrf] };

        // Create interfaces for VPCs
        let vpc1_if1 = gateway_config::Interface {
            name: "vpc1_if1".to_string(),
            ipaddrs: vec!["10.1.1.1/24".to_string()],
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: None,
            system_name: None,
            ospf: None,
            mtu: None,
            pci: Some("0000:02:00.1".to_string()),
        };

        let vpc2_if1 = gateway_config::Interface {
            name: "vpc2_if1".to_string(),
            ipaddrs: vec!["10.2.1.1/24".to_string()],
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: None,
            system_name: None,
            ospf: None,
            mtu: None,
            pci: Some("0000:02:00.1".to_string()),
        };

        // Create VPCs
        let vpc1 = gateway_config::Vpc {
            name: "vpc-1".to_string(),
            id: "0x202".to_string(),
            vni: 1001,
            interfaces: vec![vpc1_if1],
        };

        let vpc2 = gateway_config::Vpc {
            name: "vpc-2".to_string(),
            id: "2x122".to_string(),
            vni: 1002,
            interfaces: vec![vpc2_if1],
        };

        // Create PeeringIPs for expose rules
        let include_ip = gateway_config::PeeringIPs {
            rule: Some(gateway_config::config::peering_i_ps::Rule::Cidr(
                "10.1.0.0/16".to_string(),
            )),
        };

        let exclude_ip = gateway_config::PeeringIPs {
            rule: Some(gateway_config::config::peering_i_ps::Rule::Not(
                "10.1.2.0/24".to_string(),
            )),
        };

        // Create PeeringAs for expose rules
        let include_as = gateway_config::PeeringAs {
            rule: Some(gateway_config::config::peering_as::Rule::Cidr(
                "192.168.0.0/16".to_string(),
            )),
        };

        let exclude_as = gateway_config::PeeringAs {
            rule: Some(gateway_config::config::peering_as::Rule::Not(
                "192.168.2.0/24".to_string(),
            )),
        };

        // Create Expose rules
        let vpc1_expose = gateway_config::Expose {
            ips: vec![include_ip],
            r#as: vec![include_as],
            nat: Some(gateway_config::config::expose::Nat::Stateless(
                gateway_config::config::PeeringStatelessNat {},
            )),
        };

        let vpc2_expose = gateway_config::Expose {
            ips: vec![exclude_ip],
            r#as: vec![exclude_as],
            nat: Some(gateway_config::config::expose::Nat::Stateless(
                gateway_config::config::PeeringStatelessNat {},
            )),
        };

        // Create PeeringEntryFor
        let vpc1_entry = gateway_config::PeeringEntryFor {
            vpc: "vpc-1".to_string(),
            expose: vec![vpc1_expose],
        };

        let vpc2_entry = gateway_config::PeeringEntryFor {
            vpc: "vpc-2".to_string(),
            expose: vec![vpc2_expose],
        };

        // Create VpcPeering
        let peering = gateway_config::VpcPeering {
            name: "vpc1-vpc2-peering".to_string(),
            r#for: vec![vpc1_entry, vpc2_entry],
        };

        // Create Overlay
        let overlay = gateway_config::Overlay {
            vpcs: vec![vpc1, vpc2],
            peerings: vec![peering],
        };

        // Create the full GatewayConfig
        GatewayConfig {
            generation: 42,
            device: Some(device),
            underlay: Some(underlay),
            overlay: Some(overlay),
        }
    }

    #[test]
    fn test_convert_to_grpc_config() {
        // Create test data
        let grpc_config = create_test_gateway_config();
        // Call the conversion function (gRPC -> ExternalConfig)
        let result = convert_gateway_config_from_grpc_with_defaults(&grpc_config);

        // Verify result
        assert!(
            result.is_ok(),
            "Conversion from gRPC failed: {:?}",
            result.err()
        );
        let external_config = result.unwrap();

        // ExternalConfig -> gRPC
        let result = gateway_config::GatewayConfig::try_from(&external_config);
        assert!(
            result.is_ok(),
            "Conversion to gRPC failed: {:?}",
            result.err()
        );
        let converted_grpc_config = result.unwrap();

        assert_eq!(grpc_config, converted_grpc_config);
    }

    #[test]
    fn test_tryfrom_conversions() {
        let tracing = create_tracing_config();

        // Create test data with specific components
        let device = gateway_config::Device {
            driver: 0, // Kernel
            hostname: "test-device".to_string(),
            ports: Vec::new(),
            eal: None,
            tracing: Some(tracing.clone()),
        };

        let interface = gateway_config::Interface {
            name: "eth0".to_string(),
            ipaddrs: vec!["192.168.1.1/24".to_string()],
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("00:11:22:33:44:55".to_string()),
            system_name: None,
            ospf: None,
            mtu: Some(9000),
            pci: Some("0000:02:00.1".to_string()),
        };

        // DeviceConfig TryFrom
        let device_config_result = DeviceConfig::try_from(&device);
        assert!(
            device_config_result.is_ok(),
            "TryFrom for DeviceConfig failed"
        );
        let device_config = device_config_result.unwrap();
        assert_eq!(device_config.settings.hostname, "test-device");

        // Back to gRPC
        let device_back_result = gateway_config::Device::try_from(&device_config);
        assert!(device_back_result.is_ok(), "TryFrom back to Device failed");
        let device_back = device_back_result.unwrap();
        assert_eq!(device_back.hostname, device.hostname);
        assert_eq!(device_back.driver, device.driver);
        assert_eq!(device_back.tracing.as_ref().unwrap(), &tracing);

        // InterfaceConfig TryFrom
        let interface_config_result = InterfaceConfig::try_from(&interface);
        assert!(
            interface_config_result.is_ok(),
            "TryFrom for InterfaceConfig failed"
        );
        let interface_config = interface_config_result.unwrap();
        assert_eq!(interface_config.name, "eth0");
        assert!(!interface_config.addresses.is_empty());

        // Back to gRPC
        let interface_back_result = gateway_config::Interface::try_from(&interface_config);
        assert!(
            interface_back_result.is_ok(),
            "TryFrom back to Interface failed"
        );
        let interface_back = interface_back_result.unwrap();
        assert_eq!(interface_back.name, interface.name);
        assert_eq!(interface_back.r#type, interface.r#type);
        assert!(!interface_back.ipaddrs.is_empty());
    }

    #[allow(clippy::too_many_lines)]
    fn create_test_status() -> gateway_config::GetDataplaneStatusResponse {
        // interface_statuses
        let interface_statuses = vec![
            gateway_config::InterfaceStatus {
                ifname: "eth0".into(),
                oper_status: gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp as i32,
                admin_status: gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp
                    as i32,
            },
            gateway_config::InterfaceStatus {
                ifname: "eth1".into(),
                oper_status: gateway_config::InterfaceOperStatusType::InterfaceStatusOperDown
                    as i32,
                admin_status: gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown
                    as i32,
            },
        ];

        // FRR
        let frr_status = Some(gateway_config::FrrStatus {
            zebra_status: gateway_config::ZebraStatusType::ZebraStatusConnected as i32,
            frr_agent_status: gateway_config::FrrAgentStatusType::FrrAgentStatusConnected as i32,
            applied_config_gen: 42,
            restarts: 1,
            applied_configs: 10,
            failed_configs: 0,
        });

        // Dataplane overall
        let dataplane_status = Some(gateway_config::DataplaneStatusInfo {
            status: gateway_config::DataplaneStatusType::DataplaneStatusHealthy as i32,
        });

        // interface_runtime
        let mut interface_runtime = std::collections::HashMap::new();
        interface_runtime.insert(
            "eth0".to_string(),
            gateway_config::InterfaceRuntimeStatus {
                admin_status: gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp
                    as i32,
                oper_status: gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp as i32,
                mac: "00:11:22:33:44:55".into(),
                mtu: 1500,
                counters: Some(gateway_config::InterfaceCounters {
                    tx_bits: 1_000_000,
                    tx_bps: 1000.0,
                    tx_errors: 1,
                    rx_bits: 2_000_000,
                    rx_bps: 2000.0,
                    rx_errors: 2,
                }),
            },
        );

        // BGP runtime
        let bgp_msgs = Some(gateway_config::BgpMessages {
            received: Some(gateway_config::BgpMessageCounters {
                capability: 1,
                keepalive: 10,
                notification: 0,
                open: 1,
                route_refresh: 0,
                update: 42,
            }),
            sent: Some(gateway_config::BgpMessageCounters {
                capability: 1,
                keepalive: 11,
                notification: 0,
                open: 1,
                route_refresh: 0,
                update: 40,
            }),
        });
        let v4pfx = Some(gateway_config::BgpNeighborPrefixes {
            received: 100,
            received_pre_policy: 120,
            sent: 90,
        });

        let mut neighbors = std::collections::HashMap::new();
        neighbors.insert(
            "192.0.2.1".to_string(),
            gateway_config::BgpNeighborStatus {
                enabled: true,
                local_as: 65001,
                peer_as: 65002,
                peer_port: 179,
                peer_group: "spines".into(),
                remote_router_id: "10.0.0.2".into(),
                session_state: gateway_config::BgpNeighborSessionState::BgpStateEstablished as i32,
                connections_dropped: 0,
                established_transitions: 3,
                last_reset_reason: String::new(),
                messages: bgp_msgs,
                ipv4_unicast_prefixes: v4pfx,
                ipv6_unicast_prefixes: None,
                l2vpn_evpn_prefixes: None,
            },
        );
        let mut vrfs = std::collections::HashMap::new();
        vrfs.insert("default".into(), gateway_config::BgpVrfStatus { neighbors });
        let bgp = Some(gateway_config::BgpStatus { vrfs });

        // VPCs + VPC peering counters
        let mut vpc_ifaces = std::collections::HashMap::new();
        vpc_ifaces.insert(
            "veth0".into(),
            gateway_config::VpcInterfaceStatus {
                ifname: "veth0".into(),
                admin_status: gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp
                    as i32,
                oper_status: gateway_config::InterfaceOperStatusType::InterfaceStatusOperUp as i32,
            },
        );
        let mut vpcs = std::collections::HashMap::new();
        vpcs.insert(
            "vpc-1".into(),
            gateway_config::VpcStatus {
                id: "0x202".into(),
                name: "vpc-1".into(),
                vni: 1001,
                route_count: 17,
                interfaces: vpc_ifaces,
            },
        );

        let mut vpc_peering_counters = std::collections::HashMap::new();
        vpc_peering_counters.insert(
            "peering-1".into(),
            gateway_config::VpcPeeringCounters {
                name: "peering-1".into(),
                src_vpc: "vpc-1".into(),
                dst_vpc: "vpc-2".into(),
                packets: 12345,
                bytes: 987_654,
                drops: 12,
                pps: 321.0,
            },
        );

        gateway_config::GetDataplaneStatusResponse {
            interface_statuses,
            frr_status,
            dataplane_status,
            interface_runtime,
            bgp,
            vpcs,
            vpc_peering_counters,
        }
    }

    #[test]
    fn test_convert_to_from_grpc_status() {
        let grpc_status = create_test_status();

        // gRPC -> internal
        let internal = convert_dataplane_status_from_grpc(&grpc_status)
            .expect("conversion from gRPC status failed");

        // internal -> gRPC
        let back =
            convert_dataplane_status_to_grpc(&internal).expect("conversion to gRPC status failed");

        assert_eq!(grpc_status, back);
    }
}
