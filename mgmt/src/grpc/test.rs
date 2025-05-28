// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
#[allow(clippy::uninlined_format_args)]
mod tests {
    // Import proto-generated types
    use gateway_config::GatewayConfig;
    use pretty_assertions::assert_eq;
    use std::convert::TryFrom;

    // Import converter module
    use crate::grpc::converter;
    use crate::models::internal::device::DeviceConfig;
    use crate::models::internal::interfaces::interface::InterfaceConfig;

    // Helper function to create a test GatewayConfig
    fn create_test_gateway_config() -> GatewayConfig {
        // Create device
        let device = gateway_config::Device {
            driver: 0,   // Kernel
            loglevel: 2, // INFO
            hostname: "test-gateway".to_string(),
            ports: Vec::new(),
            eal: None,
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
        };

        // Create BGP neighbor
        let bgp_neighbor = gateway_config::BgpNeighbor {
            address: "192.168.1.2".to_string(),
            remote_asn: "65002".to_string(),
            af_activate: vec![0, 2], // IPv4 Unicast and L2VPN EVPN
            networks: Vec::new(),
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
        };

        let vpc2_expose = gateway_config::Expose {
            ips: vec![exclude_ip],
            r#as: vec![exclude_as],
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
        // Using standalone function instead of manager method
        let result = converter::convert_from_grpc_config(&grpc_config);

        // Verify result
        assert!(
            result.is_ok(),
            "Conversion from gRPC failed: {:?}",
            result.err()
        );
        let external_config = result.unwrap();

        // Call the conversion function (ExternalConfig -> gRPC)
        // Using standalone function instead of manager method
        let result = converter::convert_to_grpc_config(&external_config);

        // Verify result
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
        // Create test data with specific components
        let device = gateway_config::Device {
            driver: 0,   // Kernel
            loglevel: 2, // INFO
            hostname: "test-device".to_string(),
            ports: Vec::new(),
            eal: None,
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
        };

        // Test DeviceConfig TryFrom
        let device_config_result = DeviceConfig::try_from(&device);
        assert!(
            device_config_result.is_ok(),
            "TryFrom for DeviceConfig failed"
        );
        let device_config = device_config_result.unwrap();

        // Verify conversion result
        assert_eq!(device_config.settings.hostname, "test-device");

        // Convert back using TryFrom
        let device_back_result = gateway_config::Device::try_from(&device_config);
        assert!(device_back_result.is_ok(), "TryFrom back to Device failed");
        let device_back = device_back_result.unwrap();

        // Verify round trip conversion
        assert_eq!(device_back.hostname, device.hostname);
        assert_eq!(device_back.driver, device.driver);
        assert_eq!(device_back.loglevel, device.loglevel);

        // Test InterfaceConfig TryFrom
        let interface_config_result = InterfaceConfig::try_from(&interface);
        assert!(
            interface_config_result.is_ok(),
            "TryFrom for InterfaceConfig failed"
        );
        let interface_config = interface_config_result.unwrap();

        // Verify conversion result
        assert_eq!(interface_config.name, "eth0");
        assert!(!interface_config.addresses.is_empty());

        // Convert back using TryFrom
        let interface_back_result = gateway_config::Interface::try_from(&interface_config);
        assert!(
            interface_back_result.is_ok(),
            "TryFrom back to Interface failed"
        );
        let interface_back = interface_back_result.unwrap();

        // Verify round trip conversion
        assert_eq!(interface_back.name, interface.name);
        assert_eq!(interface_back.r#type, interface.r#type);
        assert!(!interface_back.ipaddrs.is_empty());
    }
}
