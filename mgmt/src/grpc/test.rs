// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
#[allow(clippy::uninlined_format_args)]
mod tests {
    // Import proto-generated types
    use gateway_config::GatewayConfig;
    use std::collections::HashMap;
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
            ipaddr: "192.168.1.1/24".to_string(),
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("00:11:22:33:44:55".to_string()),
            system_name: Some("".to_string()),
            ospf: None,
        };

        let lo0 = gateway_config::Interface {
            name: "lo0".to_string(),
            ipaddr: "10.0.0.1/32".to_string(),
            r#type: 2, // Loopback
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("".to_string()),
            system_name: Some("".to_string()),
            ospf: None,
        };

        // Create BGP neighbor
        let bgp_neighbor = gateway_config::BgpNeighbor {
            address: "192.168.1.2".to_string(),
            remote_asn: "65002".to_string(),
            af_activate: vec![0, 2], // IPv4 Unicast and L2VPN EVPN
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
            ipaddr: "10.1.1.1/24".to_string(),
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("".to_string()),
            system_name: Some("".to_string()),
            ospf: None,
        };

        let vpc2_if1 = gateway_config::Interface {
            name: "vpc2_if1".to_string(),
            ipaddr: "10.2.1.1/24".to_string(),
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("".to_string()),
            system_name: Some("".to_string()),
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

    #[tokio::test]
    async fn test_convert_to_grpc_config() {
        // Create test data
        let grpc_config = create_test_gateway_config();
        // Call the conversion function (gRPC -> ExternalConfig)
        // Using standalone function instead of manager method
        let result = converter::convert_from_grpc_config(&grpc_config).await;

        // Verify result
        assert!(
            result.is_ok(),
            "Conversion from gRPC failed: {:?}",
            result.err()
        );
        let external_config = result.unwrap();

        // Call the conversion function (ExternalConfig -> gRPC)
        // Using standalone function instead of manager method
        let result = converter::convert_to_grpc_config(&external_config).await;

        // Verify result
        assert!(
            result.is_ok(),
            "Conversion to gRPC failed: {:?}",
            result.err()
        );
        let converted_grpc_config = result.unwrap();

        // Verify generation ID
        assert_eq!(
            converted_grpc_config.generation, grpc_config.generation,
            "Generation ID mismatch"
        );

        // --- DEVICE CONFIGURATION TESTS ---
        let original_device = grpc_config
            .device
            .as_ref()
            .expect("Missing device in original config");
        let converted_device = converted_grpc_config
            .device
            .as_ref()
            .expect("Missing device in converted config");

        assert_eq!(
            converted_device.hostname, original_device.hostname,
            "Device hostname mismatch"
        );
        assert_eq!(
            converted_device.driver, original_device.driver,
            "Device driver mismatch"
        );
        assert_eq!(
            converted_device.loglevel, original_device.loglevel,
            "Device log level mismatch"
        );

        // --- Test TryFrom implementation ---
        // Convert device using TryFrom
        let device_result = DeviceConfig::try_from(original_device);
        assert!(
            device_result.is_ok(),
            "TryFrom conversion for device failed"
        );
        let internal_device = device_result.unwrap();

        // Convert back to gRPC using TryFrom
        let device_grpc_result = gateway_config::Device::try_from(&internal_device);
        assert!(
            device_grpc_result.is_ok(),
            "TryFrom conversion back to gRPC device failed"
        );
        let device_grpc = device_grpc_result.unwrap();

        // Verify conversion via TryFrom
        assert_eq!(
            device_grpc.hostname, original_device.hostname,
            "Device hostname mismatch using TryFrom"
        );

        // --- UNDERLAY CONFIGURATION TESTS ---
        let original_underlay = grpc_config
            .underlay
            .as_ref()
            .expect("Missing underlay in original config");
        let converted_underlay = converted_grpc_config
            .underlay
            .as_ref()
            .expect("Missing underlay in converted config");

        // Check VRF count
        assert_eq!(
            converted_underlay.vrfs.len(),
            original_underlay.vrfs.len(),
            "VRF count mismatch"
        );

        // Get the default VRF from both configs
        let original_default_vrf = original_underlay
            .vrfs
            .iter()
            .find(|vrf| vrf.name == "default")
            .or_else(|| original_underlay.vrfs.first())
            .expect("No VRF found in original config");

        let converted_default_vrf = converted_underlay
            .vrfs
            .iter()
            .find(|vrf| vrf.name == "default")
            .or_else(|| converted_underlay.vrfs.first())
            .expect("No VRF found in converted config");

        // Check VRF name
        assert_eq!(
            converted_default_vrf.name, original_default_vrf.name,
            "VRF name mismatch"
        );

        // Check interface count
        assert_eq!(
            converted_default_vrf.interfaces.len(),
            original_default_vrf.interfaces.len(),
            "Interface count mismatch"
        );

        // Create maps of interfaces by name for comparison
        let original_interfaces: HashMap<String, &gateway_config::Interface> = original_default_vrf
            .interfaces
            .iter()
            .map(|iface| (iface.name.clone(), iface))
            .collect();

        let converted_interfaces: HashMap<String, &gateway_config::Interface> =
            converted_default_vrf
                .interfaces
                .iter()
                .map(|iface| (iface.name.clone(), iface))
                .collect();

        // Check that all original interfaces exist in converted config
        for (name, original_iface) in &original_interfaces {
            let converted_iface = converted_interfaces
                .get(name)
                .unwrap_or_else(|| panic!("Interface {name} not found in converted config"));

            assert_eq!(
                converted_iface.r#type, original_iface.r#type,
                "Interface type mismatch for {name}",
            );

            // For non-empty addresses
            if !original_iface.ipaddr.is_empty() {
                assert!(
                    !converted_iface.ipaddr.is_empty(),
                    "Interface address missing for {name}",
                );
            }

            // Check VLAN if applicable
            if original_iface.r#type == 1 {
                // VLAN type
                assert_eq!(
                    converted_iface.vlan, original_iface.vlan,
                    "VLAN ID mismatch for interface {name}",
                );
            }

            // Test TryFrom for interface
            let interface_result = InterfaceConfig::try_from(*original_iface);
            assert!(
                interface_result.is_ok(),
                "TryFrom conversion for interface failed for {}",
                name
            );

            let internal_interface = interface_result.unwrap();

            // Test converting back
            let interface_grpc_result = gateway_config::Interface::try_from(&internal_interface);
            assert!(
                interface_grpc_result.is_ok(),
                "TryFrom conversion back to gRPC interface failed for {}",
                name
            );
        }

        // --- BGP CONFIGURATION TESTS ---
        if let (Some(original_router), Some(converted_router)) =
            (&original_default_vrf.router, &converted_default_vrf.router)
        {
            // Check ASN
            assert_eq!(
                converted_router.asn, original_router.asn,
                "BGP ASN mismatch"
            );

            // Check Router ID
            assert_eq!(
                converted_router.router_id, original_router.router_id,
                "BGP Router ID mismatch"
            );

            // Check neighbor count
            assert_eq!(
                converted_router.neighbors.len(),
                original_router.neighbors.len(),
                "BGP neighbor count mismatch"
            );

            // Compare each neighbor
            for (i, original_neighbor) in original_router.neighbors.iter().enumerate() {
                let converted_neighbor = &converted_router.neighbors[i];

                assert_eq!(
                    converted_neighbor.address, original_neighbor.address,
                    "BGP neighbor address mismatch"
                );

                assert_eq!(
                    converted_neighbor.remote_asn, original_neighbor.remote_asn,
                    "BGP neighbor remote ASN mismatch"
                );

                // Check address families
                // Sort both arrays to ensure consistent comparison
                let mut original_af = original_neighbor.af_activate.clone();
                let mut converted_af = converted_neighbor.af_activate.clone();
                original_af.sort();
                converted_af.sort();

                assert_eq!(
                    converted_af, original_af,
                    "BGP neighbor address family activation mismatch"
                );
            }

            // Check IPv4 unicast
            if original_router.ipv4_unicast.is_some() {
                assert!(
                    converted_router.ipv4_unicast.is_some(),
                    "IPv4 unicast missing in converted config"
                );
                let original_ipv4 = original_router.ipv4_unicast.as_ref().unwrap();
                let converted_ipv4 = converted_router.ipv4_unicast.as_ref().unwrap();

                assert_eq!(
                    converted_ipv4.redistribute_connected, original_ipv4.redistribute_connected,
                    "IPv4 unicast redistribute_connected mismatch"
                );

                assert_eq!(
                    converted_ipv4.redistribute_static, original_ipv4.redistribute_static,
                    "IPv4 unicast redistribute_static mismatch"
                );
            } else {
                assert!(
                    converted_router.ipv4_unicast.is_none(),
                    "IPv4 unicast should be None"
                );
            }

            // Check L2VPN EVPN
            if original_router.l2vpn_evpn.is_some() {
                assert!(
                    converted_router.l2vpn_evpn.is_some(),
                    "L2VPN EVPN missing in converted config"
                );
                let original_l2vpn = original_router.l2vpn_evpn.as_ref().unwrap();
                let converted_l2vpn = converted_router.l2vpn_evpn.as_ref().unwrap();

                assert_eq!(
                    converted_l2vpn.advertise_all_vni, original_l2vpn.advertise_all_vni,
                    "L2VPN EVPN advertise_all_vni mismatch"
                );
            } else {
                assert!(
                    converted_router.l2vpn_evpn.is_none(),
                    "L2VPN EVPN should be None"
                );
            }
        }

        // --- OVERLAY CONFIGURATION TESTS ---
        let original_overlay = grpc_config
            .overlay
            .as_ref()
            .expect("Missing overlay in original config");
        let converted_overlay = converted_grpc_config
            .overlay
            .as_ref()
            .expect("Missing overlay in converted config");

        // Check VPC count
        assert_eq!(
            converted_overlay.vpcs.len(),
            original_overlay.vpcs.len(),
            "VPC count mismatch"
        );

        // Create maps of VPCs by name for comparison
        let original_vpcs: HashMap<String, &gateway_config::Vpc> = original_overlay
            .vpcs
            .iter()
            .map(|vpc| (vpc.name.clone(), vpc))
            .collect();

        let converted_vpcs: HashMap<String, &gateway_config::Vpc> = converted_overlay
            .vpcs
            .iter()
            .map(|vpc| (vpc.name.clone(), vpc))
            .collect();

        // Check that all original VPCs exist in converted config
        for (name, original_vpc) in &original_vpcs {
            let converted_vpc = converted_vpcs
                .get(name)
                .unwrap_or_else(|| panic!("VPC {name} not found in converted config"));

            assert_eq!(
                converted_vpc.id, original_vpc.id,
                "VPC ID mismatch for {name}",
            );
            assert_eq!(
                converted_vpc.vni, original_vpc.vni,
                "VPC VNI mismatch for {name}",
            );

            // Note: We're not checking interfaces yet as they are not fully implemented
        }

        // Check peering count
        assert_eq!(
            converted_overlay.peerings.len(),
            original_overlay.peerings.len(),
            "VPC peering count mismatch"
        );

        // Create maps of peerings by name for comparison
        let original_peerings: HashMap<String, &gateway_config::VpcPeering> = original_overlay
            .peerings
            .iter()
            .map(|peering| (peering.name.clone(), peering))
            .collect();

        let converted_peerings: HashMap<String, &gateway_config::VpcPeering> = converted_overlay
            .peerings
            .iter()
            .map(|peering| (peering.name.clone(), peering))
            .collect();

        // Check that all original peerings exist in converted config
        for (name, original_peering) in &original_peerings {
            let converted_peering = converted_peerings
                .get(name)
                .unwrap_or_else(|| panic!("VPC peering {name} not found in converted config"));

            // Check for count
            assert_eq!(
                converted_peering.r#for.len(),
                original_peering.r#for.len(),
                "VPC peering entry count mismatch for {name}",
            );

            // Check each VPC in the peering
            for (i, original_entry) in original_peering.r#for.iter().enumerate() {
                let converted_entry = &converted_peering.r#for[i];

                assert_eq!(
                    converted_entry.vpc, original_entry.vpc,
                    "VPC peering entry VPC name mismatch"
                );

                // Check expose rules count
                assert_eq!(
                    converted_entry.expose.len(),
                    original_entry.expose.len(),
                    "VPC peering expose rule count mismatch for VPC {}",
                    original_entry.vpc
                );

                // Check each expose rule
                for (j, original_expose) in original_entry.expose.iter().enumerate() {
                    let converted_expose = &converted_entry.expose[j];

                    // Check IP rules count
                    assert_eq!(
                        converted_expose.ips.len(),
                        original_expose.ips.len(),
                        "IP rules count mismatch in expose rule"
                    );

                    // Check AS rules count
                    assert_eq!(
                        converted_expose.r#as.len(),
                        original_expose.r#as.len(),
                        "AS rules count mismatch in expose rule"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn test_tryfrom_conversions() {
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
            ipaddr: "192.168.1.1/24".to_string(),
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("00:11:22:33:44:55".to_string()),
            system_name: Some("".to_string()),
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
        assert!(!interface_back.ipaddr.is_empty());
    }
}
