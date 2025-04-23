// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    // Import proto-generated types
    use crate::grpc::server::BasicConfigManager;
    use crate::models::external::configdb::gwconfigdb::GwConfigDatabase;
    use gateway_config::GatewayConfig;

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
        };

        let lo0 = gateway_config::Interface {
            name: "lo0".to_string(),
            ipaddr: "10.0.0.1/32".to_string(),
            r#type: 2, // Loopback
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("".to_string()),
            system_name: Some("".to_string()),
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
        };

        // Create Underlay
        let underlay = gateway_config::Underlay { vrf: vec![vrf] };

        // Create interfaces for VPCs
        let vpc1_if1 = gateway_config::Interface {
            name: "vpc1_if1".to_string(),
            ipaddr: "10.1.1.1/24".to_string(),
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("".to_string()),
            system_name: Some("".to_string()),
        };

        let vpc2_if1 = gateway_config::Interface {
            name: "vpc2_if1".to_string(),
            ipaddr: "10.2.1.1/24".to_string(),
            r#type: 0, // Ethernet
            role: 0,   // Fabric
            vlan: None,
            macaddr: Some("".to_string()),
            system_name: Some("".to_string()),
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
        // Create a mock database
        let config_db = Arc::new(RwLock::new(GwConfigDatabase::new()));

        // Create the manager
        let manager = BasicConfigManager::new(Arc::clone(&config_db));

        // Create test data
        let grpc_config = create_test_gateway_config();

        // Call the conversion function (gRPC -> ExternalConfig)
        let result = manager.convert_from_grpc_config(&grpc_config).await;

        // Verify result
        assert!(
            result.is_ok(),
            "Conversion from gRPC failed: {:?}",
            result.err()
        );
        let external_config = result.unwrap();

        // Call the conversion function (ExternalConfig -> gRPC)
        let result = manager.convert_to_grpc_config(&external_config).await;

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
            converted_underlay.vrf.len(),
            original_underlay.vrf.len(),
            "VRF count mismatch"
        );

        // Get the default VRF from both configs
        let original_default_vrf = original_underlay
            .vrf
            .iter()
            .find(|vrf| vrf.name == "default")
            .or_else(|| original_underlay.vrf.first())
            .expect("No VRF found in original config");

        let converted_default_vrf = converted_underlay
            .vrf
            .iter()
            .find(|vrf| vrf.name == "default")
            .or_else(|| converted_underlay.vrf.first())
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
                .unwrap_or_else(|| panic!("Interface {} not found in converted config", name));

            assert_eq!(
                converted_iface.r#type, original_iface.r#type,
                "Interface type mismatch for {}",
                name
            );

            // For non-empty addresses
            if !original_iface.ipaddr.is_empty() {
                assert!(
                    !converted_iface.ipaddr.is_empty(),
                    "Interface address missing for {}",
                    name
                );
            }

            // Check VLAN if applicable
            if original_iface.r#type == 1 {
                // VLAN type
                assert_eq!(
                    converted_iface.vlan, original_iface.vlan,
                    "VLAN ID mismatch for interface {}",
                    name
                );
            }
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
                .unwrap_or_else(|| panic!("VPC {} not found in converted config", name));

            assert_eq!(
                converted_vpc.id, original_vpc.id,
                "VPC ID mismatch for {}",
                name
            );
            assert_eq!(
                converted_vpc.vni, original_vpc.vni,
                "VPC VNI mismatch for {}",
                name
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
                .unwrap_or_else(|| panic!("VPC peering {} not found in converted config", name));

            // Check for count
            assert_eq!(
                converted_peering.r#for.len(),
                original_peering.r#for.len(),
                "VPC peering entry count mismatch for {}",
                name
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
}
