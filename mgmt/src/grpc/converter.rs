// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::vlan::Vid;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use tracing::Level;

use crate::models::external::configdb::gwconfig::{
    ExternalConfig, ExternalConfigBuilder, GwConfig, Underlay,
};
use crate::models::external::overlay::Overlay;
use crate::models::external::overlay::vpc::{Vpc, VpcTable};
use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use crate::models::external::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};
use crate::models::internal::routing::ospf::{Ospf, OspfInterface, OspfNetwork};

use routing::prefix::Prefix;

use crate::models::internal::device::{
    DeviceConfig,
    settings::{DeviceSettings, DpdkPortConfig, KernelPacketConfig, PacketDriver},
};
use crate::models::internal::interfaces::interface::{
    IfEthConfig, IfVlanConfig, IfVtepConfig, InterfaceConfig, InterfaceConfigTable, InterfaceType,
};

use crate::models::internal::routing::vrf::VrfConfig;

use crate::models::internal::routing::bgp::{
    AfIpv4Ucast, AfL2vpnEvpn, BgpConfig, BgpNeighCapabilities, BgpNeighType, BgpNeighbor,
    BgpOptions, NeighSendCommunities,
};

// Import proto-generated types
use gateway_config::GatewayConfig;

// Helper Functions
//--------------------------------------------------------------------------------

/// Helper method to safely get the first address from interface
pub fn get_primary_address(interface: &InterfaceConfig) -> Result<String, String> {
    if let Some(addr) = interface.addresses.iter().next() {
        Ok(format!("{}/{}", addr.address, addr.mask_len))
    } else {
        Ok(String::new()) // Return empty string if no address is found
    }
}

/// Parse a CIDR string into IP and netmask
pub fn parse_cidr(cidr: &str) -> Result<(String, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid CIDR format: {cidr}"));
    }

    let ip = parts[0].to_string();
    let netmask = parts[1]
        .parse::<u8>()
        .map_err(|_| format!("Invalid netmask in CIDR {cidr}: {}", parts[1]))?;

    Ok((ip, netmask))
}

pub fn make_prefix_string_from_addr_netmask(addr: &str, netmask: u8) -> Result<String, String> {
    let ip = IpAddr::from_str(addr).map_err(|e| format!("Invalid IP address {addr}: {e}"))?;

    // Validate netmask range based on IP type
    let max_mask = if ip.is_ipv4() { 32 } else { 128 };
    if netmask > max_mask {
        return Err(format!("Invalid netmask {netmask}: must be <= {max_mask}"));
    }

    Ok(format!("{ip}/{netmask}"))
}

/// Create a new GwConfig from ExternalConfig
pub fn create_gw_config(external_config: ExternalConfig) -> GwConfig {
    GwConfig::new(external_config)
}

// gRPC to Internal Conversions
//--------------------------------------------------------------------------------

/// Convert from GatewayConfig (gRPC) to ExternalConfig
pub async fn convert_from_grpc_config(
    grpc_config: &GatewayConfig,
) -> Result<ExternalConfig, String> {
    // Extract required components
    let device = grpc_config
        .device
        .as_ref()
        .ok_or_else(|| "Missing device configuration".to_string())?;

    let underlay = grpc_config
        .underlay
        .as_ref()
        .ok_or_else(|| "Missing underlay configuration".to_string())?;

    let overlay = grpc_config
        .overlay
        .as_ref()
        .ok_or_else(|| "Missing overlay configuration".to_string())?;

    // Convert each component
    let device_config = convert_device_from_grpc(device)?;
    let underlay_config = convert_underlay_from_grpc(underlay)?;
    let overlay_config = convert_overlay_from_grpc(overlay)?;

    // Create the ExternalConfig using the builder pattern
    let external_config = ExternalConfigBuilder::default()
        .genid(grpc_config.generation)
        .device(device_config)
        .underlay(underlay_config)
        .overlay(overlay_config)
        .build()
        .map_err(|e| format!("Failed to build ExternalConfig: {e}"))?;

    Ok(external_config)
}

/// Convert gRPC Device to internal DeviceConfig
pub fn convert_device_from_grpc(device: &gateway_config::Device) -> Result<DeviceConfig, String> {
    // Convert driver enum
    let driver = match device.driver {
        0 => PacketDriver::Kernel(KernelPacketConfig {}),
        1 => PacketDriver::DPDK(DpdkPortConfig {}),
        _ => return Err(format!("Invalid driver value: {}", device.driver)),
    };
    // Convert log level enum
    let loglevel = match device.loglevel {
        0 => Level::ERROR,
        1 => Level::WARN,
        2 => Level::INFO,
        3 => Level::DEBUG,
        4 => Level::TRACE,
        _ => return Err(format!("Invalid log level value: {}", device.loglevel)),
    };

    // Create device settings
    let mut device_settings = DeviceSettings::new(&device.hostname);
    device_settings = device_settings
        .set_packet_driver(driver)
        .set_loglevel(loglevel);

    // Create DeviceConfig with these settings
    // Note: PortConfig is not yet implemented, so we don't add any ports
    let device_config = DeviceConfig::new(device_settings);

    Ok(device_config)
}

/// Convert gRPC Underlay to internal Underlay
pub fn convert_underlay_from_grpc(underlay: &gateway_config::Underlay) -> Result<Underlay, String> {
    // Find the default VRF or first VRF if default not found
    if underlay.vrf.is_empty() {
        return Err("Underlay must contain at least one VRF".to_string());
    }

    // Look for the default VRF or use the first one
    let default_vrf = underlay
        .vrf
        .iter()
        .find(|vrf| vrf.name == "default")
        .unwrap_or(&underlay.vrf[0]);

    // Convert VRF to VrfConfig
    let vrf_config = convert_vrf_to_vrf_config(default_vrf)?;

    // Create Underlay with the VRF config
    Ok(Underlay { vrf: vrf_config })
}

/// Convert gRPC VRF to internal VrfConfig
pub fn convert_vrf_to_vrf_config(vrf: &gateway_config::Vrf) -> Result<VrfConfig, String> {
    // Create VRF config
    let mut vrf_config = VrfConfig::new(&vrf.name, None, true /* default vrf */);

    // Convert BGP config if present and add it to VRF
    if let Some(router) = &vrf.router {
        let bgp = convert_router_config_to_bgp_config(router)?;
        vrf_config.set_bgp(bgp);
    }

    // convert each interface
    for iface in &vrf.interfaces {
        let iface_config = convert_interface_to_interface_config(iface)?;
        vrf_config.add_interface_config(iface_config);
    }

    // Convert ospf config if present
    if let Some(ospf_config) = &vrf.ospf {
        let ospf = convert_ospf_config_from_grpc(ospf_config)?;
        vrf_config.set_ospf(ospf);
    }

    Ok(vrf_config)
}

/// Convert gRPC OspfConfig to internal Ospf
pub fn convert_ospf_config_from_grpc(
    ospf_config: &gateway_config::config::OspfConfig,
) -> Result<Ospf, String> {
    // Parse router_id from string to Ipv4Addr
    let router_id = ospf_config
        .router_id
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid OSPF router ID format: {}", ospf_config.router_id))?;

    // Create a new Ospf instance
    let mut ospf = Ospf::new(router_id);

    // Set VRF name if present
    if let Some(vrf_name) = &ospf_config.vrf {
        if !vrf_name.is_empty() {
            ospf.set_vrf_name(vrf_name.clone());
        }
    }

    Ok(ospf)
}

/// Convert gRPC OspfInterface to internal OspfInterface
pub fn convert_ospf_interface_from_grpc(
    ospf_interface: &gateway_config::config::OspfInterface,
) -> Result<OspfInterface, String> {
    // Parse area from string to Ipv4Addr
    let area = ospf_interface
        .area
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid OSPF area format: {}", ospf_interface.area))?;

    // Create a new OspfInterface instance
    let mut ospf_iface = OspfInterface::new(area);

    // Set passive state
    ospf_iface = ospf_iface.set_passive(ospf_interface.passive);

    // Set cost if present
    if let Some(cost) = ospf_interface.cost {
        ospf_iface = ospf_iface.set_cost(cost);
    }

    // Set network type if present
    if let Some(network_type) = &ospf_interface.network_type {
        let network = match network_type {
            0 => OspfNetwork::Broadcast,
            1 => OspfNetwork::NonBroadcast,
            2 => OspfNetwork::Point2Point,
            3 => OspfNetwork::Point2Multipoint,
            _ => return Err(format!("Invalid OSPF network type: {network_type}")),
        };
        ospf_iface = ospf_iface.set_network(network);
    }

    Ok(ospf_iface)
}

/// Convert a gRPC Interface to internal InterfaceConfig
pub fn convert_interface_to_interface_config(
    iface: &gateway_config::Interface,
) -> Result<InterfaceConfig, String> {
    // Convert interface type
    let iftype = match iface.r#type {
        0 => InterfaceType::Ethernet(IfEthConfig { mac: None }),
        1 => {
            // Safely handle the VLAN ID conversion
            let vlan_id = iface
                .vlan
                .ok_or_else(|| "VLAN interface requires vlan ID".to_string())?;

            // Try to convert to u16
            let vlan_u16 =
                u16::try_from(vlan_id).map_err(|_| format!("Invalid VLAN ID: {vlan_id}"))?;

            // Create a safe Vid
            let vid =
                Vid::new(vlan_u16).map_err(|_| format!("Invalid VLAN ID value: {vlan_u16}"))?;

            InterfaceType::Vlan(IfVlanConfig {
                mac: None,
                vlan_id: vid,
            })
        }
        2 => InterfaceType::Loopback,
        3 => {
            // For VTEP, parse the local IP from the ipaddr field
            if iface.ipaddr.is_empty() {
                return Err("VTEP interface requires IP address".to_string());
            }

            // Parse IP address for VTEP
            let ip_parts: Vec<&str> = iface.ipaddr.split('/').collect();
            let ip_str = ip_parts[0]; // Get just the IP part, not the CIDR

            let local_ip = IpAddr::from_str(ip_str)
                .map_err(|_| format!("Invalid local IP address for VTEP: {ip_str}"))?;

            InterfaceType::Vtep(IfVtepConfig {
                mac: None,
                vni: None,
                ttl: None,
                local: local_ip,
            })
        }
        _ => return Err(format!("Invalid interface type value: {}", iface.r#type)),
    };

    // Create new InterfaceConfig
    let mut interface_config = InterfaceConfig::new(&iface.name, iftype, false);

    // Add the address from gRPC if present
    if !iface.ipaddr.is_empty() {
        let (ip_str, netmask) = parse_cidr(&iface.ipaddr)?;
        let new_addr =
            IpAddr::from_str(&ip_str).map_err(|_| format!("Invalid IP address: {ip_str}"))?;
        interface_config = interface_config.add_address(new_addr, netmask);
    }

    // Add OSPF interface configuration if present
    if let Some(ospf_iface) = &iface.ospf {
        let ospf_interface = convert_ospf_interface_from_grpc(ospf_iface)?;
        interface_config = interface_config.set_ospf(ospf_interface);
    }

    Ok(interface_config)
}

/// Convert gRPC RouterConfig to internal BgpConfig
pub fn convert_router_config_to_bgp_config(
    router: &gateway_config::RouterConfig,
) -> Result<BgpConfig, String> {
    // Parse ASN from string to u32
    let asn = router
        .asn
        .parse::<u32>()
        .map_err(|_| format!("Invalid ASN format: {}", router.asn))?;

    // Parse router_id from string to Ipv4Addr
    let router_id = router
        .router_id
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("Invalid router ID format: {}", router.router_id))?;

    // Use default options
    let options = BgpOptions::default();

    // Convert neighbors
    let mut neighbors = Vec::new();
    for neighbor in &router.neighbors {
        neighbors.push(convert_bgp_neighbor(neighbor)?);
    }

    // Convert IPv4 Unicast address family if present
    let af_ipv4unicast = AfIpv4Ucast::new();

    let af_l2vpnevpn = AfL2vpnEvpn::new()
        .set_adv_all_vni(true)
        .set_adv_default_gw(true)
        .set_adv_svi_ip(true)
        .set_adv_ipv4_unicast(true)
        .set_adv_ipv6_unicast(false)
        .set_default_originate_ipv4(false)
        .set_default_originate_ipv6(false);

    let mut bgpconfig = BgpConfig::new(asn);
    bgpconfig.set_router_id(router_id);
    bgpconfig.set_bgp_options(options);
    bgpconfig.set_af_ipv4unicast(af_ipv4unicast);
    bgpconfig.set_af_l2vpn_evpn(af_l2vpnevpn);

    // Add each neighbor to the BGP config
    for neighbor in &router.neighbors {
        bgpconfig.add_neighbor(convert_bgp_neighbor(neighbor)?);
    }

    Ok(bgpconfig)
}

/// Convert gRPC BgpNeighbor to internal BgpNeighbor
pub fn convert_bgp_neighbor(neighbor: &gateway_config::BgpNeighbor) -> Result<BgpNeighbor, String> {
    // Parse remote ASN
    let remote_as = neighbor
        .remote_asn
        .parse::<u32>()
        .map_err(|_| format!("Invalid remote ASN format: {}", neighbor.remote_asn))?;

    // Create neighbor address for ntype
    let neighbor_addr = IpAddr::from_str(&neighbor.address)
        .map_err(|_| format!("Invalid neighbor address: {}", neighbor.address))?;

    // Determine which address families are activated
    let mut ipv4_unicast = false;
    let mut ipv6_unicast = false;
    let mut l2vpn_evpn = false;

    for af in &neighbor.af_activate {
        match *af {
            0 => ipv4_unicast = true,
            1 => ipv6_unicast = true,
            2 => l2vpn_evpn = true,
            _ => return Err(format!("Unknown BGP address family: {af}")),
        }
    }

    // Create the neighbor config
    let neigh = BgpNeighbor::new_host(neighbor_addr)
        .set_remote_as(remote_as)
        .set_update_source_address(neighbor_addr)
        .set_capabilities(BgpNeighCapabilities::default())
        .set_send_community(NeighSendCommunities::Both)
        .ipv4_unicast_activate(ipv4_unicast)
        .ipv6_unicast_activate(ipv6_unicast)
        .l2vpn_evpn_activate(l2vpn_evpn);
    Ok(neigh)
}

/// Convert a gRPC VPC to internal Vpc
pub fn convert_vpc_from_grpc(vpc_grpc: &gateway_config::Vpc) -> Result<Vpc, String> {
    // Create a new VPC with name and VNI
    let vpc = Vpc::new(&vpc_grpc.name, &vpc_grpc.id, vpc_grpc.vni)
        .map_err(|e| format!("Failed to create VPC: {e}"))?;

    // Convert and add interfaces if any
    // SMATOV: TODO: We will add this handling later. TBD
    if !vpc_grpc.interfaces.is_empty() {
        // For each interface from gRPC
        for _iface in &vpc_grpc.interfaces {
            // let interface = convert_interface_from_grpc(iface)?;
            // SMATOV: TODO vpc.add_interface_config(interface)
        }
    }

    Ok(vpc)
}

/// Convert a gRPC VpcPeering to internal VpcPeering
pub fn convert_peering_from_grpc(
    peering_grpc: &gateway_config::VpcPeering,
) -> Result<VpcPeering, String> {
    // Need exactly two VPCs for a peering
    if peering_grpc.r#for.len() != 2 {
        return Err(format!(
            "VPC peering {} must have exactly two VPCs",
            peering_grpc.name
        ));
    }

    // Get the two VPC manifests
    let vpc1_manifest = convert_vpc_manifest_from_grpc(&peering_grpc.r#for[0])?;
    let vpc2_manifest = convert_vpc_manifest_from_grpc(&peering_grpc.r#for[1])?;

    // Create the peering using the constructor
    Ok(VpcPeering::new(
        &peering_grpc.name,
        vpc1_manifest,
        vpc2_manifest,
    ))
}

/// Convert gRPC PeeringEntryFor to VpcManifest
pub fn convert_vpc_manifest_from_grpc(
    entry: &gateway_config::PeeringEntryFor,
) -> Result<VpcManifest, String> {
    // Create a new VPC manifest with the VPC name
    let mut manifest = VpcManifest::new(&entry.vpc);

    // Process each expose rule
    for expose_grpc in &entry.expose {
        let expose = convert_expose_from_grpc(expose_grpc)?;
        manifest.add_expose(expose).map_err(|e| {
            format!(
                "Failed to add expose to manifest for VPC {}: {e}",
                entry.vpc
            )
        })?;
    }

    Ok(manifest)
}

/// Convert gRPC Expose to VpcExpose
pub fn convert_expose_from_grpc(expose: &gateway_config::Expose) -> Result<VpcExpose, String> {
    // Start with an empty expose
    let mut vpc_expose = VpcExpose::empty();

    // Process PeeringIP rules
    for ip in &expose.ips {
        if let Some(rule) = &ip.rule {
            match rule {
                gateway_config::config::peering_i_ps::Rule::Cidr(cidr) => {
                    // Parse CIDR into IP and netmask
                    let (ip_str, netmask) = parse_cidr(cidr)?;
                    // Add as an include rule
                    vpc_expose = vpc_expose.ip(Prefix::from((ip_str.as_str(), netmask)));
                }
                gateway_config::config::peering_i_ps::Rule::Not(not) => {
                    // Parse CIDR into IP and netmask for exclude rule
                    let (ip_str, netmask) = parse_cidr(not)?;
                    // Add as an exclude rule
                    vpc_expose = vpc_expose.not(Prefix::from((ip_str.as_str(), netmask)));
                }
            }
        } else {
            return Err("PeeringIPs must have either 'cidr' or 'not' field set".to_string());
        }
    }

    // Process PeeringAs rules
    for as_rule in &expose.r#as {
        if let Some(rule) = &as_rule.rule {
            match rule {
                gateway_config::config::peering_as::Rule::Cidr(cidr) => {
                    // Parse CIDR into IP and netmask
                    let (ip_str, netmask) = parse_cidr(cidr)?;
                    // Add as an include rule for AS
                    vpc_expose = vpc_expose.as_range(Prefix::from((ip_str.as_str(), netmask)));
                }
                gateway_config::config::peering_as::Rule::Not(ip_exclude) => {
                    // Parse CIDR into IP and netmask for exclude rule
                    let (ip_str, netmask) = parse_cidr(ip_exclude)?;
                    // Add as an exclude rule for AS
                    vpc_expose = vpc_expose.not_as(Prefix::from((ip_str.as_str(), netmask)));
                }
            }
        } else {
            return Err("PeeringAs must have either 'cidr' or 'not' field set".to_string());
        }
    }

    Ok(vpc_expose)
}

/// Convert Overlay from gRPC
pub fn convert_overlay_from_grpc(overlay: &gateway_config::Overlay) -> Result<Overlay, String> {
    // Create VPC table
    let mut vpc_table = VpcTable::new();

    // Add VPCs
    for vpc_grpc in &overlay.vpcs {
        // Convert VPC
        let vpc = convert_vpc_from_grpc(vpc_grpc)?;

        vpc_table
            .add(vpc)
            .map_err(|e| format!("Failed to add VPC {}: {e}", vpc_grpc.name))?;
    }

    // Create peering table
    let mut peering_table = VpcPeeringTable::new();

    // Add peerings
    for peering_grpc in &overlay.peerings {
        // Convert peering
        let peering = convert_peering_from_grpc(peering_grpc)?;

        // Add to table
        peering_table
            .add(peering)
            .map_err(|e| format!("Failed to add peering {}: {e}", peering_grpc.name))?;
    }

    // Create overlay with the tables
    Ok(Overlay::new(vpc_table, peering_table))
}

// Internal to gRPC Conversions
//--------------------------------------------------------------------------------

/// Convert DeviceConfig to gRPC Device
pub fn convert_device_to_grpc(dev: &DeviceConfig) -> Result<gateway_config::Device, String> {
    let driver = match dev.settings.driver {
        PacketDriver::Kernel(_) => 0,
        PacketDriver::DPDK(_) => 1,
    };

    let loglevel = match dev.settings.loglevel {
        Level::ERROR => 0,
        Level::WARN => 1,
        Level::INFO => 2,
        Level::DEBUG => 3,
        Level::TRACE => 4,
    };

    // Convert ports if available
    let ports = Vec::new(); // TODO: Implement port conversion when needed

    Ok(gateway_config::Device {
        driver,
        hostname: dev.settings.hostname.clone(),
        loglevel,
        eal: None, // TODO: Handle EAL configuration when needed
        ports,
    })
}

pub fn convert_ospf_interface_to_grpc(
    ospf_interface: &OspfInterface,
) -> gateway_config::config::OspfInterface {
    // Convert network type if present
    let network_type = ospf_interface
        .network
        .as_ref()
        .map(|network| match network {
            OspfNetwork::Broadcast => 0,
            OspfNetwork::NonBroadcast => 1,
            OspfNetwork::Point2Point => 2,
            OspfNetwork::Point2Multipoint => 3,
        });

    gateway_config::config::OspfInterface {
        passive: ospf_interface.passive,
        area: ospf_interface.area.to_string(),
        cost: ospf_interface.cost,
        network_type,
    }
}

pub fn convert_interfaces_to_grpc(
    interfaces: &InterfaceConfigTable,
) -> Result<Vec<gateway_config::Interface>, String> {
    let mut grpc_interfaces = Vec::new();

    for interface in interfaces.values() {
        // Get IP address safely
        let ipaddr = get_primary_address(interface)?;

        // Convert interface type
        let if_type = match &interface.iftype {
            InterfaceType::Ethernet(_) => 0,
            InterfaceType::Vlan(_) => 1,
            InterfaceType::Loopback => 2,
            InterfaceType::Vtep(_) => 3,
            _ => {
                return Err(format!(
                    "Unsupported interface type: {:?}",
                    interface.iftype
                ));
            }
        };

        // Get VLAN ID if available
        let vlan = match &interface.iftype {
            InterfaceType::Vlan(if_vlan_config) => Some(if_vlan_config.vlan_id.as_u16() as u32),
            _ => None,
        };

        // Get MAC address if available
        let macaddr = match &interface.iftype {
            InterfaceType::Ethernet(eth_config) => eth_config.mac.as_ref().map(|m| m.to_string()),
            InterfaceType::Vlan(vlan_config) => vlan_config.mac.as_ref().map(|m| m.to_string()),
            InterfaceType::Vtep(vtep_config) => vtep_config.mac.as_ref().map(|m| m.to_string()),
            _ => None,
        };

        // Convert OSPF interface if present
        let ospf = interface
            .ospf
            .as_ref()
            .map(|ospf_config| convert_ospf_interface_to_grpc(ospf_config));

        // Create the gRPC interface
        let grpc_iface = gateway_config::Interface {
            name: interface.name.clone(),
            ipaddr,
            r#type: if_type,
            vlan,
            macaddr,
            system_name: None, // TODO: Implement when needed
            role: 0,           // Default to Fabric
            ospf,
        };

        grpc_interfaces.push(grpc_iface);
    }

    Ok(grpc_interfaces)
}

// Improved BGP conversion with better handling of address families
pub fn convert_bgp_neighbor_to_grpc(
    neighbor: &BgpNeighbor,
) -> Result<gateway_config::BgpNeighbor, String> {
    // Get neighbor address safely
    let address = match &neighbor.ntype {
        BgpNeighType::Host(addr) => addr.to_string(),
        BgpNeighType::PeerGroup(name) => {
            return Err(format!("Peer group type not supported in gRPC: {name}"));
        }
        BgpNeighType::Unset => {
            return Err("Unset BGP neighbor type not supported in gRPC".to_string());
        }
    };

    // Get remote ASN safely
    let remote_asn = neighbor
        .remote_as
        .as_ref()
        .ok_or_else(|| "Missing remote ASN for BGP neighbor".to_string())?
        .to_string();

    // Build address family activation list
    let mut af_activate = Vec::new();
    if neighbor.ipv4_unicast {
        af_activate.push(0); // IPV4_UNICAST
    }
    if neighbor.ipv6_unicast {
        af_activate.push(1); // IPV6_UNICAST
    }
    if neighbor.l2vpn_evpn {
        af_activate.push(2); // L2VPN_EVPN
    }

    Ok(gateway_config::BgpNeighbor {
        address,
        remote_asn,
        af_activate,
    })
}

// Improved router config conversion
pub fn convert_bgp_config_to_grpc(bgp: &BgpConfig) -> Result<gateway_config::RouterConfig, String> {
    // Convert BGP neighbors
    let mut neighbors = Vec::with_capacity(bgp.neighbors.len());
    for neighbor in &bgp.neighbors {
        let grpc_neighbor = convert_bgp_neighbor_to_grpc(neighbor)?;
        neighbors.push(grpc_neighbor);
    }

    // Get router ID safely
    let router_id = bgp
        .router_id
        .as_ref()
        .map_or(String::new(), |id| id.to_string());

    // Create IPv4 unicast config if enabled
    let ipv4_unicast = bgp.af_ipv4unicast.as_ref().map(|_| {
        gateway_config::BgpAddressFamilyIPv4 {
            redistribute_connected: true, // Default to true
            redistribute_static: false,   // Default to false
        }
    });

    // Create IPv6 unicast config if enabled
    let ipv6_unicast = bgp.af_ipv6unicast.as_ref().map(|_| {
        gateway_config::BgpAddressFamilyIPv6 {
            redistribute_connected: true, // Default to true
            redistribute_static: false,   // Default to false
        }
    });

    // Create L2VPN EVPN config if enabled
    let l2vpn_evpn =
        bgp.af_l2vpnevpn
            .as_ref()
            .map(|config| gateway_config::BgpAddressFamilyL2vpnEvpn {
                advertise_all_vni: config.adv_all_vni,
            });

    // Create route maps (empty for now)
    let route_maps = Vec::new(); // TODO: Implement route map conversion

    Ok(gateway_config::RouterConfig {
        asn: bgp.asn.to_string(),
        router_id,
        neighbors,
        ipv4_unicast,
        ipv6_unicast,
        l2vpn_evpn,
        route_maps,
    })
}

/// Convert gRPC OSPF to internal Ospf
pub fn convert_ospf_to_grpc(ospf: &Ospf) -> gateway_config::config::OspfConfig {
    gateway_config::config::OspfConfig {
        router_id: ospf.router_id.to_string(),
        vrf: ospf.vrf.clone(),
    }
}

/// Convert gRPC VRF to internal VrfConfig
pub fn convert_vrf_config_to_grpc(vrf: &VrfConfig) -> Result<gateway_config::Vrf, String> {
    // Convert interfaces
    let interfaces = convert_interfaces_to_grpc(&vrf.interfaces)?;

    // Convert router config if BGP is configured
    let router = match &vrf.bgp {
        Some(bgp) => Some(convert_bgp_config_to_grpc(bgp)?),
        None => None,
    };

    // Convert OSPF config if present
    let ospf = vrf.ospf.as_ref().map(|ospf| convert_ospf_to_grpc(ospf));

    Ok(gateway_config::Vrf {
        name: vrf.name.clone(),
        interfaces,
        router,
        ospf,
    })
}

// Improved underlay conversion
pub fn convert_underlay_to_grpc(underlay: &Underlay) -> Result<gateway_config::Underlay, String> {
    // Convert the VRF
    let vrf_grpc = convert_vrf_config_to_grpc(&underlay.vrf)?;

    Ok(gateway_config::Underlay {
        vrf: vec![vrf_grpc],
    })
}

// Helper to convert VPC interfaces
pub fn convert_vpc_interfaces_to_grpc(
    _vpc: &Vpc,
) -> Result<Vec<gateway_config::Interface>, String> {
    // TODO: We currently don't support VPC interfaces in gRPC
    Ok(Vec::new())
}

/// Convert VPC to gRPC
pub fn convert_vpc_to_grpc(vpc: &Vpc) -> Result<gateway_config::Vpc, String> {
    // Convert VPC interfaces
    let interfaces = convert_vpc_interfaces_to_grpc(vpc)?;

    Ok(gateway_config::Vpc {
        name: vpc.name.clone(),
        id: vpc.id.to_string(),
        vni: vpc.vni.as_u32(),
        interfaces,
    })
}

/// Convert VPC expose rules to gRPC
pub fn convert_vpc_expose_to_grpc(expose: &VpcExpose) -> Result<gateway_config::Expose, String> {
    let mut ips = Vec::new();
    let mut as_rules = Vec::new();

    // Convert IP inclusion rules
    for prefix in expose.ips.iter() {
        let rule = gateway_config::config::peering_i_ps::Rule::Cidr(prefix.to_string());
        ips.push(gateway_config::PeeringIPs { rule: Some(rule) });
    }

    // Convert IP exclusion rules
    for prefix in expose.nots.iter() {
        let rule = gateway_config::config::peering_i_ps::Rule::Not(prefix.to_string());
        ips.push(gateway_config::PeeringIPs { rule: Some(rule) });
    }

    // Convert AS inclusion rules
    for prefix in expose.as_range.iter() {
        let rule = gateway_config::config::peering_as::Rule::Cidr(prefix.to_string());
        as_rules.push(gateway_config::PeeringAs { rule: Some(rule) });
    }

    // Convert AS exclusion rules
    for prefix in expose.not_as.iter() {
        let rule = gateway_config::config::peering_as::Rule::Not(prefix.to_string());
        as_rules.push(gateway_config::PeeringAs { rule: Some(rule) });
    }

    Ok(gateway_config::Expose {
        ips,
        r#as: as_rules,
    })
}

/// Convert VPC manifest to gRPC
pub fn convert_vpc_manifest_to_grpc(
    manifest: &VpcManifest,
) -> Result<gateway_config::PeeringEntryFor, String> {
    let mut expose_rules = Vec::new();

    // Convert each expose rule
    for expose in &manifest.exposes {
        let grpc_expose = convert_vpc_expose_to_grpc(expose)?;
        expose_rules.push(grpc_expose);
    }

    Ok(gateway_config::PeeringEntryFor {
        vpc: manifest.name.clone(),
        expose: expose_rules,
    })
}

/// Convert VPC peering to gRPC
pub fn convert_vpc_peering_to_grpc(
    peering: &VpcPeering,
) -> Result<gateway_config::VpcPeering, String> {
    // Convert the left and right VPC manifests
    let left_for = convert_vpc_manifest_to_grpc(&peering.left)?;
    let right_for = convert_vpc_manifest_to_grpc(&peering.right)?;

    Ok(gateway_config::VpcPeering {
        name: peering.name.clone(),
        r#for: vec![left_for, right_for],
    })
}

/// Convert Overlay to gRPC
pub fn convert_overlay_to_grpc(overlay: &Overlay) -> Result<gateway_config::Overlay, String> {
    let mut vpcs = Vec::new();
    let mut peerings = Vec::new();

    // Convert VPCs
    for vpc in overlay.vpc_table.values() {
        let grpc_vpc = convert_vpc_to_grpc(vpc)?;
        vpcs.push(grpc_vpc);
    }

    // Convert peerings
    for peering in overlay.peering_table.values() {
        let grpc_peering = convert_vpc_peering_to_grpc(peering)?;
        peerings.push(grpc_peering);
    }

    Ok(gateway_config::Overlay { vpcs, peerings })
}

/// Convert from ExternalConfig to GatewayConfig (gRPC)
pub async fn convert_to_grpc_config(
    external_config: &ExternalConfig,
) -> Result<GatewayConfig, String> {
    // Convert device config
    let device = convert_device_to_grpc(&external_config.device)?;

    // Convert underlay config
    let underlay = convert_underlay_to_grpc(&external_config.underlay)?;

    // Convert overlay config
    let overlay = convert_overlay_to_grpc(&external_config.overlay)?;

    // Create the complete gRPC config
    Ok(GatewayConfig {
        generation: external_config.genid,
        device: Some(device),
        underlay: Some(underlay),
        overlay: Some(overlay),
    })
}

// TryFrom implementations for automatic conversions
//--------------------------------------------------------------------------------

impl TryFrom<&gateway_config::Device> for DeviceConfig {
    type Error = String;

    fn try_from(device: &gateway_config::Device) -> Result<Self, Self::Error> {
        convert_device_from_grpc(device)
    }
}

impl TryFrom<&DeviceConfig> for gateway_config::Device {
    type Error = String;

    fn try_from(device: &DeviceConfig) -> Result<Self, Self::Error> {
        convert_device_to_grpc(device)
    }
}

impl TryFrom<&gateway_config::Interface> for InterfaceConfig {
    type Error = String;

    fn try_from(interface: &gateway_config::Interface) -> Result<Self, Self::Error> {
        convert_interface_to_interface_config(interface)
    }
}

impl TryFrom<&InterfaceConfig> for gateway_config::Interface {
    type Error = String;

    fn try_from(interface: &InterfaceConfig) -> Result<Self, Self::Error> {
        // Get IP address safely
        let ipaddr = get_primary_address(interface)?;

        // Convert interface type
        let if_type = match &interface.iftype {
            InterfaceType::Ethernet(_) => 0,
            InterfaceType::Vlan(_) => 1,
            InterfaceType::Loopback => 2,
            InterfaceType::Vtep(_) => 3,
            _ => {
                return Err(format!(
                    "Unsupported interface type: {:?}",
                    interface.iftype
                ));
            }
        };

        // Get VLAN ID if available
        let vlan = match &interface.iftype {
            InterfaceType::Vlan(if_vlan_config) => Some(if_vlan_config.vlan_id.as_u16() as u32),
            _ => None,
        };

        // Get MAC address if available
        let macaddr = match &interface.iftype {
            InterfaceType::Ethernet(eth_config) => eth_config.mac.as_ref().map(|m| m.to_string()),
            InterfaceType::Vlan(vlan_config) => vlan_config.mac.as_ref().map(|m| m.to_string()),
            InterfaceType::Vtep(vtep_config) => vtep_config.mac.as_ref().map(|m| m.to_string()),
            _ => None,
        };

        // Convert OSPF interface if present
        let ospf = interface
            .ospf
            .as_ref()
            .map(|ospf_config| convert_ospf_interface_to_grpc(ospf_config));

        Ok(gateway_config::Interface {
            name: interface.name.clone(),
            ipaddr,
            r#type: if_type,
            vlan,
            macaddr,
            system_name: None,
            role: 0, // Default to Fabric
            ospf,
        })
    }
}

// Add more TryFrom implementations as needed for other types

// BgpNeighbor conversions
impl TryFrom<&gateway_config::BgpNeighbor> for BgpNeighbor {
    type Error = String;

    fn try_from(neighbor: &gateway_config::BgpNeighbor) -> Result<Self, Self::Error> {
        convert_bgp_neighbor(neighbor)
    }
}

impl TryFrom<&BgpNeighbor> for gateway_config::BgpNeighbor {
    type Error = String;

    fn try_from(neighbor: &BgpNeighbor) -> Result<Self, Self::Error> {
        convert_bgp_neighbor_to_grpc(neighbor)
    }
}

// BgpConfig conversions
impl TryFrom<&gateway_config::RouterConfig> for BgpConfig {
    type Error = String;

    fn try_from(router: &gateway_config::RouterConfig) -> Result<Self, Self::Error> {
        convert_router_config_to_bgp_config(router)
    }
}

impl TryFrom<&BgpConfig> for gateway_config::RouterConfig {
    type Error = String;

    fn try_from(bgp: &BgpConfig) -> Result<Self, Self::Error> {
        convert_bgp_config_to_grpc(bgp)
    }
}

// OSPF conversions
impl TryFrom<&gateway_config::config::OspfConfig> for Ospf {
    type Error = String;

    fn try_from(ospf_config: &gateway_config::config::OspfConfig) -> Result<Self, Self::Error> {
        convert_ospf_config_from_grpc(ospf_config)
    }
}

impl From<&Ospf> for gateway_config::config::OspfConfig {
    fn from(ospf: &Ospf) -> Self {
        convert_ospf_to_grpc(ospf)
    }
}

// OSPF Interface conversions
impl TryFrom<&gateway_config::config::OspfInterface> for OspfInterface {
    type Error = String;

    fn try_from(
        ospf_interface: &gateway_config::config::OspfInterface,
    ) -> Result<Self, Self::Error> {
        convert_ospf_interface_from_grpc(ospf_interface)
    }
}

impl From<&OspfInterface> for gateway_config::config::OspfInterface {
    fn from(ospf_interface: &OspfInterface) -> Self {
        convert_ospf_interface_to_grpc(ospf_interface)
    }
}

// VRF conversions
impl TryFrom<&gateway_config::Vrf> for VrfConfig {
    type Error = String;

    fn try_from(vrf: &gateway_config::Vrf) -> Result<Self, Self::Error> {
        convert_vrf_to_vrf_config(vrf)
    }
}

impl TryFrom<&VrfConfig> for gateway_config::Vrf {
    type Error = String;

    fn try_from(vrf: &VrfConfig) -> Result<Self, Self::Error> {
        convert_vrf_config_to_grpc(vrf)
    }
}

// Underlay conversions
impl TryFrom<&gateway_config::Underlay> for Underlay {
    type Error = String;

    fn try_from(underlay: &gateway_config::Underlay) -> Result<Self, Self::Error> {
        convert_underlay_from_grpc(underlay)
    }
}

impl TryFrom<&Underlay> for gateway_config::Underlay {
    type Error = String;

    fn try_from(underlay: &Underlay) -> Result<Self, Self::Error> {
        convert_underlay_to_grpc(underlay)
    }
}

// VPC conversions
impl TryFrom<&gateway_config::Vpc> for Vpc {
    type Error = String;

    fn try_from(vpc: &gateway_config::Vpc) -> Result<Self, Self::Error> {
        convert_vpc_from_grpc(vpc)
    }
}

impl TryFrom<&Vpc> for gateway_config::Vpc {
    type Error = String;

    fn try_from(vpc: &Vpc) -> Result<Self, Self::Error> {
        convert_vpc_to_grpc(vpc)
    }
}

// VPC Expose conversions
impl TryFrom<&gateway_config::Expose> for VpcExpose {
    type Error = String;

    fn try_from(expose: &gateway_config::Expose) -> Result<Self, Self::Error> {
        convert_expose_from_grpc(expose)
    }
}

impl TryFrom<&VpcExpose> for gateway_config::Expose {
    type Error = String;

    fn try_from(expose: &VpcExpose) -> Result<Self, Self::Error> {
        convert_vpc_expose_to_grpc(expose)
    }
}

// VPC Manifest conversions
impl TryFrom<&gateway_config::PeeringEntryFor> for VpcManifest {
    type Error = String;

    fn try_from(entry: &gateway_config::PeeringEntryFor) -> Result<Self, Self::Error> {
        convert_vpc_manifest_from_grpc(entry)
    }
}

impl TryFrom<&VpcManifest> for gateway_config::PeeringEntryFor {
    type Error = String;

    fn try_from(manifest: &VpcManifest) -> Result<Self, Self::Error> {
        convert_vpc_manifest_to_grpc(manifest)
    }
}

// VPC Peering conversions
impl TryFrom<&gateway_config::VpcPeering> for VpcPeering {
    type Error = String;

    fn try_from(peering: &gateway_config::VpcPeering) -> Result<Self, Self::Error> {
        convert_peering_from_grpc(peering)
    }
}

impl TryFrom<&VpcPeering> for gateway_config::VpcPeering {
    type Error = String;

    fn try_from(peering: &VpcPeering) -> Result<Self, Self::Error> {
        convert_vpc_peering_to_grpc(peering)
    }
}

// Overlay conversions
impl TryFrom<&gateway_config::Overlay> for Overlay {
    type Error = String;

    fn try_from(overlay: &gateway_config::Overlay) -> Result<Self, Self::Error> {
        convert_overlay_from_grpc(overlay)
    }
}

impl TryFrom<&Overlay> for gateway_config::Overlay {
    type Error = String;

    fn try_from(overlay: &Overlay) -> Result<Self, Self::Error> {
        convert_overlay_to_grpc(overlay)
    }
}
