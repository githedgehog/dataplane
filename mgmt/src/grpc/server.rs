// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// mgmt/src/grpc/server.rs

use async_trait::async_trait;
use net::vlan::Vid;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::Level;

use crate::models::external::configdb::gwconfig::{
    ExternalConfig, ExternalConfigBuilder, GwConfig, Underlay,
};
use crate::models::external::overlay::Overlay;
use crate::models::external::overlay::vpc::{Vpc, VpcTable};
use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use crate::models::external::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};

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
    BgpOptions, BgpUpdateSource, NeighSendCommunities,
};

// Import proto-generated types
use gateway_config::{
    ConfigService, ConfigServiceServer, Error, GatewayConfig, GetConfigGenerationRequest,
    GetConfigGenerationResponse, GetConfigRequest, UpdateConfigRequest, UpdateConfigResponse,
};

// Import database access
use crate::models::external::configdb::gwconfigdb::GwConfigDatabase;
use tokio::sync::RwLock;

/// Trait for configuration management
#[async_trait]
pub trait ConfigManager: Send + Sync {
    async fn get_current_config(&self) -> Result<GatewayConfig, String>;
    async fn get_generation(&self) -> Result<u64, String>;
    async fn apply_config(&self, config: GatewayConfig) -> Result<(), String>;
}

/// Implementation of the gRPC server
pub struct ConfigServiceImpl {
    config_manager: Arc<dyn ConfigManager>,
}

impl ConfigServiceImpl {
    pub fn new(config_manager: Arc<dyn ConfigManager>) -> Self {
        Self { config_manager }
    }
}

#[async_trait]
impl ConfigService for ConfigServiceImpl {
    async fn get_config(
        &self,
        _request: Request<GetConfigRequest>,
    ) -> Result<Response<GatewayConfig>, Status> {
        // Get current config from manager
        let current_config = self
            .config_manager
            .get_current_config()
            .await
            .map_err(|e| Status::internal(format!("Failed to get configuration: {}", e)))?;

        Ok(Response::new(current_config))
    }

    async fn get_config_generation(
        &self,
        _request: Request<GetConfigGenerationRequest>,
    ) -> Result<Response<GetConfigGenerationResponse>, Status> {
        let generation = self
            .config_manager
            .get_generation()
            .await
            .map_err(|e| Status::internal(format!("Failed to get generation: {}", e)))?;

        Ok(Response::new(GetConfigGenerationResponse { generation }))
    }

    async fn update_config(
        &self,
        request: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        let update_request = request.into_inner();
        let grpc_config = update_request
            .config
            .ok_or_else(|| Status::invalid_argument("Missing config in update request"))?;

        // Apply the configuration
        match self.config_manager.apply_config(grpc_config).await {
            Ok(_) => Ok(Response::new(UpdateConfigResponse {
                error: Error::None as i32,
                message: "Configuration updated successfully".to_string(),
            })),
            Err(e) => Ok(Response::new(UpdateConfigResponse {
                error: Error::ApplyFailed as i32,
                message: format!("Failed to apply configuration: {}", e),
            })),
        }
    }
}

/// Basic configuration manager implementation
pub struct BasicConfigManager {
    config_db: Arc<RwLock<GwConfigDatabase>>,
}

impl BasicConfigManager {
    pub fn new(config_db: Arc<RwLock<GwConfigDatabase>>) -> Self {
        Self { config_db }
    }

    // Helper method to safely get the first address from interface
    fn get_primary_address(&self, interface: &InterfaceConfig) -> Result<String, String> {
        if let Some(addr) = interface.addresses.iter().next() {
            Ok(format!("{}/{}", addr.address, addr.mask_len))
        } else {
            Ok(String::new()) // Return empty string if no address is found
        }
    }

    /// Convert from GatewayConfig (gRPC) to ExternalConfig
    async fn convert_from_grpc_config(
        &self,
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
        let device_config = self.convert_device_from_grpc(device)?;
        let underlay_config = self.convert_underlay_from_grpc(underlay)?;
        let overlay_config = self.convert_overlay_from_grpc(overlay)?;

        // Create the ExternalConfig using the builder pattern
        let external_config = ExternalConfigBuilder::default()
            .genid(grpc_config.generation)
            .device(device_config)
            .underlay(underlay_config)
            .overlay(overlay_config)
            .build()
            .map_err(|e| format!("Failed to build ExternalConfig: {}", e))?;

        Ok(external_config)
    }

    /// Create a new GwConfig with the ExternalConfig
    fn create_gw_config(&self, external_config: ExternalConfig) -> GwConfig {
        // Create a new GwConfig with the external config
        GwConfig::new(external_config)
    }

    /// Convert gRPC Device to internal DeviceConfig
    fn convert_device_from_grpc(
        &self,
        device: &gateway_config::Device,
    ) -> Result<DeviceConfig, String> {
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
    fn convert_underlay_from_grpc(
        &self,
        underlay: &gateway_config::Underlay,
    ) -> Result<Underlay, String> {
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
        let vrf_config = self.convert_vrf_to_vrf_config(default_vrf)?;

        // Create Underlay with the VRF config
        Ok(Underlay { vrf: vrf_config })
    }

    /// Convert gRPC VRF to internal VrfConfig
    fn convert_vrf_to_vrf_config(&self, vrf: &gateway_config::Vrf) -> Result<VrfConfig, String> {
        // Convert interfaces to InterfaceConfigTable
        let interfaces = self.convert_interfaces_to_table(&vrf.interfaces)?;

        // Convert BGP config if present
        let bgp = vrf
            .router
            .as_ref()
            .map(|router| self.convert_router_config_to_bgp_config(router))
            .transpose()?;

        // Create VRF config
        let vrf_config = VrfConfig {
            name: vrf.name.clone(),
            default: vrf.name == "default", // Set default to true if name is "default"
            tableid: None,                  // handle this later
            vni: None,                      // handle this later
            subnets: BTreeSet::new(),       // Empty set
            static_routes: BTreeSet::new(), // Empty set
            bgp,
            interfaces,
        };

        Ok(vrf_config)
    }

    /// Convert a gRPC Interface to internal InterfaceConfig
    fn convert_interface_to_interface_config(
        &self,
        iface: &gateway_config::Interface,
    ) -> Result<InterfaceConfig, String> {
        // Convert interface type
        let iftype = match iface.r#type {
            0 => InterfaceType::Ethernet(IfEthConfig { mac: None }),
            1 => InterfaceType::Vlan(IfVlanConfig {
                mac: None,
                vlan_id: unsafe { Vid::new_unchecked(iface.vlan.unwrap().try_into().unwrap()) },
            }),
            2 => InterfaceType::Loopback,
            3 => InterfaceType::Vtep(IfVtepConfig {
                mac: None,
                vni: None,
                ttl: None,
                local: IpAddr::from_str(&iface.ipaddr)
                    .map_err(|_| format!("Invalid local IP address: {}", iface.ipaddr))?,
            }),
            _ => return Err(format!("Invalid interface type value: {}", iface.r#type)),
        };
        // Create new InterfaceConfig
        let mut interface_config = InterfaceConfig::new(&iface.name.clone(), iftype, false);

        // Add the address from gRPC if present
        if !iface.ipaddr.is_empty() {
            let ipaddr = iface.ipaddr.clone();
            let (ip_str, netmask) = self.parse_cidr(&ipaddr)?;
            let new_addr =
                IpAddr::from_str(&ip_str).map_err(|_| format!("Invalid IP address: {}", ip_str))?;
            interface_config = interface_config.add_address(new_addr, netmask);
        }
        Ok(interface_config)
    }

    /// Convert gRPC interfaces to InterfaceConfigTable
    fn convert_interfaces_to_table(
        &self,
        interfaces: &[gateway_config::Interface],
    ) -> Result<InterfaceConfigTable, String> {
        let mut table = InterfaceConfigTable::new();

        for iface in interfaces {
            let iface_config = self.convert_interface_to_interface_config(iface)?;
            table.add_interface_config(iface_config);
        }

        Ok(table)
    }

    /// Convert gRPC RouterConfig to internal BgpConfig
    fn convert_router_config_to_bgp_config(
        &self,
        router: &gateway_config::RouterConfig,
    ) -> Result<BgpConfig, String> {
        // Parse ASN from string to u32
        let asn = router
            .asn
            .parse::<u32>()
            .map_err(|_| format!("Invalid ASN format: {}", router.asn))?;

        // Parse router_id from string to Ipv4Addr
        let router_id = if router.router_id.is_empty() {
            None
        } else {
            Some(
                Ipv4Addr::from_str(&router.router_id)
                    .map_err(|_| format!("Invalid router ID format: {}", router.router_id))?,
            )
        };

        // Use default options
        let options = BgpOptions::default();

        // Convert neighbors
        let mut neighbors = Vec::new();
        for neighbor in &router.neighbors {
            neighbors.push(self.convert_bgp_neighbor(neighbor)?);
        }

        // Convert IPv4 Unicast address family if present
        let af_ipv4unicast = router.ipv4_unicast.as_ref().map(|_ipv4| AfIpv4Ucast {
            ..AfIpv4Ucast::default()
        });

        let af_ipv6unicast = None;

        // Convert L2VPN EVPN address family if present
        let af_l2vpnevpn = router.l2vpn_evpn.as_ref().map(|_l2vpn| AfL2vpnEvpn {
            adv_all_vni: true,
            adv_default_gw: true,
            adv_svi_ip: true,
            adv_ipv4_unicast: true,
            adv_ipv6_unicast: false,
            adv_ipv4_unicast_rmap: None,
            adv_ipv6_unicast_rmap: None,
            default_originate_ipv4: false,
            default_originate_ipv6: false,
        });

        // Create BgpConfig
        Ok(BgpConfig {
            asn,
            vrf: None,
            router_id,
            options,
            neighbors,
            af_ipv4unicast,
            af_ipv6unicast,
            af_l2vpnevpn,
        })
    }

    /// Convert gRPC BgpNeighbor to internal BgpNeighbor
    fn convert_bgp_neighbor(
        &self,
        neighbor: &gateway_config::BgpNeighbor,
    ) -> Result<BgpNeighbor, String> {
        // Parse remote ASN
        let remote_as = Some(
            neighbor
                .remote_asn
                .parse::<u32>()
                .map_err(|_| format!("Invalid remote ASN format: {}", neighbor.remote_asn))?,
        );

        // Create neighbor address for ntype
        let neighbor_addr = IpAddr::from_str(&neighbor.address)
            .map_err(|_| format!("Invalid neighbor address: {}", neighbor.address))?;

        // Create neighbor type
        let ntype = BgpNeighType::Host(neighbor_addr);

        // Create update source
        let update_source = Some(BgpUpdateSource::Address(neighbor_addr));

        // Set capabilities to default
        let capabilities = BgpNeighCapabilities::default();

        // Set send community to "Send Both"
        let send_community = Some(NeighSendCommunities::Both);

        // Determine which address families are activated
        let mut ipv4_unicast = false;
        let mut ipv6_unicast = false;
        let mut l2vpn_evpn = false;

        for af in &neighbor.af_activate {
            match *af {
                0 => ipv4_unicast = true,
                1 => ipv6_unicast = true,
                2 => l2vpn_evpn = true,
                _ => return Err(format!("Unknown BGP address family: {}", af)),
            }
        }

        // Create the neighbor config
        Ok(BgpNeighbor {
            ntype,
            remote_as,
            peer_group: None,
            description: None,
            route_map_in: None,
            route_map_out: None, // FIXME: Route maps need to be configured
            update_source,
            weight: None,
            capabilities,
            send_community,
            ebgp_multihop: None,
            ttl_sec_hops: None,
            advertisement_interval: None,
            maximum_prefix: None,
            maximum_prefix_out: None,
            timer_connect: None,
            timer_delay_open: None,
            tcp_mss: None,

            // SMATOV: Switches all default to false, adjust it later?
            passive: false,
            as_override: false,
            strict_capability_match: false,
            dont_capability_negotiate: false,
            allow_as_in: false,
            extended_link_bandwidth: false,
            next_hop_self: false,
            remove_private_as: false,
            rr_client: false,
            default_originate: false,

            // Address families as determined from gRPC
            ipv4_unicast,
            ipv6_unicast,
            l2vpn_evpn,
        })
    }

    /// Convert a gRPC VPC to internal Vpc
    fn convert_vpc_from_grpc(&self, vpc_grpc: &gateway_config::Vpc) -> Result<Vpc, String> {
        // Create a new VPC with name and VNI
        let vpc = Vpc::new(&vpc_grpc.name, &vpc_grpc.id, vpc_grpc.vni)
            .map_err(|e| format!("Failed to create VPC: {}", e))?;

        // Convert and add interfaces if any
        // SMATOV: TODO: We will add this handling later. TBD
        if !vpc_grpc.interfaces.is_empty() {
            // For each interface from gRPC
            for _iface in &vpc_grpc.interfaces {
                // let interface = self.convert_interface_from_grpc(iface)?;
                // SMATOV: TODO vpc.add_interface_config(interface)
            }
        }

        Ok(vpc)
    }

    /// Convert a gRPC VpcPeering to internal VpcPeering
    fn convert_peering_from_grpc(
        &self,
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
        let vpc1_manifest = self.convert_vpc_manifest_from_grpc(&peering_grpc.r#for[0])?;
        let vpc2_manifest = self.convert_vpc_manifest_from_grpc(&peering_grpc.r#for[1])?;

        // Create the peering using the constructor
        Ok(VpcPeering::new(
            &peering_grpc.name,
            vpc1_manifest,
            vpc2_manifest,
        ))
    }

    /// Convert gRPC PeeringEntryFor to VpcManifest
    fn convert_vpc_manifest_from_grpc(
        &self,
        entry: &gateway_config::PeeringEntryFor,
    ) -> Result<VpcManifest, String> {
        // Create a new VPC manifest with the VPC name
        let mut manifest = VpcManifest::new(&entry.vpc);

        // Process each expose rule
        for expose_grpc in &entry.expose {
            let expose = self.convert_expose_from_grpc(expose_grpc)?;
            manifest.add_expose(expose).map_err(|e| {
                format!(
                    "Failed to add expose to manifest for VPC {}: {}",
                    entry.vpc, e
                )
            })?;
        }

        Ok(manifest)
    }

    /// Convert gRPC Expose to VpcExpose
    fn convert_expose_from_grpc(
        &self,
        expose: &gateway_config::Expose,
    ) -> Result<VpcExpose, String> {
        // Start with an empty expose
        let mut vpc_expose = VpcExpose::empty();

        // Process PeeringIP rules
        for ip in &expose.ips {
            if let Some(rule) = &ip.rule {
                match rule {
                    gateway_config::config::peering_i_ps::Rule::Cidr(cidr) => {
                        // Parse CIDR into IP and netmask
                        let (ip_str, netmask) = self.parse_cidr(cidr)?;
                        // Add as an include rule
                        vpc_expose = vpc_expose.ip(Prefix::from((ip_str.as_str(), netmask)));
                    }
                    gateway_config::config::peering_i_ps::Rule::Not(not) => {
                        // Parse CIDR into IP and netmask for exclude rule
                        let (ip_str, netmask) = self.parse_cidr(not)?;
                        // Add as an exclude rule
                        vpc_expose = vpc_expose.not(Prefix::from((ip_str.as_str(), netmask)));
                    }
                }
            } else {
                return Err("PeeringIPs must have either cidr or not field set".to_string());
            }
        }

        // Process PeeringAs rules
        for as_rule in &expose.r#as {
            if let Some(rule) = &as_rule.rule {
                match rule {
                    gateway_config::config::peering_as::Rule::Cidr(cidr) => {
                        // Parse CIDR into IP and netmask
                        let (ip_str, netmask) = self.parse_cidr(cidr)?;
                        // Add as an include rule for AS
                        vpc_expose = vpc_expose.as_range(Prefix::from((ip_str.as_str(), netmask)));
                    }
                    gateway_config::config::peering_as::Rule::Not(not) => {
                        // Parse CIDR into IP and netmask for exclude rule
                        let (ip_str, netmask) = self.parse_cidr(not)?;
                        // Add as an exclude rule for AS
                        vpc_expose = vpc_expose.not_as(Prefix::from((ip_str.as_str(), netmask)));
                    }
                }
            } else {
                return Err("PeeringAs must have either cidr or not field set".to_string());
            }
        }

        Ok(vpc_expose)
    }

    /// Parse a CIDR string into IP and netmask
    fn parse_cidr(&self, cidr: &str) -> Result<(String, u8), String> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid CIDR format: {}", cidr));
        }

        let ip = parts[0].to_string();
        let netmask = parts[1]
            .parse::<u8>()
            .map_err(|_| format!("Invalid netmask in CIDR {}: {}", cidr, parts[1]))?;

        Ok((ip, netmask))
    }

    /// Convert Overlay from gRPC
    fn convert_overlay_from_grpc(
        &self,
        overlay: &gateway_config::Overlay,
    ) -> Result<Overlay, String> {
        // Create VPC table
        let mut vpc_table = VpcTable::new();

        // Add VPCs
        for vpc_grpc in &overlay.vpcs {
            // Convert VPC
            let vpc = self.convert_vpc_from_grpc(vpc_grpc)?;

            vpc_table
                .add(vpc)
                .map_err(|e| format!("Failed to add VPC {}: {}", vpc_grpc.name, e))?;
        }

        // Create peering table
        let mut peering_table = VpcPeeringTable::new();

        // Add peerings
        for peering_grpc in &overlay.peerings {
            // Convert peering
            let peering = self.convert_peering_from_grpc(peering_grpc)?;

            // Add to table
            peering_table
                .add(peering)
                .map_err(|e| format!("Failed to add peering {}: {}", peering_grpc.name, e))?;
        }

        // Create overlay with the tables
        Ok(Overlay::new(vpc_table, peering_table))
    }

    /// Convert DeviceConfig to gRPC Device
    pub fn convert_device_to_grpc(
        &self,
        dev: &DeviceConfig,
    ) -> Result<gateway_config::Device, String> {
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

    pub fn make_prefix_string_from_addr_netmask(
        &self,
        addr: &str,
        netmask: u8,
    ) -> Result<String, String> {
        let ip =
            IpAddr::from_str(addr).map_err(|e| format!("Invalid IP address {}: {}", addr, e))?;

        // Validate netmask range based on IP type
        let max_mask = if ip.is_ipv4() { 32 } else { 128 };
        if netmask > max_mask {
            return Err(format!(
                "Invalid netmask {}: must be <= {}",
                netmask, max_mask
            ));
        }

        Ok(format!("{}/{}", ip, netmask))
    }

    pub fn convert_interfaces_to_grpc(
        &self,
        interfaces: &InterfaceConfigTable,
    ) -> Result<Vec<gateway_config::Interface>, String> {
        let mut grpc_interfaces = Vec::new();

        for interface in interfaces.values() {
            // Get IP address safely
            let ipaddr = self.get_primary_address(interface)?;

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
                InterfaceType::Ethernet(eth_config) => {
                    eth_config.mac.as_ref().map(|m| m.to_string())
                }
                InterfaceType::Vlan(vlan_config) => vlan_config.mac.as_ref().map(|m| m.to_string()),
                InterfaceType::Vtep(vtep_config) => vtep_config.mac.as_ref().map(|m| m.to_string()),
                _ => None,
            };

            // Create the gRPC interface
            let grpc_iface = gateway_config::Interface {
                name: interface.name.clone(),
                ipaddr,
                r#type: if_type,
                vlan,
                macaddr,
                system_name: None, // TODO: Implement when needed
                role: 0,           // Default to Fabric
            };

            grpc_interfaces.push(grpc_iface);
        }

        Ok(grpc_interfaces)
    }

    // Improved BGP conversion with better handling of address families
    fn convert_bgp_neighbor_to_grpc(
        &self,
        neighbor: &BgpNeighbor,
    ) -> Result<gateway_config::BgpNeighbor, String> {
        // Get neighbor address safely
        let address = match &neighbor.ntype {
            BgpNeighType::Host(addr) => addr.to_string(),
            BgpNeighType::PeerGroup(name) => {
                return Err(format!("Peer group type not supported in gRPC: {}", name));
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
    fn convert_bgp_config_to_grpc(
        &self,
        bgp: &BgpConfig,
    ) -> Result<gateway_config::RouterConfig, String> {
        // Convert BGP neighbors
        let mut neighbors = Vec::with_capacity(bgp.neighbors.len());
        for neighbor in &bgp.neighbors {
            let grpc_neighbor = self.convert_bgp_neighbor_to_grpc(neighbor)?;
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

    // Improved VRF conversion
    fn convert_vrf_config_to_grpc(&self, vrf: &VrfConfig) -> Result<gateway_config::Vrf, String> {
        // Convert interfaces
        let interfaces = self.convert_interfaces_to_grpc(&vrf.interfaces)?;

        // Convert router config if BGP is configured
        let router = match &vrf.bgp {
            Some(bgp) => Some(self.convert_bgp_config_to_grpc(bgp)?),
            None => None,
        };

        Ok(gateway_config::Vrf {
            name: vrf.name.clone(),
            interfaces,
            router,
        })
    }

    // Improved underlay conversion
    pub fn convert_underlay_to_grpc(
        &self,
        underlay: &Underlay,
    ) -> Result<gateway_config::Underlay, String> {
        // Convert the VRF
        let vrf_grpc = self.convert_vrf_config_to_grpc(&underlay.vrf)?;

        Ok(gateway_config::Underlay {
            vrf: vec![vrf_grpc],
        })
    }

    // Helper to convert VPC interfaces
    fn convert_vpc_interfaces_to_grpc(
        &self,
        _vpc: &Vpc,
    ) -> Result<Vec<gateway_config::Interface>, String> {
        // TODO: We currently don't support VPC interfaces in gRPC
        Ok(Vec::new())
    }

    /// Convert VPC to gRPC
    fn convert_vpc_to_grpc(&self, vpc: &Vpc) -> Result<gateway_config::Vpc, String> {
        // Convert VPC interfaces
        let interfaces = self.convert_vpc_interfaces_to_grpc(vpc)?;

        Ok(gateway_config::Vpc {
            name: vpc.name.clone(),
            id: vpc.id.to_string(),
            vni: vpc.vni.as_u32(),
            interfaces,
        })
    }

    /// Convert VPC expose rules to gRPC
    fn convert_vpc_expose_to_grpc(
        &self,
        expose: &VpcExpose,
    ) -> Result<gateway_config::Expose, String> {
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
    fn convert_vpc_manifest_to_grpc(
        &self,
        manifest: &VpcManifest,
    ) -> Result<gateway_config::PeeringEntryFor, String> {
        let mut expose_rules = Vec::new();

        // Convert each expose rule
        for expose in &manifest.exposes {
            let grpc_expose = self.convert_vpc_expose_to_grpc(expose)?;
            expose_rules.push(grpc_expose);
        }

        Ok(gateway_config::PeeringEntryFor {
            vpc: manifest.name.clone(),
            expose: expose_rules,
        })
    }

    /// Convert VPC peering to gRPC
    fn convert_vpc_peering_to_grpc(
        &self,
        peering: &VpcPeering,
    ) -> Result<gateway_config::VpcPeering, String> {
        // Convert the left and right VPC manifests
        let left_for = self.convert_vpc_manifest_to_grpc(&peering.left)?;
        let right_for = self.convert_vpc_manifest_to_grpc(&peering.right)?;

        Ok(gateway_config::VpcPeering {
            name: peering.name.clone(),
            r#for: vec![left_for, right_for],
        })
    }

    /// Convert Overlay to gRPC
    pub fn convert_overlay_to_grpc(
        &self,
        overlay: &Overlay,
    ) -> Result<gateway_config::Overlay, String> {
        let mut vpcs = Vec::new();
        let mut peerings = Vec::new();

        // Convert VPCs
        for vpc in overlay.vpc_table.values() {
            let grpc_vpc = self.convert_vpc_to_grpc(vpc)?;
            vpcs.push(grpc_vpc);
        }

        // Convert peerings
        for peering in overlay.peering_table.values() {
            let grpc_peering = self.convert_vpc_peering_to_grpc(peering)?;
            peerings.push(grpc_peering);
        }

        Ok(gateway_config::Overlay { vpcs, peerings })
    }

    /// Convert from ExternalConfig to GatewayConfig (gRPC)
    async fn convert_to_grpc_config(
        &self,
        external_config: &ExternalConfig,
    ) -> Result<GatewayConfig, String> {
        // Convert device config
        let device = self.convert_device_to_grpc(&external_config.device)?;

        // Convert underlay config
        let underlay = self.convert_underlay_to_grpc(&external_config.underlay)?;

        // Convert overlay config
        let overlay = self.convert_overlay_to_grpc(&external_config.overlay)?;

        // Create the complete gRPC config
        Ok(GatewayConfig {
            generation: external_config.genid,
            device: Some(device),
            underlay: Some(underlay),
            overlay: Some(overlay),
        })
    }
}

#[async_trait]
impl ConfigManager for BasicConfigManager {
    async fn get_current_config(&self) -> Result<GatewayConfig, String> {
        let config_db = self.config_db.read().await;
        let gw_config = config_db.get_current_config();

        // Convert GwConfig to GatewayConfig (gRPC format)
        self.convert_to_grpc_config(&gw_config.unwrap().external)
            .await
    }

    async fn get_generation(&self) -> Result<u64, String> {
        let config_db = self.config_db.read().await;
        let gw_config_gen = config_db.get_current_gen();

        Ok(gw_config_gen.unwrap())
    }

    async fn apply_config(&self, grpc_config: GatewayConfig) -> Result<(), String> {
        // Convert gRPC config to ExternalConfig
        let external_config = self.convert_from_grpc_config(&grpc_config).await?;

        // Create a new GwConfig with this ExternalConfig
        let gw_config = self.create_gw_config(external_config);

        // Get a write lock on the DB
        let mut config_db = self.config_db.write().await;

        // Store the new config
        config_db.add(gw_config);

        Ok(())
    }
}

/// Function to create the gRPC service
pub fn create_config_service(
    config_db: Arc<RwLock<GwConfigDatabase>>,
) -> ConfigServiceServer<ConfigServiceImpl> {
    let config_manager = Arc::new(BasicConfigManager::new(config_db));
    let service = ConfigServiceImpl::new(config_manager);
    ConfigServiceServer::new(service)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

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
