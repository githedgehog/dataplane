// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::string::ToString;
use tracing::{Level, error, warn};

use crate::models::external::gwconfig::{
    ExternalConfig, ExternalConfigBuilder, GwConfig, Underlay,
};
use crate::models::external::overlay::Overlay;
use crate::models::external::overlay::vpc::{Vpc, VpcTable};
use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
use crate::models::external::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};
use crate::models::internal::routing::ospf::Ospf;

use routing::prefix::Prefix;

use crate::models::internal::device::{
    DeviceConfig,
    settings::{DeviceSettings, DpdkPortConfig, KernelPacketConfig, PacketDriver},
};
use crate::models::internal::interfaces::interface::InterfaceConfig;

use crate::models::internal::routing::bgp::BgpConfig;
use crate::models::internal::routing::vrf::VrfConfig;

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
    match parts.as_slice() {
        [ip, mask] => {
            let netmask = mask
                .parse::<u8>()
                .map_err(|_| format!("Invalid netmask in CIDR {cidr}: {mask}"))?;
            Ok(((*ip).to_string(), netmask))
        }
        _ => Err(format!("Invalid CIDR format: {cidr}")),
    }
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

/// Create a new `GwConfig` from `ExternalConfig`
pub fn create_gw_config(external_config: ExternalConfig) -> GwConfig {
    GwConfig::new(external_config)
}

// gRPC to Internal Conversions
//--------------------------------------------------------------------------------

/// Convert from `GatewayConfig` (gRPC) to `ExternalConfig`
pub fn convert_from_grpc_config(grpc_config: &GatewayConfig) -> Result<ExternalConfig, String> {
    // convert device if present or provide a default
    let device_config = if let Some(device) = &grpc_config.device {
        convert_device_from_grpc(device)?
    } else {
        warn!("Missing device configuration!");
        DeviceConfig::new(DeviceSettings::new("Unset"))
    };

    // convert underlay or provide a default (empty)
    let underlay_config = if let Some(underlay) = &grpc_config.underlay {
        convert_underlay_from_grpc(underlay)?
    } else {
        warn!("Missing underlay configuration!");
        Underlay::default()
    };

    // convert overlay or provide a default (empty)
    let overlay_config = if let Some(overlay) = &grpc_config.overlay {
        convert_overlay_from_grpc(overlay)?
    } else {
        warn!("Missing overlay configuration!");
        Overlay::default()
    };

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

/// Convert `gateway_config::Device` to `DeviceConfig`
pub fn convert_device_from_grpc(device: &gateway_config::Device) -> Result<DeviceConfig, String> {
    // Convert driver enum
    let driver = match gateway_config::config::PacketDriver::try_from(device.driver) {
        Ok(gateway_config::config::PacketDriver::Kernel) => {
            PacketDriver::Kernel(KernelPacketConfig {})
        }
        Ok(gateway_config::config::PacketDriver::Dpdk) => PacketDriver::DPDK(DpdkPortConfig {}),
        Err(_) => return Err(format!("Invalid driver value: {}", device.driver)),
    };
    // Convert log level enum
    let loglevel = match gateway_config::config::LogLevel::try_from(device.loglevel) {
        Ok(gateway_config::config::LogLevel::Error) => Level::ERROR,
        Ok(gateway_config::config::LogLevel::Warning) => Level::WARN,
        Ok(gateway_config::config::LogLevel::Info) => Level::INFO,
        Ok(gateway_config::config::LogLevel::Debug) => Level::DEBUG,
        Ok(gateway_config::config::LogLevel::Trace) => Level::TRACE,
        Err(_) => return Err(format!("Invalid log level value: {}", device.loglevel)),
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
    if underlay.vrfs.is_empty() {
        return Err("Underlay must contain at least one VRF".to_string());
    }

    // Look for the default VRF or use the first one
    let default_vrf = underlay
        .vrfs
        .iter()
        .find(|vrf| vrf.name == "default")
        .unwrap_or(&underlay.vrfs[0]); // FIXME(manish): This should be an error, preserving the original behavior for now

    // Convert VRF to VrfConfig
    let vrf_config = convert_vrf_to_vrf_config(default_vrf)?;

    // Create Underlay with the VRF config
    Ok(Underlay { vrf: vrf_config })
}

/// Convert gRPC VRF to internal `VrfConfig`
pub fn convert_vrf_to_vrf_config(vrf: &gateway_config::Vrf) -> Result<VrfConfig, String> {
    // Create VRF config
    let mut vrf_config = VrfConfig::new(&vrf.name, None, true /* default vrf */);

    // Convert BGP config if present and add it to VRF
    if let Some(router) = &vrf.router {
        let bgp = BgpConfig::try_from(router)?;
        vrf_config.set_bgp(bgp);
    }

    // convert each interface
    for iface in &vrf.interfaces {
        let iface_config = InterfaceConfig::try_from(iface)?;
        vrf_config.add_interface_config(iface_config);
    }

    // Convert ospf config if present
    if let Some(ospf_config) = &vrf.ospf {
        let ospf = convert_ospf_config_from_grpc(ospf_config)?;
        vrf_config.set_ospf(ospf);
    }

    Ok(vrf_config)
}

/// Convert gRPC `OspfConfig` to internal `Ospf`
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
    #[allow(clippy::collapsible_if)]
    if let Some(vrf_name) = &ospf_config.vrf {
        if !vrf_name.is_empty() {
            ospf.set_vrf_name(vrf_name.clone());
        }
    }

    Ok(ospf)
}

/// Convert a gRPC VPC to internal Vpc
pub fn convert_vpc_from_grpc(vpc_grpc: &gateway_config::Vpc) -> Result<Vpc, String> {
    // Create a new VPC with name and VNI
    let mut vpc = Vpc::new(&vpc_grpc.name, &vpc_grpc.id, vpc_grpc.vni)
        .map_err(|e| format!("Failed to create VPC: {e}"))?;

    // Convert and add interfaces if any
    // SMATOV: TODO: We will add this handling later. TBD
    if !vpc_grpc.interfaces.is_empty() {
        // For each interface from gRPC
        for iface in &vpc_grpc.interfaces {
            let interface = InterfaceConfig::try_from(iface)?;
            vpc.add_interface_config(interface);
        }
    }

    Ok(vpc)
}

/// Convert a gRPC `VpcPeering` to internal `VpcPeering`
pub fn convert_peering_from_grpc(
    peering_grpc: &gateway_config::VpcPeering,
) -> Result<VpcPeering, String> {
    let (vpc1_manifest, vpc2_manifest) = match peering_grpc.r#for.as_slice() {
        [vpc1, vpc2] => {
            let vpc1_manifest = convert_vpc_manifest_from_grpc(vpc1)?;
            let vpc2_manifest = convert_vpc_manifest_from_grpc(vpc2)?;
            Ok((vpc1_manifest, vpc2_manifest))
        }
        _ => Err(format!(
            "VPC peering {} must have exactly two VPCs",
            peering_grpc.name
        )),
    }?;

    // Create the peering using the constructor
    Ok(VpcPeering::new(
        &peering_grpc.name,
        vpc1_manifest,
        vpc2_manifest,
    ))
}

/// Convert gRPC `PeeringEntryFor` to `VpcManifest`
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

/// Convert gRPC `Expose` to `VpcExpose`
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
                    vpc_expose = vpc_expose.ip(Prefix::try_from_tuple((ip_str.as_str(), netmask))
                        .map_err(|e| e.to_string())?);
                }
                gateway_config::config::peering_i_ps::Rule::Not(not) => {
                    // Parse CIDR into IP and netmask for exclude rule
                    let (ip_str, netmask) = parse_cidr(not)?;
                    // Add as an exclude rule
                    vpc_expose = vpc_expose.not(
                        Prefix::try_from_tuple((ip_str.as_str(), netmask))
                            .map_err(|e| e.to_string())?,
                    );
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
                    vpc_expose = vpc_expose.as_range(
                        Prefix::try_from_tuple((ip_str.as_str(), netmask))
                            .map_err(|e| e.to_string())?,
                    );
                }
                gateway_config::config::peering_as::Rule::Not(ip_exclude) => {
                    // Parse CIDR into IP and netmask for exclude rule
                    let (ip_str, netmask) = parse_cidr(ip_exclude)?;
                    // Add as an exclude rule for AS
                    vpc_expose = vpc_expose.not_as(
                        Prefix::try_from_tuple((ip_str.as_str(), netmask))
                            .map_err(|e| e.to_string())?,
                    );
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

        vpc_table.add(vpc).map_err(|e| {
            let msg = format!("Failed to add VPC {}: {e}", vpc_grpc.name);
            error!("{msg}");
            msg
        })?;
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

/// Convert `DeviceConfig` to gRPC `Device`
pub fn convert_device_to_grpc(dev: &DeviceConfig) -> Result<gateway_config::Device, String> {
    let driver = match dev.settings.driver {
        PacketDriver::Kernel(_) => gateway_config::config::PacketDriver::Kernel,
        PacketDriver::DPDK(_) => gateway_config::config::PacketDriver::Dpdk,
    };

    let loglevel = match dev.settings.loglevel {
        Level::ERROR => gateway_config::config::LogLevel::Error,
        Level::WARN => gateway_config::config::LogLevel::Warning,
        Level::INFO => gateway_config::config::LogLevel::Info,
        Level::DEBUG => gateway_config::config::LogLevel::Debug,
        Level::TRACE => gateway_config::config::LogLevel::Trace,
    };

    // Convert ports if available
    let ports = Vec::new(); // TODO: Implement port conversion when needed

    Ok(gateway_config::Device {
        driver: driver.into(),
        hostname: dev.settings.hostname.clone(),
        loglevel: loglevel.into(),
        eal: None, // TODO: Handle EAL configuration when needed
        ports,
    })
}

/// Convert internal `Ospf` to gRPC `OspfConfig`
pub fn convert_ospf_to_grpc(ospf: &Ospf) -> gateway_config::config::OspfConfig {
    gateway_config::config::OspfConfig {
        router_id: ospf.router_id.to_string(),
        vrf: ospf.vrf.clone(),
    }
}

/// Convert internal `VrfConfig` to gRPC `Vrf`
pub fn convert_vrf_config_to_grpc(vrf: &VrfConfig) -> Result<gateway_config::Vrf, String> {
    // Convert interfaces
    let interfaces = Vec::<gateway_config::config::Interface>::try_from(&vrf.interfaces)?;

    // Convert router config if BGP is configured
    let router = match &vrf.bgp {
        Some(bgp) => Some(gateway_config::config::RouterConfig::try_from(bgp)?),
        None => None,
    };

    // Convert OSPF config if present
    let ospf = vrf.ospf.as_ref().map(convert_ospf_to_grpc);

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
        vrfs: vec![vrf_grpc],
    })
}

// Helper to convert VPC interfaces
pub fn convert_vpc_interfaces_to_grpc(vpc: &Vpc) -> Result<Vec<gateway_config::Interface>, String> {
    vpc.interfaces
        .values()
        .map(gateway_config::config::Interface::try_from)
        .collect()
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
    for prefix in &expose.ips {
        let rule = gateway_config::config::peering_i_ps::Rule::Cidr(prefix.to_string());
        ips.push(gateway_config::PeeringIPs { rule: Some(rule) });
    }

    // Convert IP exclusion rules
    for prefix in &expose.nots {
        let rule = gateway_config::config::peering_i_ps::Rule::Not(prefix.to_string());
        ips.push(gateway_config::PeeringIPs { rule: Some(rule) });
    }

    // Convert AS inclusion rules
    for prefix in &expose.as_range {
        let rule = gateway_config::config::peering_as::Rule::Cidr(prefix.to_string());
        as_rules.push(gateway_config::PeeringAs { rule: Some(rule) });
    }

    // Convert AS exclusion rules
    for prefix in &expose.not_as {
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

/// Convert from `ExternalConfig` to `GatewayConfig` (gRPC)
pub fn convert_to_grpc_config(external_config: &ExternalConfig) -> Result<GatewayConfig, String> {
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

// Add more TryFrom implementations as needed for other types

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
