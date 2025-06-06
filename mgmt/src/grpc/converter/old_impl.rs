// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::string::ToString;
use tracing::{Level, error, warn};

use crate::models::external::gwconfig::{
    ExternalConfig, ExternalConfigBuilder, GwConfig, Underlay,
};
use crate::models::external::overlay::Overlay;
use crate::models::external::overlay::vpc::{Vpc, VpcTable};
use crate::models::external::overlay::vpcpeering::{VpcPeering, VpcPeeringTable};

use crate::models::internal::device::{
    DeviceConfig,
    settings::{DeviceSettings, DpdkPortConfig, KernelPacketConfig, PacketDriver},
};
use crate::models::internal::routing::vrf::VrfConfig;

// Import proto-generated types
use gateway_config::GatewayConfig;

// Helper Functions
//--------------------------------------------------------------------------------

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
    let vrf_config = VrfConfig::try_from(default_vrf)?;

    // Create Underlay with the VRF config
    Ok(Underlay { vrf: vrf_config })
}

/// Convert Overlay from gRPC
pub fn convert_overlay_from_grpc(overlay: &gateway_config::Overlay) -> Result<Overlay, String> {
    // Create VPC table
    let mut vpc_table = VpcTable::new();

    // Add VPCs
    for vpc_grpc in &overlay.vpcs {
        // Convert VPC
        let vpc = Vpc::try_from(vpc_grpc)?;

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
        let peering = VpcPeering::try_from(peering_grpc)?;

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

// Improved underlay conversion
pub fn convert_underlay_to_grpc(underlay: &Underlay) -> Result<gateway_config::Underlay, String> {
    // Convert the VRF
    let vrf_grpc = gateway_config::Vrf::try_from(&underlay.vrf)?;

    Ok(gateway_config::Underlay {
        vrfs: vec![vrf_grpc],
    })
}

/// Convert Overlay to gRPC
pub fn convert_overlay_to_grpc(overlay: &Overlay) -> Result<gateway_config::Overlay, String> {
    let mut vpcs = Vec::new();
    let mut peerings = Vec::new();

    // Convert VPCs
    for vpc in overlay.vpc_table.values() {
        let grpc_vpc = gateway_config::Vpc::try_from(vpc)?;
        vpcs.push(grpc_vpc);
    }

    // Convert peerings
    for peering in overlay.peering_table.values() {
        let grpc_peering = gateway_config::VpcPeering::try_from(peering)?;
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
