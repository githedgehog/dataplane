// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ::gateway_config::config as gateway_config;
use gateway_config::TracingConfig as ApiTracingConfig;

use crate::internal::device::{
    DeviceConfig,
    settings::{DeviceSettings, DpdkPortConfig, KernelPacketConfig, PacketDriver},
    tracecfg::TracingConfig,
};

impl TryFrom<&gateway_config::Device> for DeviceConfig {
    type Error = String;

    fn try_from(device: &gateway_config::Device) -> Result<Self, Self::Error> {
        // Convert driver enum
        let driver = match ::gateway_config::PacketDriver::try_from(device.driver) {
            Ok(::gateway_config::PacketDriver::Kernel) => {
                PacketDriver::Kernel(KernelPacketConfig {})
            }
            Ok(::gateway_config::PacketDriver::Dpdk) => PacketDriver::DPDK(DpdkPortConfig {}),
            Err(_) => return Err(format!("Invalid driver value: {}", device.driver)),
        };

        // Create device settings
        let mut device_settings = DeviceSettings::new(&device.hostname);
        device_settings = device_settings.set_packet_driver(driver);

        // Create DeviceConfig with these settings
        // Note: PortConfig is not yet implemented, so we don't add any ports
        let mut device_config = DeviceConfig::new(device_settings);

        if let Some(tracing) = &device.tracing {
            device_config.set_tracing(TracingConfig::try_from(tracing)?);
        }
        Ok(device_config)
    }
}

impl TryFrom<&DeviceConfig> for gateway_config::Device {
    type Error = String;

    fn try_from(device: &DeviceConfig) -> Result<Self, Self::Error> {
        let driver = match device.settings.driver {
            PacketDriver::Kernel(_) => ::gateway_config::PacketDriver::Kernel,
            PacketDriver::DPDK(_) => ::gateway_config::PacketDriver::Dpdk,
        };

        // Convert ports if available
        let ports = Vec::new(); // TODO: Implement port conversion when needed
        let tracing = device.tracing.as_ref().map(ApiTracingConfig::from);

        Ok(gateway_config::Device {
            driver: driver.into(),
            hostname: device.settings.hostname.clone(),
            eal: None, // TODO: Handle EAL configuration when needed
            ports,
            tracing,
        })
    }
}
