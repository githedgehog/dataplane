// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ::gateway_config::config as gateway_config;
use tracing::Level;

use crate::internal::device::{
    DeviceConfig,
    settings::{DeviceSettings, DpdkPortConfig, KernelPacketConfig, PacketDriver},
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
        // Convert log level enum
        let loglevel = match gateway_config::LogLevel::try_from(device.loglevel) {
            Ok(::gateway_config::LogLevel::Error) => Level::ERROR,
            Ok(::gateway_config::LogLevel::Warning) => Level::WARN,
            Ok(::gateway_config::LogLevel::Info) => Level::INFO,
            Ok(::gateway_config::LogLevel::Debug) => Level::DEBUG,
            Ok(::gateway_config::LogLevel::Trace) => Level::TRACE,
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
}

impl TryFrom<&DeviceConfig> for gateway_config::Device {
    type Error = String;

    fn try_from(device: &DeviceConfig) -> Result<Self, Self::Error> {
        let driver = match device.settings.driver {
            PacketDriver::Kernel(_) => ::gateway_config::PacketDriver::Kernel,
            PacketDriver::DPDK(_) => ::gateway_config::PacketDriver::Dpdk,
        };

        let loglevel = match device.settings.loglevel {
            Level::ERROR => ::gateway_config::LogLevel::Error,
            Level::WARN => ::gateway_config::LogLevel::Warning,
            Level::INFO => ::gateway_config::LogLevel::Info,
            Level::DEBUG => ::gateway_config::LogLevel::Debug,
            Level::TRACE => ::gateway_config::LogLevel::Trace,
        };

        // Convert ports if available
        let ports = Vec::new(); // TODO: Implement port conversion when needed

        Ok(gateway_config::Device {
            driver: driver.into(),
            hostname: device.settings.hostname.clone(),
            loglevel: loglevel.into(),
            eal: None, // TODO: Handle EAL configuration when needed
            ports,
        })
    }
}
