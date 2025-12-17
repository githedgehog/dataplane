// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use ::gateway_config::config as gateway_config;
use gateway_config::TracingConfig as ApiTracingConfig;

use crate::internal::device::{DeviceConfig, tracecfg::TracingConfig};

impl TryFrom<&gateway_config::Device> for DeviceConfig {
    type Error = String;

    fn try_from(device: &gateway_config::Device) -> Result<Self, Self::Error> {
        // Create DeviceConfig
        let mut device_config = DeviceConfig::new();
        if let Some(tracing) = &device.tracing {
            device_config.set_tracing(TracingConfig::try_from(tracing)?);
        }
        Ok(device_config)
    }
}

impl TryFrom<&DeviceConfig> for gateway_config::Device {
    type Error = String;

    fn try_from(device: &DeviceConfig) -> Result<Self, Self::Error> {
        let tracing = device.tracing.as_ref().map(ApiTracingConfig::from);

        Ok(gateway_config::Device { tracing })
    }
}
