// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_intf::gateway_agent_crd::GatewayAgent;

use crate::converters::k8s::FromK8sConversionError;
use crate::internal::device::DeviceConfig;
use crate::internal::device::settings::{DeviceSettings, KernelPacketConfig, PacketDriver};
use crate::internal::device::tracecfg::TracingConfig;

impl TryFrom<&GatewayAgent> for DeviceConfig {
    type Error = FromK8sConversionError;

    fn try_from(ga: &GatewayAgent) -> Result<Self, Self::Error> {
        // We don't really use this, we take the actual value from the CLI
        let driver = PacketDriver::Kernel(KernelPacketConfig {});

        // Create device settings
        let mut device_settings = DeviceSettings::new(ga.metadata.name.as_ref().ok_or(
            FromK8sConversionError::MissingData("metadata.name is required".to_string()),
        )?);
        device_settings = device_settings.set_packet_driver(driver);

        // Create DeviceConfig with these settings
        // Note: PortConfig is not yet implemented, so we don't add any ports
        let mut device_config = DeviceConfig::new(device_settings);

        if let Some(logs) = &ga
            .spec
            .gateway
            .as_ref()
            .ok_or(FromK8sConversionError::MissingData(
                "gateway section is required".to_string(),
            ))?
            .logs
        {
            device_config.set_tracing(TracingConfig::try_from(logs)?);
        }
        Ok(device_config)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use k8s_intf::bolero::LegalValue;

    #[test]
    fn test_simple_hostname() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgent>>()
            .for_each(|ga| {
                let ga = ga.as_ref();
                let dev = DeviceConfig::try_from(ga).unwrap();
                assert_eq!(&dev.settings.hostname, ga.metadata.name.as_ref().unwrap());
                assert!(matches!(
                    &dev.settings.driver,
                    &PacketDriver::Kernel(KernelPacketConfig {})
                ));
                // Make sure we set tracing, the conversion is tested as part of the `TraceConfig` conversion
                assert_eq!(
                    ga.spec.gateway.as_ref().unwrap().logs.is_some(),
                    dev.tracing.is_some()
                );
            });
    }
}
