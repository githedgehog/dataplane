// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_intf::gateway_agent_crd::GatewayAgentGateway;

use crate::converters::k8s::FromK8sConversionError;
use crate::internal::device::DeviceConfig;
use crate::internal::device::tracecfg::TracingConfig;

impl TryFrom<&GatewayAgentGateway> for DeviceConfig {
    type Error = FromK8sConversionError;

    fn try_from(gagw: &GatewayAgentGateway) -> Result<Self, Self::Error> {
        let mut device_config = DeviceConfig::new();
        if let Some(logs) = &gagw.logs {
            device_config.set_tracing(TracingConfig::try_from(logs)?);
        }
        Ok(device_config)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use k8s_intf::bolero::LegalValue;
    use k8s_intf::gateway_agent_crd::GatewayAgent;

    #[test]
    fn test_simple_hostname() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgent>>()
            .for_each(|ga| {
                let ga = ga.as_ref();
                if let Some(gw_agent_gw) = &ga.spec.gateway {
                    let dev = DeviceConfig::try_from(gw_agent_gw).unwrap();
                    // Make sure we set tracing, the conversion is tested as part of the `TraceConfig` conversion
                    assert_eq!(
                        ga.spec.gateway.as_ref().unwrap().logs.is_some(),
                        dev.tracing.is_some()
                    );
                }
            });
    }
}
