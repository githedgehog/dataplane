// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_intf::gateway_agent_crd::GatewayAgent;

use crate::DeviceConfig;
use crate::converters::k8s::FromK8sConversionError;
use crate::external::communities::PriorityCommunityTable;
use crate::external::gwgroup::GwGroupTable;
use crate::external::overlay::Overlay;
use crate::external::underlay::Underlay;
use crate::external::{ExternalConfig, ExternalConfigBuilder};

/// Convert from `GatewayAgent` (k8s CRD) to `ExternalConfig` with default values
impl TryFrom<&GatewayAgent> for ExternalConfig {
    type Error = FromK8sConversionError;

    fn try_from(ga: &GatewayAgent) -> Result<Self, Self::Error> {
        let name = ga
            .metadata
            .name
            .as_ref()
            .ok_or(FromK8sConversionError::MissingData(
                "metadata.name not found".to_string(),
            ))?
            .as_str();

        let Some(gen_id) = ga.metadata.generation else {
            return Err(FromK8sConversionError::Invalid(format!(
                "metadata.generation not found for {name}"
            )));
        };

        let device = DeviceConfig::try_from(ga)?;
        let underlay = Underlay::try_from(ga.spec.gateway.as_ref().ok_or(
            FromK8sConversionError::MissingData(format!(
                "gateway section not found in spec for {name}"
            )),
        )?)?;
        let overlay = Overlay::try_from(&ga.spec)?;
        let gwgroup_table = GwGroupTable::try_from(&ga.spec)?;
        let comtable = PriorityCommunityTable::try_from(&ga.spec)?;

        let external_config = ExternalConfigBuilder::default()
            .genid(gen_id)
            .device(device)
            .underlay(underlay)
            .overlay(overlay)
            .gwgroups(gwgroup_table)
            .communities(comtable)
            .build()
            .map_err(|e| {
                FromK8sConversionError::InternalError(format!(
                    "Failed to build ExternalConfig for {name}: {e}"
                ))
            })?;
        Ok(external_config)
    }
}

#[cfg(test)]
mod test {
    use k8s_intf::bolero::LegalValue;
    use k8s_intf::gateway_agent_crd::GatewayAgent;

    use crate::ExternalConfig;

    #[test]
    fn test_gateway_config_conversion() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgent>>()
            .for_each(|ga| {
                let ga = ga.as_ref();
                let external_config = ExternalConfig::try_from(ga).unwrap();

                assert_eq!(external_config.genid, ga.metadata.generation.unwrap());
                // Other assertions are implicit via the unwrap of the conversion
            });
    }
}
