// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use k8s_intf::gateway_agent_crd::{GatewayAgent, GatewayAgentSpec};

use crate::converters::k8s::FromK8sConversionError;
use crate::external::communities::PriorityCommunityTable;
use crate::external::gwgroup::GwGroupTable;
use crate::external::overlay::Overlay;
use crate::external::underlay::Underlay;
use crate::external::{ExternalConfig, ExternalConfigBuilder};
use crate::{DeviceConfig, GenId};

/// A struct synthesizing the data we get from k8s
pub struct K8sInput {
    pub gwname: String,
    pub genid: GenId,
    pub spec: GatewayAgentSpec,
}

/// Validate the metadata of a `GatewayAgent`.
/// # Errors
/// Returns `FromK8sConversionError` in case data is missing or is invalid
fn validate_metadata(ga: &GatewayAgent) -> Result<K8sInput, FromK8sConversionError> {
    let genid = ga
        .metadata
        .generation
        .ok_or(FromK8sConversionError::K8sInfra(
            "Missing metadata generation Id".to_string(),
        ))?;

    if genid == 0 {
        return Err(FromK8sConversionError::K8sInfra(
            "Invalid metadata generation Id".to_string(),
        ));
    }

    let gwname = ga
        .metadata
        .name
        .as_ref()
        .ok_or(FromK8sConversionError::K8sInfra(
            "Missing metadata gateway name".to_string(),
        ))?;

    if gwname.is_empty() {
        return Err(FromK8sConversionError::K8sInfra(
            "Empty gateway name".to_string(),
        ));
    }
    let namespace = ga
        .metadata
        .namespace
        .as_ref()
        .ok_or(FromK8sConversionError::K8sInfra(
            "Missing namespace".to_string(),
        ))?;

    if namespace.as_str() != "default" {
        return Err(FromK8sConversionError::K8sInfra(format!(
            "Invalid namespace {namespace}"
        )));
    }

    let _ = ga
        .spec
        .gateway
        .as_ref()
        .ok_or(FromK8sConversionError::K8sInfra(format!(
            "Missing gateway section in spec for gateway {gwname}"
        )))?;

    let spec = K8sInput {
        gwname: gwname.clone(),
        genid,
        spec: ga.spec.clone(),
    };

    Ok(spec)
}

/// Convert from `GatewayAgent` (k8s CRD) to `ExternalConfig` with default values
impl TryFrom<&GatewayAgent> for ExternalConfig {
    type Error = FromK8sConversionError;

    fn try_from(ga: &GatewayAgent) -> Result<Self, Self::Error> {
        let input = validate_metadata(ga)?;

        let ga_spec_gw = input
            .spec
            .gateway
            .as_ref()
            .unwrap_or_else(|| unreachable!());

        let device = DeviceConfig::try_from(ga_spec_gw)?;
        let mut underlay = Underlay::try_from(ga_spec_gw)?;

        // fabricBFD variable check: enable BFD on fabric-facing BGP neighbors
        let fabric_bfd_enabled = ga
            .spec
            .config
            .as_ref()
            .and_then(|c| c.fabric_bfd)
            .unwrap_or(false);

        if fabric_bfd_enabled && let Some(bgp) = underlay.vrf.bgp.as_mut() {
            for neigh in &mut bgp.neighbors {
                neigh.bfd = true;
            }
        }

        let overlay = Overlay::try_from(&ga.spec)?;
        let gwgroup_table = GwGroupTable::try_from(&ga.spec)?;
        let comtable = PriorityCommunityTable::try_from(&ga.spec)?;

        let external_config = ExternalConfigBuilder::default()
            .gwname(input.gwname.clone())
            .genid(input.genid)
            .device(device)
            .underlay(underlay)
            .overlay(overlay)
            .gwgroups(gwgroup_table)
            .communities(comtable)
            .build()
            .map_err(|e| {
                FromK8sConversionError::InternalError(format!(
                    "Failed to translate configuration for gateway {}: {e}",
                    input.gwname
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
