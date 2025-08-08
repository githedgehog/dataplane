// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;
use std::string::ToString;

use crate::external::underlay::Underlay;
use crate::internal::routing::vrf::VrfConfig;

impl TryFrom<&gateway_config::Underlay> for Underlay {
    type Error = String;

    fn try_from(underlay: &gateway_config::Underlay) -> Result<Self, Self::Error> {
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
        Ok(Underlay {
            vrf: vrf_config,
            vtep: None,
        })
    }
}

impl TryFrom<&Underlay> for gateway_config::Underlay {
    type Error = String;

    fn try_from(underlay: &Underlay) -> Result<Self, Self::Error> {
        // Convert the VRF
        let vrf_grpc = gateway_config::Vrf::try_from(&underlay.vrf)?;

        Ok(gateway_config::Underlay {
            vrfs: vec![vrf_grpc],
        })
    }
}
