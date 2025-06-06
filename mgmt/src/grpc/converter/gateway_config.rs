// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use tracing::warn;

use crate::models::external::gwconfig::{
    ExternalConfig, ExternalConfigBuilder, GwConfig, Underlay,
};
use crate::models::external::overlay::Overlay;
use crate::models::internal::device::{DeviceConfig, settings::DeviceSettings};

// Helper Functions
//--------------------------------------------------------------------------------

/// Create a new `GwConfig` from `ExternalConfig`
pub fn create_gw_config(external_config: ExternalConfig) -> GwConfig {
    GwConfig::new(external_config)
}

/// Convert from `GatewayConfig` (gRPC) to `ExternalConfig` with default values
pub fn convert_gateway_config_from_grpc_with_defaults(
    grpc_config: &gateway_config::GatewayConfig,
) -> Result<ExternalConfig, String> {
    // convert device if present or provide a default
    let device_config = if let Some(device) = &grpc_config.device {
        DeviceConfig::try_from(device)?
    } else {
        warn!("Missing device configuration!");
        DeviceConfig::new(DeviceSettings::new("Unset"))
    };

    // convert underlay or provide a default (empty)
    let underlay_config = if let Some(underlay) = &grpc_config.underlay {
        Underlay::try_from(underlay)?
    } else {
        warn!("Missing underlay configuration!");
        Underlay::default()
    };

    // convert overlay or provide a default (empty)
    let overlay_config = if let Some(overlay) = &grpc_config.overlay {
        Overlay::try_from(overlay)?
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

impl TryFrom<&gateway_config::GatewayConfig> for ExternalConfig {
    type Error = String;

    fn try_from(grpc_config: &gateway_config::GatewayConfig) -> Result<Self, Self::Error> {
        // convert device if present or provide a default
        let device_config = if let Some(device) = &grpc_config.device {
            DeviceConfig::try_from(device)
        } else {
            Err("Missing device configuration!".to_string())
        }?;

        // convert underlay or provide a default (empty)
        let underlay_config = if let Some(underlay) = &grpc_config.underlay {
            Underlay::try_from(underlay)
        } else {
            Err("Missing underlay configuration!".to_string())
        }?;

        // convert overlay or provide a default (empty)
        let overlay_config = if let Some(overlay) = &grpc_config.overlay {
            Overlay::try_from(overlay)
        } else {
            Err("Missing overlay configuration!".to_string())
        }?;

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
}

impl TryFrom<&ExternalConfig> for gateway_config::GatewayConfig {
    type Error = String;

    fn try_from(external_config: &ExternalConfig) -> Result<Self, Self::Error> {
        // Convert device config
        let device = gateway_config::Device::try_from(&external_config.device)?;

        // Convert underlay config
        let underlay = gateway_config::Underlay::try_from(&external_config.underlay)?;

        // Convert overlay config
        let overlay = gateway_config::Overlay::try_from(&external_config.overlay)?;

        // Create the complete gRPC config
        Ok(gateway_config::GatewayConfig {
            generation: external_config.genid,
            device: Some(device),
            underlay: Some(underlay),
            overlay: Some(overlay),
        })
    }
}
