// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway configuration (external)
//! The external config contains the intended configuration externally received (e.g. via gRPC)

use std::time::SystemTime;
use tracing::{debug, info, warn};

use crate::models::external::overlay::Overlay;
use crate::models::external::{ApiError, ApiResult};
use crate::models::internal::InternalConfig;
use crate::models::internal::device::DeviceConfig;
use crate::models::internal::routing::vrf::VrfConfig;

#[allow(unused)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
}
impl Underlay {
    pub fn validate(&self) -> ApiResult {
        warn!("Validating underlay configuration (TODO");
        Ok(())
    }
}

/// Configuration metadata. Every config object stored by the dataplane has metadata
pub struct GwConfigMeta {
    pub generation: u64,             /* configuration version */
    pub created: SystemTime,         /* time when config was built (received) */
    pub applied: Option<SystemTime>, /* last time when config was applied successfully */
    pub is_applied: bool,            /* True if the config is currently applied */
}
impl GwConfigMeta {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            created: SystemTime::now(),
            applied: None,
            is_applied: false,
        }
    }
}

#[allow(unused)]
/// The configuration object as seen by the gRPC server
pub struct GwConfig {
    pub meta: GwConfigMeta,               /* config metadata */
    pub device: Option<DeviceConfig>,     /* goes as-is into the internal config */
    pub underlay: Option<Underlay>,       /* goes as-is into the internal config */
    pub overlay: Option<Overlay>, /* VPCs and peerings -- get highly developed in internal config */
    pub internal: Option<InternalConfig>, /* Built internal configuration */
}

impl GwConfig {
    pub fn new(generation: u64) -> Self {
        Self {
            meta: GwConfigMeta::new(generation),
            device: None,
            underlay: None,
            overlay: None,
            internal: None,
        }
    }
    pub fn set_device(&mut self, device: DeviceConfig) {
        self.device = Some(device);
    }
    pub fn set_underlay(&mut self, underlay: Underlay) {
        self.underlay = Some(underlay);
    }
    pub fn set_overlay(&mut self, overlay: Overlay) {
        self.overlay = Some(overlay);
    }

    /// Validate a [`GwConfig`]
    pub fn validate(&mut self) -> ApiResult {
        debug!("Validating config {} ..", self.meta.generation);
        if let Some(device) = &self.device {
            device.validate()?;
        } else {
            return Err(ApiError::IncompleteConfig("device"));
        }
        if let Some(underlay) = &self.underlay {
            underlay.validate()?;
        } else {
            return Err(ApiError::IncompleteConfig("underlay"));
        }
        if let Some(overlay) = &mut self.overlay {
            overlay.vpc_table.collect_peerings(&overlay.peering_table);
            overlay.validate()?;
        } else {
            return Err(ApiError::IncompleteConfig("overlay"));
        }
        Ok(())
    }

    /// Build the [`InternalConfig`] for this [`GwConfig`]
    pub fn build_internal_config(&mut self) -> ApiResult {
        debug!(
            "Building internal config for config {} ..",
            self.meta.generation
        );
        // Build internal config object
        let mut internal = InternalConfig::new();

        // Device config goes into internal config as-is
        if let Some(device) = &self.device {
            internal.set_device_config(&device.clone());
        } else {
            panic!("Missing device configuration");
        }

        // Underlay config goes into internal config as-is
        if let Some(underlay) = &self.underlay {
            internal.add_vrf_config(underlay.vrf.clone());
        } else {
            panic!("Missing underlay configuration");
        }

        // Build internal config for overlay config
        if let Some(_overlay) = &self.overlay {
            //TODO: build the internal config
            warn!("Building internal configuration for overlays...");
        } else {
            panic!("Missing overlay configuration");
        }

        // set the internal config
        self.internal = Some(internal);
        info!("Internal config built for {}", self.meta.generation);
        Ok(())
    }

    /// Apply a [`GwConfig`]
    pub fn apply(&mut self) -> ApiResult {
        info!("Applying config {}...", self.meta.generation);
        if self.internal.is_none() {
            debug!("Config has no internal config...");
            self.build_internal_config()?;
        }

        /*
            TODO: apply internal configuration
        */
        let success = true;
        if success {
            self.meta.applied = Some(SystemTime::now());
            self.meta.is_applied = true;
            info!("Applied config {}", self.meta.generation);
            Ok(())
        } else {
            info!("Failed to apply config {}", self.meta.generation);
            Err(ApiError::FailureApply)
        }
    }
}
