// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway configuration (external)
//! The external config contains the intended configuration externally received (e.g. via gRPC)

use std::time::SystemTime;
use tracing::info;

use crate::config::device::DeviceConfig;
use crate::config::routing::vrf::VrfConfig;
use crate::rpc::overlay::Overlay;
use crate::rpc::{ApiError, ApiResult};

#[allow(unused)]
pub struct Underlay {
    vrf: VrfConfig, /* default vrf */
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
    pub meta: GwConfigMeta,           /* config metadata */
    pub device: Option<DeviceConfig>, /* goes as-is into the internal config */
    pub underlay: Option<Underlay>,   /* goes as-is into the internal config */
    pub overlay: Option<Overlay>, /* VPCs and peerings -- get highly developed in internal config */
}

impl GwConfig {
    pub fn new(generation: u64) -> Self {
        Self {
            meta: GwConfigMeta::new(generation),
            device: None,
            underlay: None,
            overlay: None,
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
    pub fn apply(&mut self) -> ApiResult {
        info!("Applying config {}...", self.meta.generation);
        let success: bool = true;
        /*
            TODO:
              - build internal configuration
              - apply internal configuration
        */
        if success {
            self.meta.is_applied = true;
            self.meta.applied = Some(SystemTime::now());
            info!("Applied config {}", self.meta.generation);
            Ok(())
        } else {
            info!("Failed to apply config {}", self.meta.generation);
            Err(ApiError::FailureApply)
        }
    }
}
