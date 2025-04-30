// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway configuration (external)
//! The external config contains the intended configuration externally received (e.g. via gRPC)

use derive_builder::Builder;
use std::time::SystemTime;
use tracing::{debug, info, warn};

use crate::models::external::overlay::Overlay;
use crate::models::external::{ApiError, ApiResult};
use crate::models::internal::InternalConfig;
use crate::models::internal::device::DeviceConfig;
use crate::models::internal::routing::vrf::VrfConfig;

use crate::frr::frrmi::FrrMi;
use crate::processor::confbuild::build_internal_config;

/// Alias for a config generation number
pub type GenId = u64;
use crate::processor::proc::apply_gw_config;

#[derive(Clone)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
}
impl Underlay {
    pub fn validate(&self) -> ApiResult {
        warn!("Validating underlay configuration (TODO)");
        Ok(())
    }
}

#[derive(Clone)]
/// Configuration metadata. Every config object stored by the dataplane has metadata
pub struct GwConfigMeta {
    pub created: SystemTime,         /* time when config was built (received) */
    pub applied: Option<SystemTime>, /* last time when config was applied successfully */
    pub is_applied: bool,            /* True if the config is currently applied */
}
impl GwConfigMeta {
    fn new() -> Self {
        Self {
            created: SystemTime::now(),
            applied: None,
            is_applied: false,
        }
    }
}

/// The configuration object as seen by the gRPC server
#[derive(Builder)]
pub struct ExternalConfig {
    pub genid: GenId,         /* configuration generation id (version) */
    pub device: DeviceConfig, /* goes as-is into the internal config */
    pub underlay: Underlay,   /* goes as-is into the internal config */
    pub overlay: Overlay,     /* VPCs and peerings -- get highly developed in internal config */
}
impl ExternalConfig {
    pub fn validate(&mut self) -> ApiResult {
        self.device.validate()?;
        self.underlay.validate()?;
        self.overlay.validate()?;
        Ok(())
    }
}

pub struct GwConfig {
    pub meta: GwConfigMeta,               /* config metadata */
    pub external: ExternalConfig,         /* external config: received */
    pub internal: Option<InternalConfig>, /* internal config: built by gw from internal */
}

impl GwConfig {
    pub fn new(external: ExternalConfig) -> Self {
        Self {
            meta: GwConfigMeta::new(),
            external,
            internal: None,
        }
    }
    pub fn genid(&self) -> GenId {
        self.external.genid
    }

    /// Validate a [`GwConfig`]
    pub fn validate(&mut self) -> ApiResult {
        debug!("Validating external config with genid {} ..", self.genid());
        self.external.validate()
    }

    /// Build the [`InternalConfig`] for this [`GwConfig`]
    pub fn build_internal_config(&mut self) -> ApiResult {
        /* build and set internal config */
        self.internal = Some(build_internal_config(self)?);
        Ok(())
    }

    /// Apply a [`GwConfig`]
    pub async fn apply(&mut self, frrmi: &FrrMi) -> ApiResult {
        info!("Applying config with genid {}...", self.genid());
        if self.internal.is_none() {
            debug!("Config has no internal config...");
            self.build_internal_config()?;
        }

        /* Apply this gw config */
        match apply_gw_config(self, frrmi).await {
            Ok(()) => {
                self.meta.applied = Some(SystemTime::now());
                self.meta.is_applied = true;
                Ok(())
            }
            Err(e) => {
                info!("Failed to apply config {}: {e}", self.genid());
                Err(ApiError::FailureApply)
            }
        }
    }
}
