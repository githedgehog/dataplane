// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway configuration (external)
//! The external config contains the intended configuration externally received (e.g. via gRPC)

use derive_builder::Builder;
use std::time::SystemTime;
use tracing::{debug, info};

use crate::models::external::{ConfigError, ConfigResult};
use crate::models::internal::InternalConfig;
use crate::models::internal::device::DeviceConfig;
use crate::models::internal::routing::vrf::VrfConfig;
use crate::models::{external::overlay::Overlay, internal::device::settings::DeviceSettings};

use crate::frr::frrmi::FrrMi;
use crate::processor::confbuild::build_internal_config;

/// Alias for a config generation number
pub type GenId = i64;
use crate::processor::proc::apply_gw_config;

#[derive(Clone, Default)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
}
impl Underlay {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating underlay configuration...");

        // validate interfaces
        self.vrf
            .interfaces
            .values()
            .try_for_each(|iface| iface.validate())?;

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
#[derive(Builder, Clone)]
pub struct ExternalConfig {
    pub genid: GenId,         /* configuration generation id (version) */
    pub device: DeviceConfig, /* goes as-is into the internal config */
    pub underlay: Underlay,   /* goes as-is into the internal config */
    pub overlay: Overlay,     /* VPCs and peerings -- get highly developed in internal config */
}
impl ExternalConfig {
    pub const BLANK_GENID: GenId = 0;

    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            genid: Self::BLANK_GENID,
            device: DeviceConfig::new(DeviceSettings::new("Unset")),
            underlay: Underlay::default(),
            overlay: Overlay::default(),
        }
    }
    pub fn validate(&mut self) -> ConfigResult {
        self.device.validate()?;
        self.underlay.validate()?;
        self.overlay.validate()?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct GwConfig {
    pub meta: GwConfigMeta,               /* config metadata */
    pub external: ExternalConfig,         /* external config: received */
    pub internal: Option<InternalConfig>, /* internal config: built by gw from internal */
}

impl GwConfig {
    /// Create a [`GwConfig`] object with a given [`ExternalConfig`].
    pub fn new(external: ExternalConfig) -> Self {
        Self {
            meta: GwConfigMeta::new(),
            external,
            internal: None,
        }
    }
    /// Create a blank [`GwConfig`] with an empty [`ExternalConfig`].
    /// Such a config has generation id 0 (from the empty [`ExternalConfig`]).
    pub fn blank() -> Self {
        Self::new(ExternalConfig::new())
    }

    /// Return the [`GenId`] of a [`GwConfig`] object.
    pub fn genid(&self) -> GenId {
        self.external.genid
    }

    /// Validate a [`GwConfig`].
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating external config with genid {} ..", self.genid());
        self.external.validate()
    }

    /// Build the [`InternalConfig`] for this [`GwConfig`].
    pub fn build_internal_config(&mut self) -> ConfigResult {
        /* build and set internal config */
        self.internal = Some(build_internal_config(self)?);
        Ok(())
    }

    /// Apply a [`GwConfig`].
    pub async fn apply(&mut self, frrmi: &mut FrrMi) -> ConfigResult {
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
                Err(ConfigError::FailureApply)
            }
        }
    }
}
