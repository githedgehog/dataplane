// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Top-level configuration object for the dataplane

use crate::errors::ConfigResult;
use crate::external::{ExternalConfig, GenId};
use crate::internal::InternalConfig;
use std::time::SystemTime;
use tracing::debug;

/// Metadata associated to a gateway configuration
#[derive(Clone, Debug)]
pub struct GwConfigMeta {
    pub create_t: SystemTime,        /* time when config was built (received) */
    pub apply_t: Option<SystemTime>, /* last time when config was applied successfully */
    pub replace_t: Option<SystemTime>, /* time when config was un-applied */
    pub replacement: Option<GenId>,  /* Id of config that replaced this one */
    pub is_applied: bool,            /* True if the config is currently applied */
}
impl GwConfigMeta {
    ////////////////////////////////////////////////////////////////////////////////
    /// Build config metadata. This is automatically built when creating a `GwConfig
    ////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    fn new() -> Self {
        Self {
            create_t: SystemTime::now(),
            apply_t: None,
            replace_t: None,
            replacement: None,
            is_applied: false,
        }
    }
    ////////////////////////////////////////////////////////////////////////////////
    /// Set the state of this config. The management processor will always be responsible
    /// for setting this, regardless of how it stores the configurations. The metadata
    /// is included here in case other components needed some of its data.
    ////////////////////////////////////////////////////////////////////////////////
    pub fn set_state(&mut self, genid: GenId, value: bool, replacement: Option<GenId>) {
        if value {
            self.apply_t = Some(SystemTime::now());
            self.replace_t.take();
            self.replacement.take();
            debug!("Config {genid} has been marked as active");
        } else {
            self.replace_t = Some(SystemTime::now());
            self.replacement = replacement;
            debug!("Config {genid} has been marked as inactive");
        }
        self.is_applied = value;
    }
}

#[derive(Clone, Debug)]
pub struct GwConfig {
    pub meta: GwConfigMeta,               /* config metadata */
    pub external: ExternalConfig,         /* external config: received */
    pub internal: Option<InternalConfig>, /* internal config: built by gw from internal */
}

impl GwConfig {
    //////////////////////////////////////////////////////////////////
    /// Create a [`GwConfig`] object with a given [`ExternalConfig`].
    //////////////////////////////////////////////////////////////////
    pub fn new(external: ExternalConfig) -> Self {
        Self {
            meta: GwConfigMeta::new(),
            external,
            internal: None,
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Create a blank [`GwConfig`] with an empty [`ExternalConfig`].
    /// Such a config has generation id 0
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn blank() -> Self {
        Self::new(ExternalConfig::new())
    }

    //////////////////////////////////////////////////////////////////
    /// Set an internal config object, once built.
    //////////////////////////////////////////////////////////////////
    pub fn set_internal_config(&mut self, internal: InternalConfig) {
        self.internal = Some(internal);
    }

    //////////////////////////////////////////////////////////////////
    /// Return the [`GenId`] of a [`GwConfig`] object.
    //////////////////////////////////////////////////////////////////
    pub fn genid(&self) -> GenId {
        self.external.genid
    }

    //////////////////////////////////////////////////////////////////
    /// Validate a [`GwConfig`]. We only validate the external.
    //////////////////////////////////////////////////////////////////
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating external config with genid {} ..", self.genid());
        self.external.validate()
    }
}
