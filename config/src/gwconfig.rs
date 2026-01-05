// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Top-level configuration object for the dataplane

use crate::errors::{ConfigError, ConfigResult};
use crate::external::{ExternalConfig, GenId};
use crate::internal::InternalConfig;
use std::time::SystemTime;
use tracing::debug;

/// Metadata associated to a gateway configuration
#[derive(Clone, Debug)]
pub struct GwConfigMeta {
    // generation Id of a config
    pub genid: GenId,

    // time when a config was learnt
    pub create_t: SystemTime,

    // time when a config was applied
    pub apply_t: Option<SystemTime>,

    // error if configuration could not be applied
    pub error: Option<ConfigError>,
}
impl GwConfigMeta {
    ////////////////////////////////////////////////////////////////////////////////
    /// Build config metadata. This is automatically built when creating a `GwConfig`
    ////////////////////////////////////////////////////////////////////////////////
    #[must_use]
    fn new(genid: GenId) -> Self {
        Self {
            genid,
            create_t: SystemTime::now(),
            apply_t: None,
            error: None,
        }
    }
    ////////////////////////////////////////////////////////////////////////////////
    /// Set the time when attempting to apply a configuration finished, whether it
    /// succeeded or not.
    ////////////////////////////////////////////////////////////////////////////////
    pub fn apply_time(&mut self) {
        self.apply_t = Some(SystemTime::now());
    }

    ////////////////////////////////////////////////////////////////////////////////
    /// Set the `ConfigError` if a configuration failed to be applied.
    ////////////////////////////////////////////////////////////////////////////////
    pub fn error(&mut self, result: &ConfigResult) {
        self.error.take();
        if let Err(e) = result {
            self.error = Some(e.clone());
        }
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
    #[must_use]
    pub fn new(external: ExternalConfig) -> Self {
        Self {
            meta: GwConfigMeta::new(external.genid),
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
    #[must_use]
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
