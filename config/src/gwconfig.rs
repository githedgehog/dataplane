// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Top-level configuration object for the dataplane

use crate::errors::{ConfigError, ConfigResult};
use crate::external::{ExternalConfig, GenId};
use crate::internal::InternalConfig;
use concurrency::slot::Slot;
use concurrency::sync::Arc;
use std::time::SystemTime;

/// Metadata associated to a gateway configuration
#[derive(Clone, Debug)]
pub struct GwConfigMeta {
    /// generation Id of a config
    pub genid: GenId,

    /// time when a config was created/learnt
    pub create_t: SystemTime,

    /// time when a config was applied
    pub apply_t: Option<SystemTime>,

    /// error if configuration could not be applied
    pub error: Option<ConfigError>,

    /// whether this config was applied as a rollback
    pub is_rollback: bool,
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
            is_rollback: false,
        }
    }
    ////////////////////////////////////////////////////////////////////////////////
    /// Set the time when attempting to apply a configuration finished.
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

#[derive(Debug)]
pub struct GwConfig {
    meta: Slot<GwConfigMeta>,
    external: ExternalConfig,
    internal: Option<InternalConfig>,
}

impl GwConfig {
    #[must_use]
    pub(crate) fn new(external: ExternalConfig) -> Self {
        Self {
            meta: Slot::new(Arc::from(GwConfigMeta::new(external.genid()))),
            external,
            internal: None,
        }
    }
    #[must_use]
    /// Build an empty [`GwConfig`] from an empty [`ExternalConfig`].
    /// An empty [`ExternalConfig`] should always be valid. A unit test verifies this invariant.
    pub fn blank() -> Self {
        Self::from_external(ExternalConfig::new("")).unwrap_or_else(|_| unreachable!())
    }

    /// Consume an [`ExternalConfig`] to obtain a [`GwConfig`], which is validated by definition.
    /// This is the only way to obtain a non-blank [`GwConfig`].
    ///
    /// # Errors
    ///    This method returns `ConfigError` if the external config fails to validate
    pub fn from_external(mut external: ExternalConfig) -> Result<Self, ConfigError> {
        external.validate()?;
        Ok(Self::new(external))
    }

    #[must_use]
    pub fn meta(&self) -> &Slot<GwConfigMeta> {
        &self.meta
    }

    #[must_use]
    pub fn external(&self) -> &ExternalConfig {
        &self.external
    }

    #[must_use]
    pub fn internal(&self) -> Option<&InternalConfig> {
        self.internal.as_ref()
    }

    pub fn set_internal_config(&mut self, internal: InternalConfig) {
        self.internal = Some(internal);
    }

    #[must_use]
    pub fn genid(&self) -> GenId {
        self.external.genid()
    }
}

#[cfg(test)]
mod tests {
    use crate::ExternalConfig;

    #[test]
    fn test_blank_config_is_valid() {
        ExternalConfig::new("")
            .validate()
            .expect("Failed to validate blank config");
    }
}
