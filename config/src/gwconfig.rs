// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Top-level configuration object for the dataplane

use crate::errors::{ConfigError, ConfigResult};
use crate::external::{ExternalConfig, GenId, ValidatedExternalConfig};
use crate::internal::InternalConfig;
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::debug;

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
    pub fn new(genid: GenId) -> Self {
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
    /// Configuration metadata
    pub meta: ArcSwap<GwConfigMeta>,

    /// Configuration, as received
    pub external: ExternalConfig,

    /// Configuration built from the external
    pub internal: Option<InternalConfig>,
}

impl GwConfig {
    //////////////////////////////////////////////////////////////////
    /// Create a [`GwConfig`] object with a given [`ExternalConfig`].
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn new(external: ExternalConfig) -> Self {
        Self {
            meta: ArcSwap::new(Arc::from(GwConfigMeta::new(external.genid))),
            external,
            internal: None,
        }
    }

    //////////////////////////////////////////////////////////////////
    /// Create a blank [`GwConfig`] with an empty [`ExternalConfig`].
    //////////////////////////////////////////////////////////////////
    #[must_use]
    pub fn blank() -> Self {
        Self::new(ExternalConfig::new(""))
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

    /// Validate a [`GwConfig`]. We only validate the external.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if the external configuration fails validation.
    pub fn validate(self) -> Result<ValidatedGwConfig, ConfigError> {
        debug!("Validating external config with genid {} ..", self.genid());
        let validated_external = self.external.validate()?;

        Ok(ValidatedGwConfig {
            meta: self.meta,
            external: validated_external,
            internal: self.internal.clone(),
        })
    }

    /// FOR TESTS ONLY. Fake validation for the config.
    ///
    /// # Safety
    ///
    /// All bets are off. Do not use outside of tests.
    #[cfg(feature = "testing")]
    #[allow(unsafe_code)]
    #[must_use]
    pub unsafe fn fake_validated_config_for_tests(self) -> ValidatedGwConfig {
        let fake_valid_external = unsafe { self.external.fake_validated_external_for_tests() };

        ValidatedGwConfig {
            meta: self.meta,
            external: fake_valid_external,
            internal: self.internal.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ValidatedGwConfig {
    meta: ArcSwap<GwConfigMeta>,
    external: ValidatedExternalConfig,
    internal: Option<InternalConfig>,
}

impl ValidatedGwConfig {
    #[must_use]
    pub fn blank() -> Self {
        // The blank config has no overlay, peerings, or VPCs, so it trivially passes validation.
        // A unit test verifies this invariant.
        let external = ValidatedExternalConfig::blank();
        Self {
            meta: ArcSwap::new(Arc::from(GwConfigMeta::new(external.genid()))),
            external,
            internal: None,
        }
    }

    #[must_use]
    pub fn meta(&self) -> &ArcSwap<GwConfigMeta> {
        &self.meta
    }

    #[must_use]
    pub fn external(&self) -> &ValidatedExternalConfig {
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
    use crate::GwConfig;

    #[test]
    fn test_blank_config_is_valid() {
        let _ = GwConfig::blank()
            .validate()
            .expect("Failed to validate blank config");
    }
}
