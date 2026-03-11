// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configuration database

use crate::processor::confbuild::internal::build_internal_config;
use crate::processor::display::ConfigHistory;
use config::{ExternalConfig, GenId, GwConfig, GwConfigMeta};
use std::sync::Arc;
use tracing::{debug, info};

/// Configuration database, keeps a set of [`GwConfig`]s keyed by generation id [`GenId`]
pub(crate) struct GwConfigDatabase {
    applied: Arc<GwConfig>,     /* Currently applied config or blank */
    history: Vec<GwConfigMeta>, /* event history */
}

impl GwConfigDatabase {
    #[must_use]
    pub fn new() -> Self {
        debug!("Building config database...");
        let mut blank = GwConfig::blank();
        let internal = build_internal_config(&blank, None).unwrap_or_else(|_| unreachable!());
        blank.set_internal_config(internal);
        GwConfigDatabase {
            applied: Arc::from(blank),
            history: vec![],
        }
    }

    pub fn log(&self) {
        let history = ConfigHistory(self);
        info!("\n{history}");
    }

    #[must_use]
    pub fn history(&self) -> &Vec<GwConfigMeta> {
        &self.history
    }

    #[must_use]
    pub fn history_mut(&mut self) -> &mut Vec<GwConfigMeta> {
        &mut self.history
    }

    /// Store the given config
    pub fn store(&mut self, config: Arc<GwConfig>) {
        info!("Storing config for generation '{}' in db", config.genid());
        self.applied = config;
    }

    /// Get a refcounted reference to the applied `GwConfig`
    pub fn get_applied(&self) -> Arc<GwConfig> {
        self.applied.clone()
    }

    /// Get the generation Id of the currently applied config, if any.
    #[must_use]
    pub fn get_current_gen(&self) -> Option<GenId> {
        self.get_current_config().map(|c| c.genid())
    }

    /// Get a reference to the config currently applied, if any.
    #[must_use]
    pub fn get_current_config(&self) -> Option<Arc<GwConfig>> {
        if self.applied.genid() == ExternalConfig::BLANK_GENID {
            None
        } else {
            Some(Arc::clone(&self.applied))
        }
    }
}
