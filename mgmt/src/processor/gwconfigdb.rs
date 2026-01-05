// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configuration database

use config::{GenId, GwConfig, GwConfigMeta};
use tracing::{debug, info};

/// Configuration database, keeps a set of [`GwConfig`]s keyed by generation id [`GenId`]
#[derive(Default)]
pub(crate) struct GwConfigDatabase {
    applied: Option<GwConfig>,  /* Currently applied config */
    history: Vec<GwConfigMeta>, /* event history */
}

impl GwConfigDatabase {
    #[must_use]
    pub fn new() -> Self {
        debug!("Building config database...");
        let mut configdb = Self::default();
        configdb.store(GwConfig::blank());
        configdb
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
    pub fn store(&mut self, config: GwConfig) {
        info!("Storing config for generation '{}' in db", config.genid());
        self.applied = Some(config);
    }

    /// Get the generation Id of the currently applied config, if any.
    #[must_use]
    pub fn get_current_gen(&self) -> Option<GenId> {
        self.applied.as_ref().map(|c| c.genid())
    }

    /// Get a reference to the config currently applied, if any.
    #[must_use]
    pub fn get_current_config(&self) -> Option<&GwConfig> {
        self.applied.as_ref()
    }

    /// Get a mutable reference to the config currently applied, if any.
    #[must_use]
    pub fn get_current_config_mut(&mut self) -> Option<&mut GwConfig> {
        self.applied.as_mut()
    }
}
