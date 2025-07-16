// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configuration database: entity able to store multiple gateway configurations

use config::{ConfigError, ConfigResult, ExternalConfig, GenId, GwConfig};
use std::collections::BTreeMap;
use tracing::{debug, error, info};

#[derive(Default)]
#[allow(unused)]
/// Configuration database, keeps a set of [`GwConfig`]s keyed by generation id [`GenId`]
pub struct GwConfigDatabase {
    configs: BTreeMap<GenId, GwConfig>, /* collection of configs */
    current: Option<GenId>,             /* [`GenId`] of currently applied config */
}

impl GwConfigDatabase {
    #[must_use]
    pub fn new() -> Self {
        debug!("Building config database...");
        let mut configdb = Self::default();
        configdb.add(GwConfig::blank());
        configdb
    }
    pub fn add(&mut self, config: GwConfig) {
        debug!("Storing config '{}' in config db...", config.genid());
        self.configs.insert(config.external.genid, config);
    }

    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.configs.len()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&GenId, &GwConfig)> {
        self.configs.iter()
    }
    #[must_use]
    pub fn get(&self, genid: GenId) -> Option<&GwConfig> {
        self.configs.get(&genid)
    }
    pub fn contains(&self, genid: GenId) -> bool {
        self.configs.contains_key(&genid)
    }
    pub fn get_mut(&mut self, generation: GenId) -> Option<&mut GwConfig> {
        self.configs.get_mut(&generation)
    }
    pub fn remove(&mut self, genid: GenId) -> ConfigResult {
        if genid == ExternalConfig::BLANK_GENID {
            debug!("Will not remove config {genid} as it is protected");
            return Ok(());
        }
        debug!("Removing config '{genid}' from config db...");
        if let Some(config) = &self.configs.get(&genid) {
            if config.meta.is_applied {
                error!("Can't remove config {genid}: in use");
                Err(ConfigError::Forbidden("In use"))
            } else {
                debug!("Successfully removed config '{genid}'");
                self.configs.remove(&genid);
                Ok(())
            }
        } else {
            error!("Can't remove config {genid}: not found");
            Err(ConfigError::NoSuchConfig(genid))
        }
    }

    /// Set the current generation id
    pub fn set_current_gen(&mut self, genid: GenId) {
        info!("Config with genid '{genid}' is now the current");
        self.current = Some(genid);
    }

    /// Get the generation Id of the currently applied config, if any.
    #[must_use]
    pub fn get_current_gen(&self) -> Option<GenId> {
        self.current
    }
    /// Get a reference to the config currently applied, if any.
    #[must_use]
    pub fn get_current_config(&self) -> Option<&GwConfig> {
        self.current.and_then(|genid| self.get(genid))
    }

    /// Get a mutable reference to the config currently applied, if any.
    #[must_use]
    pub fn get_current_config_mut(&mut self) -> Option<&mut GwConfig> {
        self.current.and_then(|genid| self.get_mut(genid))
    }
}
