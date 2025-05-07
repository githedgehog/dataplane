// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configuration database: entity able to store multiple gateway configurations

use crate::frr::frrmi::FrrMi;
use std::collections::BTreeMap;
use tracing::{debug, error, info};

use crate::models::external::gwconfig::{ExternalConfig, GenId, GwConfig};
use crate::models::external::{ConfigError, ConfigResult};

#[derive(Default)]
#[allow(unused)]
/// Configuration database, keeps a set of [`GwConfig`]s keyed by generation id [`GenId`]
pub struct GwConfigDatabase {
    configs: BTreeMap<GenId, GwConfig>, /* collection of configs */
    current: Option<GenId>,             /* [`GenId`] of currently applied config */
}

impl GwConfigDatabase {
    pub fn new() -> Self {
        debug!("Building config database...");
        let mut configdb = Self::default();
        configdb.add(GwConfig::blank());
        configdb
    }
    pub fn add(&mut self, config: GwConfig) {
        debug!("Adding config '{}' to config db...", config.genid());
        self.configs.insert(config.external.genid, config);
    }
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
        debug!("Removing config '{}' from config db...", genid);
        if genid == ExternalConfig::BLANK_GENID {
            error!("Can't remove config {}: forbidden", genid);
            return Err(ConfigError::Forbidden("Cannot delete initial config"));
        }
        if let Some(config) = &self.configs.get(&genid) {
            if config.meta.is_applied {
                error!("Can't remove config {}: in use", genid);
                Err(ConfigError::Forbidden("In use"))
            } else {
                debug!("Successfully removed config '{}'", genid);
                self.configs.remove(&genid);
                Ok(())
            }
        } else {
            error!("Can't remove config {}: not found", genid);
            Err(ConfigError::NoSuchConfig(genid))
        }
    }

    pub async fn apply(&mut self, genid: GenId, frrmi: &FrrMi) -> ConfigResult {
        debug!("Applying config with genid '{}'...", genid);

        /* get the generation (id) of the currently applied config, if any */
        let last = self.current;

        /* Abort if the requested config is already applied */
        if let Some(last) = last {
            if last == genid {
                info!("Config {} is already applied", last);
                return Ok(());
            }
            debug!("The current config is {last}");
        } else {
            debug!("There is no current config applied");
        }

        /* look up the config to apply */
        let Some(config) = self.get_mut(genid) else {
            error!("Can't apply config {}: not found", genid);
            return Err(ConfigError::NoSuchConfig(genid));
        };
        debug!("Config with id {genid} found");

        /* attempt to apply the configuration found */
        let res = config.apply(frrmi).await;
        if res.is_ok() {
            info!("Successfully applied config '{}'", genid);
            self.current = Some(genid);
        } else {
            /* roll-back */
            if let Some(current) = last {
                info!("Rolling back to prior config '{}'", current);
                let mut config = self.get_mut(current);
                if let Some(config) = &mut config {
                    if let Err(e) = config.apply(frrmi).await {
                        error!("Fatal: could not roll-back to prior config: {e}");
                    }
                }
            } else {
                info!("There was no current config. Flushing system...");
                /* To do: build a dummy config and apply it for the purpose of flushing */
            }
        }
        res
    }

    /// Get the generation Id of the currently applied config, if any.
    pub fn get_current_gen(&self) -> Option<GenId> {
        self.current
    }
    /// Get a reference to the config currently applied, if any.
    pub fn get_current_config(&self) -> Option<&GwConfig> {
        if let Some(genid) = self.current {
            self.get(genid)
        } else {
            None
        }
    }
}
