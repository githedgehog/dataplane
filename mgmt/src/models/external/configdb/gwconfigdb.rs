// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configuration database: entity able to store multiple gateway configurations

use std::collections::BTreeMap;
use tracing::{debug, error, info};

use crate::models::external::configdb::gwconfig::{GenId, GwConfig};
use crate::models::external::{ApiError, ApiResult};

#[derive(Default)]
#[allow(unused)]
/// Configuration database, keeps a set of [`GwConfig`]s keyed by generation id [`GenId`]
pub struct GwConfigDatabase {
    configs: BTreeMap<GenId, GwConfig>, /* collection of configs */
    current: Option<GenId>,             /* [`GenId`] of currently applied config */
}

impl GwConfigDatabase {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, config: GwConfig) {
        debug!("Adding config '{}' to config db...", config.genid());
        self.configs.insert(config.external.genid, config);
    }
    pub fn get(&self, genid: GenId) -> Option<&GwConfig> {
        self.configs.get(&genid)
    }
    pub fn remove(&mut self, genid: GenId) -> ApiResult {
        debug!("Removing config '{}' from config db...", genid);
        if let Some(config) = &self.configs.get(&genid) {
            if config.meta.is_applied {
                error!("Can't remove config {}: in use", genid);
                Err(ApiError::Forbidden)
            } else {
                debug!("Successfully removed config '{}'", genid);
                self.configs.remove(&genid);
                Ok(())
            }
        } else {
            error!("Can't remove config {}: not found", genid);
            Err(ApiError::NoSuchConfig(genid))
        }
    }
    pub fn apply(&mut self, genid: GenId) -> ApiResult {
        debug!("Applying config '{}'...", genid);
        let Some(config) = self.configs.get_mut(&genid) else {
            error!("Can't apply config {}: not found", genid);
            return Err(ApiError::NoSuchConfig(genid));
        };
        // apply the selected config
        let res = config.apply();
        if res.is_ok() {
            info!("Successfully applied config '{}'", genid);
            self.current = Some(genid);
        } else {
            // TODO: roll back
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
