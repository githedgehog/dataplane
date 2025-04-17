// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configuration database: entity able to store multiple gateway configurations

use std::collections::BTreeMap;
use tracing::{debug, error, info};

use crate::models::external::configdb::gwconfig::GwConfig;
use crate::models::external::{ApiError, ApiResult};

#[derive(Default)]
#[allow(unused)]
/// Configuration database, keeps a set of [`GwConfig`]s keyed by generation
pub struct GwConfigDatabase {
    configs: BTreeMap<u64, GwConfig>, /* collection of configs */
    current: Option<u64>,             /* generation (Id) of currently applied config */
}

impl GwConfigDatabase {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add(&mut self, config: GwConfig) {
        debug!("Adding config '{}' to config db...", config.meta.generation);
        self.configs.insert(config.meta.generation, config);
    }
    pub fn get(&self, generation: u64) -> Option<&GwConfig> {
        self.configs.get(&generation)
    }
    pub fn remove(&mut self, generation: u64) -> ApiResult {
        debug!("Removing config '{}' from config db...", generation);
        if let Some(config) = &self.configs.get(&generation) {
            if config.meta.is_applied {
                error!("Can't remove config {}: in use", generation);
                Err(ApiError::Forbidden)
            } else {
                debug!("Successfully removed config '{}'", generation);
                self.configs.remove(&generation);
                Ok(())
            }
        } else {
            error!("Can't remove config {}: not found", generation);
            Err(ApiError::NoSuchConfig(generation))
        }
    }
    pub fn apply(&mut self, generation: u64) -> ApiResult {
        debug!("Applying config '{}'...", generation);
        let Some(config) = self.configs.get_mut(&generation) else {
            error!("Can't apply config {}: not found", generation);
            return Err(ApiError::NoSuchConfig(generation));
        };
        // apply the selected config
        let res = config.apply();
        if res.is_ok() {
            info!("Successfully applied config '{}'", generation);
            self.current = Some(generation);
        } else {
            // TODO: roll back
        }
        res
    }
}
