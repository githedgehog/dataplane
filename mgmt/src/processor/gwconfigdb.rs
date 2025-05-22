// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configuration database: entity able to store multiple gateway configurations

use crate::frr::frrmi::FrrMi;
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::models::external::gwconfig::{ExternalConfig, GenId, GwConfig};
use crate::models::external::{ConfigError, ConfigResult};
use crate::processor::display::GwConfigDatabaseSummary;

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
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.configs.len()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&GenId, &GwConfig)> {
        self.configs.iter()
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
    pub fn unmark_current(&mut self, value: bool) {
        #[allow(clippy::collapsible_if)]
        if let Some(genid) = &self.current {
            if let Some(config) = self.configs.get_mut(genid) {
                config.set_applied(value);
                debug!("Marked config with genid {genid} as inactive");
            }
        }
    }
    pub fn remove(&mut self, genid: GenId) -> ConfigResult {
        if genid == ExternalConfig::BLANK_GENID {
            debug!("Will not remove config {genid} as it is protected");
            return Ok(());
        }
        debug!("Removing config '{genid}' from config db...");
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

    pub async fn apply(
        &mut self,
        genid: GenId,
        frrmi: &mut FrrMi,
        netlink: Arc<rtnetlink::Handle>,
    ) -> ConfigResult {
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
            debug!("There is no config applied");
        }

        if self.contains(genid) {
            /* mark the current config, if any, as not applied anymore. It is unfortunate
            to do this here, hence the check, since otherwise the borrow checker complains
            of double mutable borrow */
            self.unmark_current(false);
        }

        /* look up the config to apply: this should always succeed */
        let Some(config) = self.get_mut(genid) else {
            error!("Can't apply config {}: not found", genid);
            return Err(ConfigError::NoSuchConfig(genid));
        };

        /* attempt to apply the configuration found */
        let res = config.apply(frrmi, netlink.clone()).await;
        if res.is_ok() {
            info!("Config with genid '{}' is now the current", genid);
            self.current = Some(genid);
        } else {
            /* delete the config we wanted to apply */
            debug!("Deleting config with id {genid}..");
            let _ = self.remove(genid);

            /* roll-back to a previous config (if there) or the blank config (to wipe out),
            except if the failed config is the blank itself.

            Question: if a config fails because frr-agent did not respond, rolling back to
            that config will not help, since we will fail to re-apply the FRR config
            which was previously successful. On the other hand,  since the frr-agent will test
            before applying a config, we can confident that a failed config needs not be re-applied
            because, hopefully, frr-reload will not break it ? */
            if genid != ExternalConfig::BLANK_GENID {
                let previous = last.unwrap_or(ExternalConfig::BLANK_GENID);
                info!("Rolling back to config '{}'...", previous);
                let mut config = self.get_mut(previous);
                #[allow(clippy::collapsible_if)]
                if let Some(config) = &mut config {
                    if let Err(e) = config.apply(frrmi, netlink).await {
                        error!("Fatal: could not roll-back to previous config: {e}");
                    }
                }
            }
        }
        debug!(
            "The current config database looks as follows:\n{}",
            GwConfigDatabaseSummary(self)
        );
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
