// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane tracing configuration

#![allow(unused)]

use crate::ConfigResult;
use ordermap::OrderMap;
use tracectl::DEFAULT_DEFAULT_LOGLEVEL;
use tracectl::{LevelFilter, get_trace_ctl};
use tracing::debug;

#[derive(Clone, Debug)]
pub struct TracingConfig {
    pub default: LevelFilter,
    pub tags: OrderMap<String, LevelFilter>,
}
impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            default: DEFAULT_DEFAULT_LOGLEVEL,
            tags: OrderMap::new(),
        }
    }
}
impl TracingConfig {
    #[must_use]
    pub fn new(default: LevelFilter) -> Self {
        Self {
            default,
            tags: OrderMap::new(),
        }
    }
    pub fn add_tag(&mut self, tag: &str, level: LevelFilter) {
        let _ = self.tags.insert(tag.to_string(), level);
    }
    /// Validate the tracing configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if any configured trace tag is unknown.
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating tracing configuration..");
        let tags: Vec<&str> = self.tags.keys().map(String::as_str).collect();
        Ok(get_trace_ctl().check_tags(&tags)?)
    }
}
