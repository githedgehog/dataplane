// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane tracing configuration

#![allow(unused)]

use crate::ConfigResult;
use ordermap::OrderMap;
use tracing::debug;

#[cfg(unix)]
use tracectl::DEFAULT_DEFAULT_LOGLEVEL;
#[cfg(unix)]
use tracectl::{LevelFilter, get_trace_ctl};

#[cfg(not(unix))]
use tracing::metadata::LevelFilter;
#[cfg(not(unix))]
const DEFAULT_DEFAULT_LOGLEVEL: LevelFilter = LevelFilter::INFO;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracingRateLimit {
    pub burst: u32,
    pub replenish_per_second: u32,
}
impl Default for TracingRateLimit {
    fn default() -> Self {
        #[cfg(unix)]
        let (burst, replenish_per_second) = {
            let d = tracectl::TracingRateLimitConfig::default();
            (d.burst, d.replenish_per_second)
        };
        #[cfg(not(unix))]
        // Default params
        let (burst, replenish_per_second) = (50, 5);
        Self {
            burst,
            replenish_per_second,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TracingConfig {
    pub default: LevelFilter,
    pub tags: OrderMap<String, LevelFilter>,
    /// Log rate limiter. `None` disables rate limiting (no config); `Some`
    /// throttles with the given values (an empty CRD `{}` resolves to the
    /// [`TracingRateLimit::default`]).
    pub rate_limit: Option<TracingRateLimit>,
}
impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            default: DEFAULT_DEFAULT_LOGLEVEL,
            tags: OrderMap::new(),
            rate_limit: None,
        }
    }
}
impl TracingConfig {
    #[must_use]
    pub fn new(default: LevelFilter) -> Self {
        Self {
            default,
            tags: OrderMap::new(),
            rate_limit: None,
        }
    }
    pub fn add_tag(&mut self, tag: &str, level: LevelFilter) {
        let _ = self.tags.insert(tag.to_string(), level);
    }
    pub fn set_rate_limit(&mut self, rate_limit: TracingRateLimit) {
        self.rate_limit = Some(rate_limit);
    }
    /// Validate the tracing configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if any configured trace tag is unknown.
    #[cfg(unix)]
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating tracing configuration..");
        let tags: Vec<&str> = self.tags.keys().map(String::as_str).collect();
        Ok(get_trace_ctl().check_tags(&tags)?)
    }

    /// Validate the tracing configuration (no-op on non-unix platforms).
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())` on non-unix platforms.
    #[cfg(not(unix))]
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating tracing configuration (no-op on this platform)..");
        Ok(())
    }
}
