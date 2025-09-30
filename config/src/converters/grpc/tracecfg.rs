// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::internal::device::tracecfg::TracingConfig;
use ::gateway_config::config::TracingConfig as ApiTracingConfig;
use std::collections::HashMap;
use tracectl::LevelFilter;

fn loglevel_to_levelfilter(value: i32) -> Result<LevelFilter, String> {
    match gateway_config::LogLevel::try_from(value) {
        Ok(::gateway_config::LogLevel::Off) => Ok(LevelFilter::OFF),
        Ok(::gateway_config::LogLevel::Error) => Ok(LevelFilter::ERROR),
        Ok(::gateway_config::LogLevel::Warning) => Ok(LevelFilter::WARN),
        Ok(::gateway_config::LogLevel::Info) => Ok(LevelFilter::INFO),
        Ok(::gateway_config::LogLevel::Debug) => Ok(LevelFilter::DEBUG),
        Ok(::gateway_config::LogLevel::Trace) => Ok(LevelFilter::TRACE),
        Err(_) => Err(format!("Invalid log level value: {value:?}")),
    }
}
fn levelfilter_to_loglevel(value: LevelFilter) -> gateway_config::LogLevel {
    match value {
        LevelFilter::OFF => ::gateway_config::LogLevel::Off,
        LevelFilter::ERROR => ::gateway_config::LogLevel::Error,
        LevelFilter::WARN => ::gateway_config::LogLevel::Warning,
        LevelFilter::INFO => ::gateway_config::LogLevel::Info,
        LevelFilter::DEBUG => ::gateway_config::LogLevel::Debug,
        LevelFilter::TRACE => ::gateway_config::LogLevel::Trace,
    }
}

// API to internal
impl TryFrom<&ApiTracingConfig> for TracingConfig {
    type Error = String;
    fn try_from(cfg: &ApiTracingConfig) -> Result<Self, Self::Error> {
        let default_loglevel = loglevel_to_levelfilter(cfg.default)?;
        let mut config = TracingConfig::new(default_loglevel);
        for (tag, level) in &cfg.taglevel {
            let level = loglevel_to_levelfilter(*level)?;
            config.add_tag(tag, level);
        }
        Ok(config)
    }
}

// Internal to API
impl From<&TracingConfig> for ApiTracingConfig {
    fn from(value: &TracingConfig) -> Self {
        ApiTracingConfig {
            default: levelfilter_to_loglevel(value.default).into(),
            taglevel: value
                .tags
                .iter()
                .map(|(tag, level)| (tag.clone(), levelfilter_to_loglevel(*level).into()))
                .collect::<HashMap<String, i32>>(),
        }
    }
}
