// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: device

pub mod ports;
pub mod settings;
pub mod tracecfg;

use ports::PortConfig;
use settings::DeviceSettings;
use tracecfg::TracingConfig;
use tracing::{debug, error};

use crate::{ConfigError, ConfigResult};

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub settings: DeviceSettings,
    pub ports: Vec<PortConfig>,
    pub tracing: Option<TracingConfig>,
}
impl DeviceConfig {
    #[must_use]
    pub fn new(settings: DeviceSettings) -> Self {
        Self {
            settings,
            ports: vec![],
            tracing: None,
        }
    }
    pub fn set_tracing(&mut self, tracing: TracingConfig) {
        self.tracing = Some(tracing);
    }
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating device configuration..");
        if self.settings.hostname.is_empty() {
            return Err(ConfigError::MissingIdentifier("Device hostname"));
        }
        if let Some(tracing) = &self.tracing {
            tracing.validate()?;
        }
        Ok(())
    }
}
