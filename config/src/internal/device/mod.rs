// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: device

pub mod ports;
pub mod settings;

use ports::PortConfig;
use settings::DeviceSettings;
use tracing::{debug, error};

use crate::{ConfigError, ConfigResult};

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub settings: DeviceSettings,
    pub ports: Vec<PortConfig>,
}
impl DeviceConfig {
    #[must_use]
    pub fn new(settings: DeviceSettings) -> Self {
        Self {
            settings,
            ports: vec![],
        }
    }
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating device configuration..");
        if self.settings.hostname.is_empty() {
            return Err(ConfigError::MissingIdentifier("Device hostname"));
        }
        Ok(())
    }
}
