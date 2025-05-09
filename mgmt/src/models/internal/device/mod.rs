// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: device

pub mod ports;
pub mod settings;

use ports::PortConfig;
use settings::DeviceSettings;
use tracing::warn;

use crate::models::external::ApiResult;

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub settings: DeviceSettings,
    pub ports: Vec<PortConfig>,
}
impl DeviceConfig {
    pub fn new(settings: DeviceSettings) -> Self {
        Self {
            settings,
            ports: vec![],
        }
    }
    pub fn validate(&self) -> ApiResult {
        warn!("Validating device configuration (TODO");
        Ok(())
    }
}
