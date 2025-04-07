// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: device

pub mod ports;
pub mod settings;

use ports::PortConfig;
use settings::DeviceSettings;

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    settings: DeviceSettings,
    ports: Vec<PortConfig>,
}
impl DeviceConfig {
    pub fn new(settings: DeviceSettings) -> Self {
        Self {
            settings,
            ports: vec![],
        }
    }
}
