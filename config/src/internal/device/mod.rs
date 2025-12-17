// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: device

pub mod settings;
pub mod tracecfg;

use settings::DeviceSettings;
use tracecfg::TracingConfig;
use tracing::{debug, error};

use crate::{ConfigError, ConfigResult};

#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub settings: DeviceSettings,
    pub tracing: Option<TracingConfig>,
}
impl DeviceConfig {
    #[must_use]
    pub fn new(settings: DeviceSettings) -> Self {
        Self {
            settings,
            tracing: None,
        }
    }
    pub fn set_tracing(&mut self, tracing: TracingConfig) {
        self.tracing = Some(tracing);
    }
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating device configuration..");
        if let Some(tracing) = &self.tracing {
            // DISABLE validation since the set of available tags
            // is not burnt in the gRPC protobuf schema.
            // tracing.validate()?;
        }
        Ok(())
    }
}
