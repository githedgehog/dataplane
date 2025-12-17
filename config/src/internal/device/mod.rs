// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: device

pub mod tracecfg;

use tracecfg::TracingConfig;
use tracing::{debug, error};

use crate::{ConfigError, ConfigResult};

#[derive(Clone, Debug, Default)]
pub struct DeviceConfig {
    pub tracing: Option<TracingConfig>,
}
impl DeviceConfig {
    #[must_use]
    pub fn new() -> Self {
        Self { tracing: None }
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
