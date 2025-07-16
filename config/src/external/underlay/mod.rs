// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Underlay configuration

use crate::internal::interfaces::interface::{InterfaceConfig, InterfaceType};
use crate::internal::routing::vrf::VrfConfig;
use crate::{ConfigError, ConfigResult};
use tracing::debug;

#[derive(Clone, Default, Debug)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
}
impl Underlay {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get_vtep_interface(&self) -> Result<Option<&InterfaceConfig>, ConfigError> {
        let vteps: Vec<&InterfaceConfig> = self
            .vrf
            .interfaces
            .values()
            .filter(|config| matches!(config.iftype, InterfaceType::Vtep(_)))
            .collect();
        match vteps.len() {
            0 => Ok(None),
            1 => Ok(Some(vteps[0])),
            _ => Err(ConfigError::TooManyInstances(
                "Vtep interfaces",
                vteps.len(),
            )),
        }
    }
    pub fn validate(&self) -> ConfigResult {
        debug!("Validating underlay configuration...");

        // validate interfaces
        self.vrf
            .interfaces
            .values()
            .try_for_each(|iface| iface.validate())?;

        Ok(())
    }
}
