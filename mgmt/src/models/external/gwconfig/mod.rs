// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway configuration (external)
//! The external config contains the intended configuration externally received (e.g. via gRPC)

use derive_builder::Builder;

use std::time::SystemTime;
use tracing::debug;

use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;

use crate::models::external::overlay::Overlay;
use crate::models::external::{ConfigError, ConfigResult};
use crate::models::internal::InternalConfig;

use crate::models::internal::device::DeviceConfig;
use crate::models::internal::device::settings::DeviceSettings;
use crate::models::internal::interfaces::interface::{InterfaceConfig, InterfaceType};
use crate::models::internal::routing::evpn::VtepConfig;
use crate::models::internal::routing::vrf::VrfConfig;

use crate::processor::confbuild::internal::build_internal_config;

/// Alias for a config generation number
pub type GenId = i64;

#[derive(Clone, Default, Debug)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
    pub vtep: Option<VtepConfig>,
}
impl Underlay {
    pub fn new() -> Self {
        Self::default()
    }
    // Get the vtep interface from the list of interfaces of the underlay vrf.
    // One vtep interface should exist at the most. No vtep interface is a valid
    // configuration if no VPCs are configured.
    fn get_vtep_interface(&self) -> Result<Option<&InterfaceConfig>, ConfigError> {
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
    fn get_vtep_info(&self) -> Result<Option<VtepConfig>, ConfigError> {
        match self.get_vtep_interface()? {
            Some(intf) => match &intf.iftype {
                InterfaceType::Vtep(vtep) => {
                    let mac = match vtep.mac {
                        Some(mac) => SourceMac::new(mac).map_err(|_| {
                            ConfigError::BadVtepMacAddress(
                                mac,
                                "mac address is not a valid source mac address",
                            )
                        }),
                        None => {
                            return Err(ConfigError::InternalFailure(format!(
                                "Missing VTEP MAC address on {}",
                                intf.name
                            )));
                        }
                    }?;
                    let ip = UnicastIpv4Addr::new(vtep.local).map_err(|_| {
                        ConfigError::InternalFailure(format!(
                            "VTEP local address is not a valid unicast address {}",
                            vtep.local
                        ))
                    })?;
                    Ok(Some(VtepConfig::new(ip.into(), mac)))
                }
                _ => unreachable!(),
            },
            None => Ok(None),
        }
    }

    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating underlay configuration...");

        // validate interfaces
        self.vrf
            .interfaces
            .values()
            .try_for_each(|iface| iface.validate())?;

        // set vtep information if vtep interface is present
        self.vtep = self.get_vtep_info()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// Configuration metadata. Every config object stored by the dataplane has metadata
pub struct GwConfigMeta {
    pub create_t: SystemTime,        /* time when config was built (received) */
    pub apply_t: Option<SystemTime>, /* last time when config was applied successfully */
    pub replace_t: Option<SystemTime>, /* time when config was un-applied */
    pub replacement: Option<GenId>,  /* Id of config that replaced this one */
    pub is_applied: bool,            /* True if the config is currently applied */
}
impl GwConfigMeta {
    fn new() -> Self {
        Self {
            create_t: SystemTime::now(),
            apply_t: None,
            replace_t: None,
            replacement: None,
            is_applied: false,
        }
    }
}

/// The configuration object as seen by the gRPC server
#[derive(Builder, Clone, Debug)]
pub struct ExternalConfig {
    pub genid: GenId,         /* configuration generation id (version) */
    pub device: DeviceConfig, /* goes as-is into the internal config */
    pub underlay: Underlay,   /* goes as-is into the internal config */
    pub overlay: Overlay,     /* VPCs and peerings -- get highly developed in internal config */
}
impl ExternalConfig {
    pub const BLANK_GENID: GenId = 0;

    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            genid: Self::BLANK_GENID,
            device: DeviceConfig::new(DeviceSettings::new("Unset")),
            underlay: Underlay::default(),
            overlay: Overlay::default(),
        }
    }
    pub fn validate(&mut self) -> ConfigResult {
        self.device.validate()?;
        self.underlay.validate()?;
        self.overlay.validate()?;

        // if there are vpcs configured, there must be a vtep configured
        if !self.overlay.vpc_table.is_empty() && self.underlay.vtep.is_none() {
            return Err(ConfigError::MissingParameter(
                "Vtep interface configuration",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct GwConfig {
    pub meta: GwConfigMeta,               /* config metadata */
    pub external: ExternalConfig,         /* external config: received */
    pub internal: Option<InternalConfig>, /* internal config: built by gw from internal */
}

impl GwConfig {
    /// Create a [`GwConfig`] object with a given [`ExternalConfig`].
    pub fn new(external: ExternalConfig) -> Self {
        Self {
            meta: GwConfigMeta::new(),
            external,
            internal: None,
        }
    }
    /// Create a blank [`GwConfig`] with an empty [`ExternalConfig`].
    /// Such a config has generation id 0 (from the empty [`ExternalConfig`]).
    pub fn blank() -> Self {
        Self::new(ExternalConfig::new())
    }

    /// Return the [`GenId`] of a [`GwConfig`] object.
    pub fn genid(&self) -> GenId {
        self.external.genid
    }

    /// Mark/unmark config as applied
    pub fn set_state(&mut self, value: bool, replacement: Option<GenId>) {
        if value {
            self.meta.apply_t = Some(SystemTime::now());
            self.meta.replace_t.take();
            self.meta.replacement.take();
            debug!("Config {} has been marked as active", self.genid());
        } else {
            self.meta.replace_t = Some(SystemTime::now());
            self.meta.replacement = replacement;
            debug!("Config {} has been marked as inactive", self.genid());
        }
        self.meta.is_applied = value;
    }

    /// Validate a [`GwConfig`].
    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating external config with genid {} ..", self.genid());
        self.external.validate()
    }

    /// Build the [`InternalConfig`] for this [`GwConfig`].
    pub fn build_internal_config(&mut self) -> ConfigResult {
        /* build and set internal config */
        self.internal = Some(build_internal_config(self)?);
        Ok(())
    }
}
