// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Underlay configuration

use crate::internal::interfaces::interface::{InterfaceConfig, InterfaceType};
use crate::internal::routing::evpn::VtepConfig;
use crate::internal::routing::vrf::VrfConfig;
use crate::{ConfigError, ConfigResult};

use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;
use std::net::IpAddr;

use tracing::debug;

#[derive(Clone, Default, Debug)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
    pub vtep: Option<VtepConfig>,
}

impl TryFrom<&InterfaceConfig> for VtepConfig {
    type Error = ConfigError;
    fn try_from(intf: &InterfaceConfig) -> Result<Self, Self::Error> {
        match &intf.iftype {
            InterfaceType::Vtep(vtep) => {
                let mac = match vtep.mac {
                    Some(mac) => SourceMac::new(mac).map_err(|_| {
                        ConfigError::BadVtepMacAddress(mac, "VTEP mac is not a valid source mac")
                    }),
                    None => {
                        return Err(ConfigError::MissingParameter("VTEP MAC address"));
                    }
                }?;
                let ip = UnicastIpv4Addr::new(vtep.local).map_err(|e| {
                    ConfigError::BadVtepLocalAddress(IpAddr::V4(e), "Invalid address")
                })?;
                Ok(VtepConfig::new(ip.into(), mac))
            }
            _ => Err(ConfigError::InternalFailure(format!(
                "Attempted to get vtep config from non-vtep interface {}",
                intf.name
            ))),
        }
    }
}

impl Underlay {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Look for a vtep interface in the list of interfaces of the underlay VRF
    /// and, if found, build a `VtepConfig` out of it. We accept at most one VTEP
    /// interface and it has to have valid ip and mac. No Vtep interface is valid
    /// if not VPCs are configured. This is checked elsewhere.
    fn get_vtep_info(&self) -> Result<Option<VtepConfig>, ConfigError> {
        let vteps: Vec<&InterfaceConfig> = self
            .vrf
            .interfaces
            .values()
            .filter(|config| matches!(config.iftype, InterfaceType::Vtep(_)))
            .collect();
        match vteps.len() {
            0 => Ok(None),
            1 => Ok(Some(VtepConfig::try_from(vteps[0])?)),
            _ => Err(ConfigError::TooManyInstances(
                "Vtep interfaces",
                vteps.len(),
            )),
        }
    }

    pub fn validate(&mut self) -> ConfigResult {
        debug!("Validating underlay configuration...");

        // validate interfaces
        self.vrf
            .interfaces
            .values()
            .try_for_each(|iface| iface.validate())?;

        // set vtep information if a vtep interface has been specified in the config
        self.vtep = self.get_vtep_info()?;

        Ok(())
    }
}
