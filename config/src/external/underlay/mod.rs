// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Underlay configuration

use crate::internal::interfaces::interface::{InterfaceConfig, InterfaceType};
use crate::internal::routing::evpn::VtepConfig;
use crate::internal::routing::vrf::VrfConfig;
use crate::{ConfigError, ConfigResult};

use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;

use tracing::debug;

#[derive(Clone, Default, Debug)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
    pub vtep: Option<VtepConfig>,
}
impl Underlay {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Get the vtep interface from the list of interfaces of the underlay vrf.
    /// One vtep interface should exist at the most. No vtep interface is a valid
    /// configuration if no VPCs are configured.
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

    /// Build a `VtepConfig` from the vtep interface specified in the underlay vrf
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

        // set vtep information if a vtep interface has been specified in the config
        self.vtep = self.get_vtep_info()?;

        Ok(())
    }
}
