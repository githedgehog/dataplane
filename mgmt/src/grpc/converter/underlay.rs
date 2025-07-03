// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;
use std::string::ToString;

use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;
use std::net::IpAddr;

use crate::models::external::ConfigError;
use crate::models::external::gwconfig::Underlay;
use crate::models::internal::interfaces::interface::InterfaceConfig;
use crate::models::internal::interfaces::interface::InterfaceType;
use crate::models::internal::routing::evpn::VtepConfig;
use crate::models::internal::routing::vrf::VrfConfig;

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
                        return Err(ConfigError::MissingParameter(format!(
                            "VTEP MAC address on {}",
                            intf.name
                        )));
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

/// Look up for a vtep interface in the list  of interfaces of the underlay VRF
/// and, if found, build a `VtepConfig` out of it. We accept at most one VTEP
/// interface and it has to have valid ip and mac. No Vtep interface is valid
/// if no VPCs are configured, but we don't know this here and that's checked
/// elsewhere.
fn get_vtep_info(vrf_cfg: &VrfConfig) -> Result<Option<VtepConfig>, ConfigError> {
    let vteps: Vec<&InterfaceConfig> = vrf_cfg
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

impl TryFrom<&gateway_config::Underlay> for Underlay {
    type Error = String;

    fn try_from(underlay: &gateway_config::Underlay) -> Result<Self, Self::Error> {
        // Find the default VRF or first VRF if default not found
        if underlay.vrfs.is_empty() {
            return Err("Underlay must contain at least one VRF".to_string());
        }

        // Look for the default VRF. The default VRF is called "default"
        let default_vrf = underlay
            .vrfs
            .iter()
            .find(|vrf| vrf.name == "default")
            .ok_or_else(|| "Failed to find default VRF".to_string())?;

        // Convert VRF to VrfConfig
        let vrf_config = VrfConfig::try_from(default_vrf)?;

        // Build vtep config from the interfaces of default vrf
        let vtep = get_vtep_info(&vrf_config).map_err(|e| e.to_string())?;

        // Create Underlay with the VRF config
        Ok(Underlay {
            vrf: vrf_config,
            vtep,
        })
    }
}

impl TryFrom<&Underlay> for gateway_config::Underlay {
    type Error = String;

    fn try_from(underlay: &Underlay) -> Result<Self, Self::Error> {
        // Convert the VRF
        let vrf_grpc = gateway_config::Vrf::try_from(&underlay.vrf)?;

        Ok(gateway_config::Underlay {
            vrfs: vec![vrf_grpc],
        })
    }
}
