// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;
use std::convert::TryFrom;
use std::net::Ipv4Addr;

use crate::internal::interfaces::interface::InterfaceConfig;
use crate::internal::routing::bgp::BgpConfig;
use crate::internal::routing::ospf::Ospf;
use crate::internal::routing::vrf::VrfConfig;

// OSPF conversions
impl TryFrom<&gateway_config::OspfConfig> for Ospf {
    type Error = String;

    fn try_from(ospf_config: &gateway_config::OspfConfig) -> Result<Self, Self::Error> {
        // Parse router_id from string to Ipv4Addr
        let router_id = ospf_config
            .router_id
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("Invalid OSPF router ID format: {}", ospf_config.router_id))?;

        // Create a new Ospf instance
        let mut ospf = Ospf::new(router_id);

        // Set VRF name if present
        #[allow(clippy::collapsible_if)]
        if let Some(vrf_name) = &ospf_config.vrf {
            if !vrf_name.is_empty() {
                ospf.set_vrf_name(vrf_name.clone());
            }
        }

        Ok(ospf)
    }
}

impl From<&Ospf> for gateway_config::OspfConfig {
    fn from(ospf: &Ospf) -> Self {
        gateway_config::OspfConfig {
            router_id: ospf.router_id.to_string(),
            vrf: ospf.vrf.clone(),
        }
    }
}

impl TryFrom<&gateway_config::Vrf> for VrfConfig {
    type Error = String;

    fn try_from(vrf: &gateway_config::Vrf) -> Result<Self, Self::Error> {
        // Create VRF config
        let mut vrf_config = VrfConfig::new(&vrf.name, None, true /* default vrf */);

        // Convert BGP config if present and add it to VRF
        if let Some(router) = &vrf.router {
            let bgp = BgpConfig::try_from(router)?;
            vrf_config.set_bgp(bgp);
        }

        // convert each interface
        for iface in &vrf.interfaces {
            let iface_config = InterfaceConfig::try_from(iface)?;
            vrf_config.add_interface_config(iface_config);
        }

        // Convert ospf config if present
        if let Some(ospf_config) = &vrf.ospf {
            let ospf = Ospf::try_from(ospf_config)?;
            vrf_config.set_ospf(ospf);
        }

        Ok(vrf_config)
    }
}

impl TryFrom<&VrfConfig> for gateway_config::Vrf {
    type Error = String;

    fn try_from(vrf: &VrfConfig) -> Result<Self, Self::Error> {
        // Convert interfaces
        let interfaces = Vec::<gateway_config::Interface>::try_from(&vrf.interfaces)?;

        // Convert router config if BGP is configured
        let router = match &vrf.bgp {
            Some(bgp) => Some(gateway_config::RouterConfig::try_from(bgp)?),
            None => None,
        };

        // Convert OSPF config if present
        let ospf = vrf.ospf.as_ref().map(gateway_config::OspfConfig::from);

        Ok(gateway_config::Vrf {
            name: vrf.name.clone(),
            interfaces,
            router,
            ospf,
        })
    }
}
