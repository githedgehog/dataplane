// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::converters::strings::parse_address_v4;
use std::net::IpAddr;

use k8s_intf::gateway_agent_crd::GatewayAgentGateway;
use lpm::prefix::{Prefix, PrefixString};
use net::eth::mac::SourceMac;

use crate::external::underlay::Underlay;
use crate::internal::interfaces::interface::{
    IfVtepConfig, InterfaceAddress, InterfaceConfig, InterfaceType,
};

use crate::internal::routing::bgp::{AfIpv4Ucast, AfL2vpnEvpn, BgpConfig, BgpNeighbor};
use crate::internal::routing::vrf::VrfConfig;

use crate::converters::k8s::FromK8sConversionError;

fn add_hardcoded_interfaces(
    vrf: &mut VrfConfig,
    gateway: &GatewayAgentGateway,
) -> Result<(), FromK8sConversionError> {
    let vtep_ip_raw = gateway
        .vtep_ip
        .as_ref()
        .ok_or(FromK8sConversionError::MissingData(
            "Gateway VTEP IP not specified".to_string(),
        ))?;
    let vtep_ip = vtep_ip_raw.parse::<InterfaceAddress>().map_err(|e| {
        FromK8sConversionError::ParseError(format!("Invalid VTEP IP {vtep_ip_raw}: {e}"))
    })?;

    // Loopback
    let mut lo = InterfaceConfig::new("lo", InterfaceType::Loopback, false);
    lo = lo.add_address(vtep_ip.address, vtep_ip.mask_len);
    vrf.add_interface_config(lo);

    // VTEP
    let vtep_mac = if let Some(vtep_mac_raw) = gateway.vtep_mac.as_ref() {
        let vtep_mac = vtep_mac_raw.parse::<SourceMac>().map_err(|e| {
            FromK8sConversionError::ParseError(format!("Invalid VTEP MAC {vtep_mac_raw}: {e}"))
        })?;
        Some(vtep_mac)
    } else {
        None
    };

    let vtep_ipv4 = match vtep_ip.address {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => {
            return Err(FromK8sConversionError::Invalid(format!(
                "VTEP IP {v6} is not IPv4"
            )));
        }
    };

    let vtep_iftype = InterfaceType::Vtep(IfVtepConfig {
        mac: vtep_mac.map(SourceMac::inner),
        vni: None,
        ttl: None,
        local: vtep_ipv4,
    });

    let vtep = InterfaceConfig::new("vtep", vtep_iftype, false);
    vrf.add_interface_config(vtep);

    Ok(())
}

fn add_interfaces(
    vrf: &mut VrfConfig,
    gateway: &GatewayAgentGateway,
) -> Result<(), FromK8sConversionError> {
    add_hardcoded_interfaces(vrf, gateway)?;
    if let Some(interfaces) = gateway.interfaces.as_ref() {
        for (name, iface) in interfaces {
            let iface_config = InterfaceConfig::try_from((name.as_str(), iface))?;
            vrf.add_interface_config(iface_config);
        }
    }
    Ok(())
}

fn add_bgp_config(
    vrf: &mut VrfConfig,
    gateway: &GatewayAgentGateway,
) -> Result<(), FromK8sConversionError> {
    let asn = gateway.asn.ok_or(FromK8sConversionError::MissingData(
        "Gateway ASN not specified".to_string(),
    ))?;

    let protocol_ip = gateway
        .protocol_ip
        .as_ref()
        .ok_or(FromK8sConversionError::MissingData(
            "Gateway protocol IP not specified".to_string(),
        ))?;

    let router_id = parse_address_v4(protocol_ip).map_err(|e| {
        FromK8sConversionError::ParseError(format!("Invalid IPv4 protocol IP {protocol_ip}: {e}"))
    })?;

    let vtep_ip_raw = gateway
        .vtep_ip
        .as_ref()
        .ok_or(FromK8sConversionError::MissingData(
            "Gateway VTEP IP not specified".to_string(),
        ))?;

    let vtep_prefix = Prefix::try_from(PrefixString(vtep_ip_raw)).map_err(|e| {
        FromK8sConversionError::ParseError(format!("Invalid VTEP IP {vtep_ip_raw}: {e}"))
    })?;
    if !vtep_prefix.is_ipv4() {
        return Err(FromK8sConversionError::Invalid(format!(
            "Invalid VTEP IP {vtep_ip_raw}: not an IPv4 prefix"
        )));
    }

    let mut af_ipv4unicast = AfIpv4Ucast::new();
    af_ipv4unicast.add_networks(vec![vtep_prefix]);

    let af_l2vpnevpn = AfL2vpnEvpn::new()
        .set_adv_all_vni(true)
        .set_adv_default_gw(true)
        .set_adv_svi_ip(true)
        .set_adv_ipv4_unicast(true)
        .set_adv_ipv6_unicast(false)
        .set_default_originate_ipv4(false)
        .set_default_originate_ipv6(false);

    let mut bgp = BgpConfig::new(asn);
    bgp.set_router_id(router_id);
    bgp.set_af_ipv4unicast(af_ipv4unicast);
    bgp.set_af_l2vpn_evpn(af_l2vpnevpn);

    if let Some(neighbors) = gateway.neighbors.as_ref() {
        // Add each neighbor to the BGP config
        for neighbor in neighbors {
            bgp.add_neighbor(BgpNeighbor::try_from(neighbor)?);
        }
    }

    vrf.set_bgp(bgp);
    Ok(())
}

impl TryFrom<&GatewayAgentGateway> for Underlay {
    type Error = FromK8sConversionError;

    fn try_from(gateway: &GatewayAgentGateway) -> Result<Self, Self::Error> {
        let mut vrf = VrfConfig::new("default", None, true /* default vrf */);

        add_bgp_config(&mut vrf, gateway)?;
        add_interfaces(&mut vrf, gateway)?;

        Ok(Underlay { vrf, vtep: None })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::BTreeMap;

    use ipnet::IpNet;

    use k8s_intf::bolero::{LegalValue, Normalize};
    use k8s_intf::gateway_agent_crd::{
        GatewayAgentGatewayInterfaces, GatewayAgentGatewayNeighbors,
    };

    #[test]
    fn test_underlay_conversion() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentGateway>>()
            .for_each(|gateway| {
                let gateway = gateway.as_ref();
                let underlay = Underlay::try_from(gateway).unwrap();
                let vrf = underlay.vrf;
                let bgp_config = vrf.bgp.expect("Default VRF should have BGP configuration");

                let vtep_ip = gateway.vtep_ip.as_ref().expect("Gateway has no vtep_ip");
                let vtep_network = Prefix::from(
                    vtep_ip
                        .parse::<IpNet>()
                        .expect("Failed to parse vtep_ip as Prefix"),
                );

                // Check BGP configuration
                assert_eq!(gateway.asn, Some(bgp_config.asn));
                assert_eq!(
                    gateway
                        .protocol_ip
                        .as_ref()
                        .map(|v| v.split('/').next().unwrap().to_string()),
                    bgp_config.router_id.map(|v| v.to_string())
                );
                let Some(af_ipv4unicast) = bgp_config.af_ipv4unicast else {
                    panic!("Default VRF should have IPv4 unicast configuration");
                };
                assert_eq!(af_ipv4unicast.networks.len(), 1);
                assert_eq!(
                    vtep_network.to_string(),
                    af_ipv4unicast.networks[0].to_string()
                );
                assert!(bgp_config.af_ipv6unicast.is_none()); // No IPv6 support yet

                assert!(bgp_config.af_l2vpnevpn.is_some());

                // Check BGP neighbors
                let converted_neighbors = bgp_config
                    .neighbors
                    .iter()
                    .map(|neighbor| GatewayAgentGatewayNeighbors::try_from(neighbor).unwrap())
                    .collect::<Vec<_>>();

                assert_eq!(
                    if let Some(neighbors) = gateway.neighbors.as_ref() {
                        neighbors.normalize()
                    } else {
                        Vec::new()
                    },
                    converted_neighbors.normalize()
                );

                let underlay_interfaces = vrf.interfaces;

                // Check hardcoded interfaces
                let lo = underlay_interfaces
                    .values()
                    .find(|intf| {
                        intf.name == "lo" && matches!(intf.iftype, InterfaceType::Loopback)
                    })
                    .expect("lo interface not found");
                assert_eq!(
                    lo.addresses
                        .iter()
                        .map(InterfaceAddress::to_string)
                        .collect::<Vec<_>>(),
                    vec![vtep_ip.clone()],
                );

                let vtep = underlay_interfaces
                    .values()
                    .find(|intf| {
                        intf.name == "vtep" && matches!(intf.iftype, InterfaceType::Vtep(_))
                    })
                    .expect("vtep interface not found");
                match &vtep.iftype {
                    InterfaceType::Vtep(vtep) => {
                        assert_eq!(vtep.local.to_string(), vtep_ip.split('/').next().unwrap());
                        assert_eq!(vtep.mac.map(|v| v.to_string()), gateway.vtep_mac);
                    }
                    _ => panic!("Unexpected interface type"),
                }

                // Check configured interfaces
                let converted_interfaces = underlay_interfaces
                    .values()
                    .filter(|intf| matches!(intf.iftype, InterfaceType::Ethernet(_)))
                    .map(|intf| {
                        (
                            intf.name.clone(),
                            GatewayAgentGatewayInterfaces::try_from(intf).unwrap(),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();

                assert_eq!(
                    if let Some(intfs) = gateway.interfaces.as_ref() {
                        intfs.normalize()
                    } else {
                        BTreeMap::new()
                    },
                    converted_interfaces.normalize()
                );

                // No extra interfaces
                let expected_num_ifs = 2 + gateway.interfaces.as_ref().map_or(0, BTreeMap::len);
                assert_eq!(underlay_interfaces.values().count(), expected_num_ifs);
            });
    }
}
