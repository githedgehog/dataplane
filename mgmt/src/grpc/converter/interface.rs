// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;
use std::net::{IpAddr, Ipv4Addr};

use crate::models::internal::interfaces::interface::{
    IfEthConfig, IfVlanConfig, IfVtepConfig, InterfaceAddress, InterfaceConfig,
    InterfaceConfigTable, InterfaceType,
};
use crate::models::internal::routing::ospf::{OspfInterface, OspfNetwork};
use linux_raw_sys::if_ether;
use net::eth::mac::{Mac, SourceMac};
use net::vlan::Vid;

fn interface_addresses_to_strings(interface: &InterfaceConfig) -> Vec<String> {
    interface
        .addresses
        .iter()
        .map(|addr| format!("{addr}"))
        .collect()
}

impl TryFrom<&gateway_config::OspfInterface> for OspfInterface {
    type Error = String;

    fn try_from(ospf_interface: &gateway_config::OspfInterface) -> Result<Self, Self::Error> {
        // Parse area from string to Ipv4Addr
        let area = ospf_interface
            .area
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("Invalid OSPF area format: {}", ospf_interface.area))?;

        // Create a new OspfInterface instance
        let mut ospf_iface = OspfInterface::new(area);

        // Set passive state
        ospf_iface = ospf_iface.set_passive(ospf_interface.passive);

        // Set cost if present
        if let Some(cost) = ospf_interface.cost {
            ospf_iface = ospf_iface.set_cost(cost);
        }

        // Set network type if present
        if let Some(network_type) = &ospf_interface.network_type {
            let network = match gateway_config::OspfNetworkType::try_from(*network_type) {
                Ok(gateway_config::OspfNetworkType::Broadcast) => OspfNetwork::Broadcast,
                Ok(gateway_config::OspfNetworkType::NonBroadcast) => OspfNetwork::NonBroadcast,
                Ok(gateway_config::OspfNetworkType::PointToPoint) => OspfNetwork::Point2Point,
                Ok(gateway_config::OspfNetworkType::PointToMultipoint) => {
                    OspfNetwork::Point2Multipoint
                }
                Err(_) => return Err(format!("Invalid OSPF network type: {network_type}")),
            };
            ospf_iface = ospf_iface.set_network(network);
        }

        Ok(ospf_iface)
    }
}

impl TryFrom<&gateway_config::Interface> for InterfaceConfig {
    type Error = String;

    fn try_from(iface: &gateway_config::Interface) -> Result<Self, Self::Error> {
        // Convert interface type
        let grpc_if_type = gateway_config::IfType::try_from(iface.r#type)
            .map_err(|_| format!("Invalid interface type: {}", iface.r#type))?;
        let mac = match &iface.macaddr {
            Some(mac) => Some(
                SourceMac::try_from(
                    Mac::try_from(mac.as_str())
                        .map_err(|_| format!("String is not a valid MAC address: {mac}"))?,
                )
                .map_err(|e| {
                    format!(
                        "Interface {} mac address ({mac}) must be a source mac address: {e}",
                        iface.name
                    )
                })?,
            ),
            None => None,
        };
        let iftype = match grpc_if_type {
            gateway_config::IfType::Ethernet => InterfaceType::Ethernet(IfEthConfig {
                mac: mac.map(SourceMac::inner),
            }),
            gateway_config::IfType::Vlan => {
                // Safely handle the VLAN ID conversion
                let vlan_id = iface
                    .vlan
                    .ok_or_else(|| "VLAN interface requires vlan ID".to_string())?;

                // Try to convert to u16
                let vlan_u16 =
                    u16::try_from(vlan_id).map_err(|_| format!("Invalid VLAN ID: {vlan_id}"))?;

                // Create a safe Vid
                let vid =
                    Vid::new(vlan_u16).map_err(|_| format!("Invalid VLAN ID value: {vlan_u16}"))?;

                InterfaceType::Vlan(IfVlanConfig {
                    mac: mac.map(SourceMac::inner),
                    vlan_id: vid,
                })
            }
            gateway_config::IfType::Loopback => InterfaceType::Loopback,
            gateway_config::IfType::Vtep => {
                let local = match iface.ipaddrs.as_slice() {
                    [] => Err("VTEP interface requires an IP address".to_string()),
                    [addr] => {
                        let addr_mask = addr.parse::<InterfaceAddress>().map_err(|e| {
                            format!("Invalid interface address \"{addr}\" for VTEP interface: {e}",)
                        })?;
                        // Purposefully skip unicast check here because fuzzer generates multicast addresses
                        // Unicast is checked when we build the vtep interface later
                        let ipv4 = match addr_mask.address {
                            IpAddr::V4(ipv4) => ipv4,
                            IpAddr::V6(_) => {
                                return Err("VTEP interface requires an IPv4 address".to_string());
                            }
                        };
                        if addr_mask.mask_len == 32 {
                            Ok(ipv4)
                        } else {
                            Err("VTEP interface requires a /32 IP address".to_string())
                        }
                    }
                    _ => Err("VTEP interface requires exactly one IP address".to_string()),
                }?;

                InterfaceType::Vtep(IfVtepConfig {
                    mac: mac.map(SourceMac::inner),
                    vni: None,
                    ttl: None,
                    local,
                })
            }
        };

        // Create new InterfaceConfig
        let mut interface_config: InterfaceConfig =
            InterfaceConfig::new(&iface.name, iftype, false);

        // Add the address from gRPC if present,
        // But not for VTEP interfaces because we abuse the field to mean local IP
        // See https://github.com/githedgehog/gateway-proto/issues/24
        if grpc_if_type != gateway_config::IfType::Vtep && !iface.ipaddrs.is_empty() {
            for ips in &iface.ipaddrs {
                let ifaddr = ips
                    .parse::<InterfaceAddress>()
                    .map_err(|e| format!("Invalid interface address \"{ips}\": {e}"))?;
                interface_config = interface_config.add_address(ifaddr.address, ifaddr.mask_len);
            }
        }

        // Add OSPF interface configuration if present
        if let Some(ospf_iface) = &iface.ospf {
            let ospf_interface = OspfInterface::try_from(ospf_iface)?;
            interface_config = interface_config.set_ospf(ospf_interface);
        }

        if let Some(mtu) = iface.mtu {
            if mtu < if_ether::ETH_MIN_MTU {
                return Err(format!("MTU too small on interface {}: {mtu}", iface.name));
            }
            if mtu > if_ether::ETH_MAX_MTU {
                return Err(format!("MTU too large on interface {}: {mtu}", iface.name));
            }
            interface_config = interface_config.set_mtu(mtu);
        }

        Ok(interface_config)
    }
}

impl TryFrom<&OspfInterface> for gateway_config::OspfInterface {
    type Error = String;

    fn try_from(ospf_interface: &OspfInterface) -> Result<Self, Self::Error> {
        // Convert network type if present
        let network_type = ospf_interface.network.as_ref().map(|network| {
            (match network {
                OspfNetwork::Broadcast => gateway_config::OspfNetworkType::Broadcast,
                OspfNetwork::NonBroadcast => gateway_config::OspfNetworkType::NonBroadcast,
                OspfNetwork::Point2Point => gateway_config::OspfNetworkType::PointToPoint,
                OspfNetwork::Point2Multipoint => gateway_config::OspfNetworkType::PointToMultipoint,
            })
            .into()
        });

        Ok(gateway_config::OspfInterface {
            passive: ospf_interface.passive,
            area: ospf_interface.area.to_string(),
            cost: ospf_interface.cost,
            network_type,
        })
    }
}

impl TryFrom<&InterfaceConfig> for gateway_config::Interface {
    type Error = String;

    fn try_from(interface: &InterfaceConfig) -> Result<Self, Self::Error> {
        // Get IP address safely
        //let ipaddr = get_primary_address(interface)?;
        let interface_addresses = match &interface.iftype {
            InterfaceType::Ethernet(_) | InterfaceType::Vlan(_) | InterfaceType::Loopback => {
                interface_addresses_to_strings(interface)
            }
            InterfaceType::Vtep(vtep) => vec![format!("{}/32", vtep.local.to_string())],
            _ => vec![],
        };

        // Convert interface type
        let if_type = match &interface.iftype {
            InterfaceType::Ethernet(_) => gateway_config::IfType::Ethernet,
            InterfaceType::Vlan(_) => gateway_config::IfType::Vlan,
            InterfaceType::Loopback => gateway_config::IfType::Loopback,
            InterfaceType::Vtep(_) => gateway_config::IfType::Vtep,
            _ => {
                return Err(format!(
                    "Unsupported interface type: {:?}",
                    interface.iftype
                ));
            }
        };

        // Get VLAN ID if available
        let vlan = match &interface.iftype {
            InterfaceType::Vlan(if_vlan_config) => Some(u32::from(if_vlan_config.vlan_id.as_u16())),
            _ => None,
        };

        // Get MAC address if available
        let macaddr = match &interface.iftype {
            InterfaceType::Ethernet(eth_config) => eth_config.mac.as_ref().map(ToString::to_string),
            InterfaceType::Vlan(vlan_config) => vlan_config.mac.as_ref().map(ToString::to_string),
            InterfaceType::Vtep(vtep_config) => vtep_config.mac.as_ref().map(ToString::to_string),
            _ => None,
        };

        // Convert OSPF interface if present
        let ospf = interface
            .ospf
            .as_ref()
            .map(gateway_config::OspfInterface::try_from)
            .transpose()
            .map_err(|e| format!("Failed to convert OSPF interface: {e}"))?;

        let mtu = interface.mtu;

        // Create the gRPC interface
        Ok(gateway_config::Interface {
            name: interface.name.clone(),
            ipaddrs: interface_addresses,
            r#type: if_type.into(),
            vlan,
            macaddr,
            system_name: None, // TODO: Implement when needed
            role: gateway_config::IfRole::Fabric.into(), // Default to Fabric
            ospf,
            mtu,
        })
    }
}

impl TryFrom<&InterfaceConfigTable> for Vec<gateway_config::Interface> {
    type Error = String;

    fn try_from(interfaces: &InterfaceConfigTable) -> Result<Self, Self::Error> {
        let mut grpc_interfaces = Vec::new();

        for interface in interfaces.values() {
            let grpc_iface = gateway_config::Interface::try_from(interface)?;
            grpc_interfaces.push(grpc_iface);
        }

        Ok(grpc_interfaces)
    }
}
