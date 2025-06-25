// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: interfaces

#![allow(unused)]

use net::eth::ethtype::EthType;
use net::eth::mac::{Mac, SourceMac};
use net::interface::Mtu;
use net::vlan::Vid;
use net::vxlan::Vni;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use thiserror::Error;

use crate::models::external::ConfigError;
use crate::models::external::ConfigResult;
use crate::models::internal::routing::ospf::OspfInterface;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// An Ip address configured on a local interface
/// Fixme(fredi): this type should be inherited from routing crate on new merge
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub mask_len: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IfVlanConfig {
    pub mac: Option<Mac>,
    pub vlan_id: Vid,
}
#[derive(Clone, Debug, PartialEq)]
pub struct IfEthConfig {
    pub mac: Option<Mac>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct IfVtepConfig {
    pub mac: Option<Mac>,
    pub vni: Option<Vni>,
    pub ttl: Option<u8>,
    pub local: Ipv4Addr,
}

#[derive(Clone, Debug, PartialEq)]
pub enum InterfaceType {
    Loopback,
    Ethernet(IfEthConfig),
    Vlan(IfVlanConfig),
    Vtep(IfVtepConfig),
}

#[derive(Clone, Debug, PartialEq)]
/// A network interface configuration. An interface can be user-specified or internal. This config object
/// includes data to create the interface in the kernel and configure it for routing (e.g. FRR)
pub struct InterfaceConfig {
    pub name: String, /* key */
    pub iftype: InterfaceType,
    pub description: Option<String>,
    pub vrf: Option<String>,
    pub addresses: BTreeSet<InterfaceAddress>,
    pub mtu: Option<Mtu>,
    pub internal: bool, /* true if automatically created */
    pub ospf: Option<OspfInterface>,
}

#[derive(Clone, Debug, Default, PartialEq)]
/// An interface configuration table
pub struct InterfaceConfigTable(BTreeMap<String, InterfaceConfig>);

impl InterfaceAddress {
    pub fn new(address: IpAddr, mask_len: u8) -> Self {
        Self { address, mask_len }
    }
}

#[derive(Clone, Debug, Error)]
pub enum InterfaceAddressParseError {
    #[error("Invalid interface address format: {0}")]
    InvalidFormat(String),
    #[error("Invalid IP address interface address: {0}")]
    InvalidIpAddress(String),
    #[error("Invalid mask length in interface address: {0}")]
    InvalidMaskLength(String),
}

impl FromStr for InterfaceAddress {
    type Err = InterfaceAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split('/');
        let address_str = parts
            .next()
            .ok_or(InterfaceAddressParseError::InvalidFormat(s.to_string()))?;
        let mask_len_str = parts
            .next()
            .ok_or(InterfaceAddressParseError::InvalidFormat(s.to_string()))?;
        if parts.next().is_some() {
            return Err(InterfaceAddressParseError::InvalidFormat(s.to_string()));
        }
        let address = address_str
            .parse::<IpAddr>()
            .map_err(|e| InterfaceAddressParseError::InvalidIpAddress(e.to_string()))?;
        let mask_len = mask_len_str
            .parse::<u8>()
            .map_err(|e| InterfaceAddressParseError::InvalidMaskLength(e.to_string()))?;
        Ok(Self::new(address, mask_len))
    }
}

impl Display for InterfaceAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.mask_len)
    }
}

impl InterfaceConfig {
    pub fn new(name: &str, iftype: InterfaceType, internal: bool) -> Self {
        Self {
            name: name.to_owned(),
            iftype,
            description: None,
            vrf: None,
            addresses: BTreeSet::new(),
            mtu: None,
            internal,
            ospf: None,
        }
    }
    pub fn set_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_owned());
        self
    }
    pub fn set_mtu(mut self, mtu: Mtu) -> Self {
        self.mtu = Some(mtu);
        self
    }
    pub fn add_address(mut self, address: IpAddr, mask_len: u8) -> Self {
        self.addresses
            .insert(InterfaceAddress::new(address, mask_len));
        self
    }
    pub fn set_vrf(mut self, vrfname: &str) -> Self {
        self.vrf = Some(vrfname.to_owned());
        self
    }
    pub fn set_ospf(mut self, ospf: OspfInterface) -> Self {
        self.ospf = Some(ospf);
        self
    }
    pub fn validate(&self) -> ConfigResult {
        // name is mandatory
        if self.name.is_empty() {
            return Err(ConfigError::MissingIdentifier("interface name"));
        }

        if let InterfaceType::Vtep(vtep) = &self.iftype {
            if vtep.local.is_multicast() {
                return Err(ConfigError::BadVtepLocalAddress(
                    vtep.local.into(),
                    "address is not unicast",
                ));
            } else {
                match &vtep.mac {
                    Some(mac) => {
                        if SourceMac::new(*mac).is_err() {
                            return Err(ConfigError::BadVtepMacAddress(
                                *mac,
                                "mac address is not a valid source mac address",
                            ));
                        };
                    }
                    None => return Err(ConfigError::MissingParameter("VTEP MAC address")),
                }
            }
        };

        Ok(())
    }
}

impl InterfaceConfigTable {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub fn add_interface_config(&mut self, cfg: InterfaceConfig) {
        self.0.insert(cfg.name.to_owned(), cfg);
    }
    pub fn values(&self) -> impl Iterator<Item = &InterfaceConfig> {
        self.0.values()
    }
}
