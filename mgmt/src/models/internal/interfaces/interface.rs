// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: interfaces

#![allow(unused)]

use crate::models::external::ConfigError;
use crate::models::external::ConfigResult;
use crate::models::internal::routing::ospf::OspfInterface;
use multi_index_map::MultiIndexMap;
use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::interface::InterfaceName;
use net::route::RouteTableId;
use net::vlan::Vid;
use net::vxlan::Vni;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
/// An Ip address configured on a local interface
/// Fixme(fredi): this type should be inherited from routing crate on new merge
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub mask_len: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfVlanConfig {
    pub mac: Option<Mac>,
    pub vlan_id: Vid,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfEthConfig {
    pub mac: Option<Mac>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfBridgeConfig {
    pub vlan_filtering: bool,
    pub vlan_protocol: EthType,
    pub mac: Option<Mac>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfVtepConfig {
    pub mac: Option<Mac>,
    pub vni: Option<Vni>,
    pub ttl: Option<u8>,
    pub local: IpAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfVrfConfig {
    pub table_id: RouteTableId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceType {
    Loopback,
    Ethernet(IfEthConfig),
    Vlan(IfVlanConfig),
    Bridge(IfBridgeConfig),
    Vtep(IfVtepConfig),
    Vrf(IfVrfConfig),
}

/// A network interface configuration. An interface can be user-specified or internal. This config object
/// includes data to create the interface in the kernel and configure it for routing (e.g. FRR)
#[derive(Clone, Debug, PartialEq, Eq, MultiIndexMap)]
#[multi_index_derive(Debug, Clone)]
pub struct InterfaceConfig {
    #[multi_index(ordered_unique)]
    pub name: InterfaceName, /* key */
    pub iftype: InterfaceType,
    pub description: Option<String>,
    pub vrf: Option<String>,
    pub addresses: BTreeSet<InterfaceAddress>,
    pub mtu: Option<u16>,
    pub internal: bool, /* true if automatically created */
    pub ospf: Option<OspfInterface>,
}

impl InterfaceAddress {
    pub fn new(address: IpAddr, mask_len: u8) -> Self {
        Self { address, mask_len }
    }
}

impl InterfaceConfig {
    pub fn new(name: InterfaceName, iftype: InterfaceType, internal: bool) -> Self {
        Self {
            name,
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
    pub fn set_mtu(mut self, mtu: u16) -> Self {
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
        // Ip address is mandatory on VTEP
        if matches!(self.iftype, InterfaceType::Vtep(_)) && self.addresses.is_empty() {
            return Err(ConfigError::MissingParameter("Ip address"));
        }

        Ok(())
    }
}

impl MultiIndexInterfaceConfigMap {
    pub fn new() -> Self {
        Self::default()
    }
}
