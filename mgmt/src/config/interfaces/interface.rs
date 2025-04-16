// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: interfaces

#![allow(unused)]

use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
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

#[derive(Clone, Debug)]
pub struct IfVlanConfig {
    pub mac: Option<Mac>,
    pub vlan_id: Vid,
}
#[derive(Clone, Debug)]
pub struct IfEthConfig {
    pub mac: Option<Mac>,
}
#[derive(Clone, Debug)]
pub struct IfBridgeConfig {
    pub vlan_filtering: bool,
    pub vlan_protocol: EthType,
    pub mac: Option<Mac>,
}
#[derive(Clone, Debug)]
pub struct IfVtepConfig {
    pub mac: Option<Mac>,
    pub vni: Option<Vni>,
    pub ttl: Option<u8>,
    pub local: IpAddr,
}

#[derive(Clone, Debug)]
pub struct IfVrfConfig {
    pub table_id: u32, // FIXME: interface manager has specific type
}

#[derive(Clone, Debug)]
pub enum InterfaceType {
    Loopback,
    Ethernet(IfEthConfig),
    Vlan(IfVlanConfig),
    Bridge(IfBridgeConfig),
    Vtep(IfVtepConfig),
    Vrf(IfVrfConfig),
}

#[derive(Clone, Debug)]
/// A network interface configuration. An interface can be user-specified or internal. This config object
/// includes data to create the interface in the kernel and configure it for routing (e.g. FRR)
pub struct InterfaceConfig {
    pub name: String, /* key */
    pub iftype: InterfaceType,
    pub description: Option<String>,
    pub vrf: Option<String>,
    pub addresses: BTreeSet<InterfaceAddress>,
    pub mtu: Option<u16>,
    pub internal: bool, /* true if automatically created */
}

#[derive(Clone, Debug, Default)]
/// An interface configuration table
pub struct InterfaceConfigTable(BTreeMap<String, InterfaceConfig>);

impl InterfaceAddress {
    pub fn new(address: IpAddr, mask_len: u8) -> Self {
        Self { address, mask_len }
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
