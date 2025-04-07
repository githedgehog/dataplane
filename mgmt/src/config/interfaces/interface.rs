// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: interfaces

#![allow(unused)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
/// An Ip address configured on a local interface
/// Fixme(fredi): this type should be inherited from routing crate on new merge
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub mask_len: u8,
}

pub enum InterfaceType {
    Bridge,
    Vtep,
    Vrf,
    Vlan,
}

#[derive(Debug)]
/// A network interface configuration. An interface can be user-specified or internal
pub struct InterfaceConfig {
    pub internal: bool,
    pub name: String,
    pub description: Option<String>,
    pub vrf: Option<String>,
    pub addresses: BTreeSet<InterfaceAddress>,
    pub mtu: Option<u16>,
}

#[derive(Debug, Default)]
/// An interface configuration table
pub struct InterfaceConfigTable(BTreeMap<String, InterfaceConfig>);

impl InterfaceAddress {
    pub fn new(address: IpAddr, mask_len: u8) -> Self {
        Self { address, mask_len }
    }
}

impl InterfaceConfig {
    pub fn new(name: &str, internal: bool) -> Self {
        Self {
            internal,
            name: name.to_owned(),
            description: None,
            vrf: None,
            addresses: BTreeSet::new(),
            mtu: None,
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
