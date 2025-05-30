// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Submodule to represent VTEP state

use net::eth::mac::Mac;
use std::net::IpAddr;

/// Type that represents a VTEP
#[derive(Default)]
pub struct Vtep {
    ip: Option<IpAddr>,
    mac: Option<Mac>,
}

#[allow(dead_code)]
impl Vtep {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn with_ip(ip: IpAddr) -> Self {
        Self {
            ip: Some(ip),
            mac: None,
        }
    }
    #[must_use]
    pub fn with_mac(mac: Mac) -> Self {
        Self {
            ip: None,
            mac: Some(mac),
        }
    }
    #[must_use]
    pub fn with_ip_and_mac(ip: IpAddr, mac: Mac) -> Self {
        Self {
            ip: Some(ip),
            mac: Some(mac),
        }
    }
    #[must_use]
    pub fn get_ip(&self) -> Option<IpAddr> {
        self.ip
    }
    #[must_use]
    pub fn get_mac(&self) -> Option<Mac> {
        self.mac
    }
    pub fn set_ip(&mut self, ip: IpAddr) {
        self.ip = Some(ip);
    }
    pub fn set_mac(&mut self, mac: Mac) {
        self.mac = Some(mac);
    }
    #[must_use]
    pub fn is_set_up(&self) -> bool {
        self.ip.is_some() && self.mac.is_some()
    }
    pub fn unset_ip(&mut self) {
        self.ip.take();
    }
    pub fn unset_mac(&mut self) {
        self.mac.take();
    }
}
