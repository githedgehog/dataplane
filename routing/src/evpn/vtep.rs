// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Submodule to represent VTEP state

use net::eth::mac::SourceMac;
use net::ip::UnicastIpAddr;

/// Type that represents a VTEP
#[derive(Clone, Debug, PartialEq)]
pub struct Vtep {
    ip: UnicastIpAddr,
    mac: SourceMac,
}

impl Vtep {
    #[must_use]
    pub fn new(ip: UnicastIpAddr, mac: SourceMac) -> Self {
        Self { ip, mac }
    }
    #[must_use]
    pub fn ip(&self) -> UnicastIpAddr {
        self.ip
    }
    #[must_use]
    pub fn mac(&self) -> SourceMac {
        self.mac
    }
}
