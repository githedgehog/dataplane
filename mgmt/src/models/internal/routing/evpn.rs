// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: EVPN

use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;

#[derive(Clone, Debug)]
pub struct VtepConfig {
    pub address: UnicastIpv4Addr,
    pub mac: SourceMac,
}
impl VtepConfig {
    pub fn new(address: UnicastIpv4Addr, mac: SourceMac) -> Self {
        Self { address, mac }
    }
}
