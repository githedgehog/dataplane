// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: EVPN

use net::eth::mac::Mac;
use std::net::IpAddr;

#[derive(Debug)]
pub struct VtepConfig {
    pub address: IpAddr,
    pub mac: Mac,
}
impl VtepConfig {
    pub fn new(address: IpAddr, mac: Mac) -> Self {
        Self { address, mac }
    }
}
