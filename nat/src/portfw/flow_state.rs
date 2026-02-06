// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding flow state

use net::ip::UnicastIpAddr;
use std::num::NonZero;

#[derive(Debug)]
pub struct PortFwState {
    use_ip: UnicastIpAddr,
    use_port: NonZero<u16>,
}
impl PortFwState {
    pub fn new(use_ip: UnicastIpAddr, use_port: NonZero<u16>) -> Self {
        Self { use_ip, use_port }
    }
}
