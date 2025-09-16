// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::port::NatPort;
use std::fmt::Display;
use std::net::IpAddr;

#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone)]
pub struct NatState {
    // Translation IP addresses and ports
    target_src_addr: Option<IpAddr>,
    target_dst_addr: Option<IpAddr>,
    target_src_port: Option<NatPort>,
    target_dst_port: Option<NatPort>,
}

impl NatState {
    #[must_use]
    pub fn new(
        target_src_addr: Option<IpAddr>,
        target_dst_addr: Option<IpAddr>,
        target_src_port: Option<NatPort>,
        target_dst_port: Option<NatPort>,
    ) -> Self {
        Self {
            target_src_addr,
            target_dst_addr,
            target_src_port,
            target_dst_port,
        }
    }
    #[must_use]
    pub fn get_nat(
        &self,
    ) -> (
        Option<IpAddr>,
        Option<IpAddr>,
        Option<NatPort>,
        Option<NatPort>,
    ) {
        (
            self.target_src_addr,
            self.target_dst_addr,
            self.target_src_port,
            self.target_dst_port,
        )
    }
}

impl Display for NatState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{:?}:{} -> {:?}:{}",
            self.target_src_addr.unwrap_or(IpAddr::from([0, 0, 0, 0])),
            self.target_src_port.map_or(0, NatPort::as_u16),
            self.target_dst_addr.unwrap_or(IpAddr::from([0, 0, 0, 0])),
            self.target_dst_port.map_or(0, NatPort::as_u16),
        )
    }
}
