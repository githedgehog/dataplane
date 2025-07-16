// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: EVPN

use net::eth::mac::{Mac, SourceMac};
use net::ip::UnicastIpAddr;

/// The configuration of a VTEP (virtual tunnel endpoint) for the Hedgehog EVPN router.
#[derive(Clone, Debug)]
pub struct VtepConfig {
    /// The source IP address to be used by vxlan packets originating from this router.
    pub address: UnicastIpAddr,
    /// The source MAC address to be used by vxlan packets originating from this router.
    pub mac: SourceMac,
}

impl VtepConfig {
    /// The TTL to be used by VTEPs.
    pub const TTL: u8 = 64;

    /// Creates a new VTEP configuration.
    #[must_use]
    pub fn new(address: UnicastIpAddr, mac: SourceMac) -> Self {
        Self { address, mac }
    }
}
