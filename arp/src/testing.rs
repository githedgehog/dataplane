// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Testing utils to build a neighbor cache without the ARP/ND daemon

use crate::cache::{NeighCacheReaderFactory, NeighCacheWriter, NeighEntry};
use net::eth::mac::{DestinationMac, Mac};
use net::interface::InterfaceIndex;
use std::net::IpAddr;

/// A neighbor cache whose entries are set by tests. The cache stays readable as long as
/// this object lives.
pub struct NeighTable {
    writer: NeighCacheWriter,
}

impl Default for NeighTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NeighTable {
    #[must_use]
    pub fn new() -> Self {
        let (writer, _) = NeighCacheWriter::new();
        Self { writer }
    }

    /// Add a reachable neighbor with `address` over `ifindex` at `mac`
    ///
    /// # Panics
    ///
    /// Panics if `mac` cannot be a destination mac.
    pub fn neighbor(&mut self, address: IpAddr, ifindex: InterfaceIndex, mac: Mac) -> &mut Self {
        let mac = DestinationMac::new(mac)
            .unwrap_or_else(|e| panic!("{mac} is not a valid destination mac: {e}"));
        self.writer
            .add_entry(NeighEntry::reachable(address, ifindex, mac));
        self
    }

    #[must_use]
    pub fn factory(&self) -> NeighCacheReaderFactory {
        self.writer.factory()
    }
}
