// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration model: BFD

#![allow(unused)]

use std::net::IpAddr;

use super::bgp::{BgpNeighType, BgpNeighbor, BgpUpdateSource};

// Hard-coded BFD parameters for fabric-facing links
pub const BFD_DETECT_MULTIPLIER: u8 = 3;
pub const BFD_TRANSMIT_INTERVAL_MS: u16 = 300;
pub const BFD_RECEIVE_INTERVAL_MS: u16 = 300;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BfdPeer {
    pub address: IpAddr,
    pub multihop: bool,
    pub source: Option<IpAddr>,
}

impl BfdPeer {
    #[must_use]
    pub fn new(address: IpAddr) -> Self {
        Self {
            address,
            multihop: false,
            source: None,
        }
    }

    #[must_use]
    pub fn set_multihop(mut self, value: bool) -> Self {
        self.multihop = value;
        self
    }

    #[must_use]
    pub fn set_source(mut self, source: Option<IpAddr>) -> Self {
        self.source = source;
        self
    }
}

// Collect BFD peers from BGP neighbors.
// Only neighbors with `neighbor.bfd == true` are included.
//
// Notes:
// - `Peer-groups` are ignored (no concrete IP to key BFD session on)
// - `multihop` is derived from `ebgp_multihop` (if present)
// - `source` is derived only when update-source is an explicit IP address
#[must_use]
pub fn peers_from_bgp_neighbors(neighbors: &[BgpNeighbor]) -> Vec<BfdPeer> {
    neighbors
        .iter()
        .filter(|n| n.bfd)
        .filter_map(|n| match &n.ntype {
            BgpNeighType::Host(addr) => {
                let multihop = n.ebgp_multihop.is_some();
                let source = n.update_source.as_ref().and_then(|src| match src {
                    BgpUpdateSource::Address(a) => Some(*a),
                    BgpUpdateSource::Interface(_) => None,
                });

                Some(
                    BfdPeer::new(*addr)
                        .set_multihop(multihop)
                        .set_source(source),
                )
            }
            _ => None,
        })
        .collect()
}
