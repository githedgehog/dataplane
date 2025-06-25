// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(dead_code)]
#![allow(rustdoc::private_doc_tests)]

//! Network Address Translation (NAT) for the dataplane
//!
//! This package implements a [`NetworkFunction`] that provides Network Address Translation (NAT)
//! functionality, either source or destination.
//!
//! # Example
//!
//! ```
//! # use net::buffer::TestBuffer;
//! # use net::headers::TryIpv4;
//! # use net::packet::test_utils::build_test_ipv4_packet;
//! # use pipeline::NetworkFunction;
//! use dataplane_nat::{NatDirection, StatelessNat};
//!
//! let mut nat = StatelessNat::new(NatDirection::SrcNat);
//! let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
//! let packets_out: Vec<_> = nat.process(packets).collect();
//!
//! let hdr0_out = &packets_out[0]
//!     .try_ipv4()
//!     .expect("Failed to get IPv4 header");
//! ```
//!
//! # Limitations
//!
//! The package is subject to the following limitations:
//!
//! - Only NAT44 is supported (no NAT46, NAT64, or NAT66)
//! - Either source or destination NAT is supported, only one at a time, by a given [`StatelessNat`]
//!   or [`Nat`] object.
//!   To perform NAT for different address fields, instantiate multiple [`StatelessNat`] or
//!   [`Nat`] objects.
//! - "Expose" objects mixing IPv4 and IPv6 endpoints or list of exposed IPs are not supported
//! - The total number of available (not excluded) private addresses used in an "Expose" object must
//!   be equal to the total number of publicly exposed addresses in this object.

mod iplist;
mod stateful;
pub mod stateless;

pub use stateless::StatelessNat;

use crate::iplist::IpList;
use mgmt::models::internal::nat::tables::NatTables;
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use pipeline::NetworkFunction;
use stateful::sessions::{NatDefaultSessionManager, NatSessionManager};

/// Indicates whether a [`Nat`] processor should perform source NAT or destination NAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatDirection {
    /// Source NAT
    SrcNat,
    /// Destination NAT
    DstNat,
}

/// A NAT processor, implementing the [`NetworkFunction`] trait. [`Nat`] processes packets to run
/// source or destination Network Address Translation (NAT) on their IP addresses.
#[derive(Debug)]
pub struct Nat {
    context: NatTables,
    sessions: NatDefaultSessionManager,
    direction: NatDirection,
}

impl Nat {
    /// Creates a new [`Nat`] processor. The `direction` indicates whether this processor should
    /// perform source or destination NAT.
    pub fn new(direction: NatDirection) -> Self {
        let context = NatTables::new();
        Self {
            context,
            sessions: NatDefaultSessionManager::new(),
            direction,
        }
    }

    /// Updates the VNI tables in the NAT processor.
    pub fn update_tables(&mut self, tables: NatTables) {
        self.context = tables;
    }

    /// Processes one packet. This is the main entry point for processing a packet. This is also the
    /// function that we pass to [`Nat::process`] to iterate over packets.
    fn process_packet<Buf: PacketBufferMut>(&mut self, packet: &mut Packet<Buf>) {
        let vni = packet.get_meta().src_vni;

        let _ = self.stateful_nat::<Buf>(packet, vni);
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Nat {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.map(|mut packet| {
            self.process_packet(&mut packet);
            packet
        })
    }
}
