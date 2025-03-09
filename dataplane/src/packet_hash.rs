// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Module to compute packet hashes

use super::Packet;
use ahash::AHasher;
use net::buffer::PacketBufferMut;
use net::headers::{Net, Transport, TryHeaders, TryIp, TryTransport};
use std::hash::{Hash, Hasher};

impl<Buf: PacketBufferMut> Packet<Buf> {
    #[allow(unused)]
    /// Computes a hash over a `Packet` object if it contains an ipv4 or ipv6 packet,
    /// using invariant fields of the ip header and common transport headers,
    /// if present, using the specified Hasher.
    pub fn hash_ip<H: Hasher>(&self, state: &mut H) {
        if let Some(ip) = self.headers().try_ip() {
            match ip {
                Net::Ipv4(ipv4) => {
                    ipv4.source().hash(state);
                    ipv4.destination().hash(state);
                    ipv4.protocol().hash(state);
                }
                Net::Ipv6(ipv6) => {
                    ipv6.source().hash(state);
                    ipv6.destination().hash(state);
                    ipv6.next_header().hash(state);
                }
            }
            if let Some(transport) = self.headers().try_transport() {
                match transport {
                    Transport::Tcp(tcp) => {
                        tcp.source().hash(state);
                        tcp.destination().hash(state);
                    }
                    Transport::Udp(udp) => {
                        udp.source().hash(state);
                        udp.destination().hash(state);
                    }
                    &Transport::Icmp4(_) | &Transport::Icmp6(_) => {}
                }
            }
        }
    }

    #[allow(unused)]
    /// Uses the ip hash `Packet` method to provide a value in the range [first, last].
    pub fn packet_hash_ecmp(&self, first: u8, last: u8) -> u64 {
        let mut hasher = AHasher::default();
        self.hash_ip(&mut hasher);
        hasher.finish() % u64::from(last - first + 1) + u64::from(first)
    }
}
