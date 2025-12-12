// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module to compute packet hashes

use crate::headers::{Net, Transport, TryHeaders, TryIp, TryTransport};
use crate::packet::Packet;
use crate::{buffer::PacketBufferMut, headers::TryEth};
use rapidhash::fast::RapidHasher;
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

    /// Computes a hash over a `Packet` including Ethernet header, vlans if present and IP invariant fields
    pub fn hash_l2_frame<H: Hasher>(&self, state: &mut H) {
        // ethernet
        if let Some(eth) = self.headers().try_eth() {
            eth.source().hash(state);
            eth.destination().hash(state);
            eth.ether_type().hash(state);
        }
        // vlan tags - we don't include PCP/DEI
        for tag in &self.headers.vlan {
            tag.vid().hash(state);
        }
        // Ip and transport
        self.hash_ip(state);
    }

    #[allow(unused)]
    /// Uses the ip hash `Packet` method to provide a value in the range [first, last].
    pub fn packet_hash_ecmp(&self, first: u8, last: u8) -> u64 {
        let mut hasher = RapidHasher::default();
        self.hash_ip(&mut hasher);
        hasher.finish() % u64::from(last - first + 1) + u64::from(first)
    }

    #[allow(unused)]
    /// Uses the `hash_l2_frame` `Packet` method to provide a hash in the range \[49152,65535\] suitable
    /// as UDP source port for vxlan-encapsulated packets, as recommended by RFC7348.
    #[allow(clippy::cast_possible_truncation)]
    pub fn packet_hash_vxlan(&self) -> u16 {
        let mut hasher = RapidHasher::default();
        self.hash_l2_frame(&mut hasher);
        (hasher.finish() % (65535u64 - 49152 + 1) + 49152u64) as u16
    }
}

#[cfg(test)]
mod tests {
    use crate::buffer::TestBuffer;
    use crate::packet::Packet;
    use crate::packet::test_utils::*;
    use std::collections::BTreeMap;

    // Builds a vector of packets.
    // Note: If this function is changed, the fingerprint file may
    // need to be updated.
    //
    // See instructions in the comment for test_ahash_detect_changes().
    fn build_test_packets(number: u16) -> Vec<Packet<TestBuffer>> {
        let mut packets = Vec::new();
        for n in 1..=number {
            packets.push(build_test_udp_ipv4_packet(
                format!("10.0.0.{}", n % 255).as_str(),
                format!("10.0.0.{}", 255 - n % 255).as_str(),
                (1 + n) % u16::MAX,
                u16::MAX - (n % u16::MAX),
            ));
        }
        packets
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn test_hash_bounds() {
        let start: u64 = 4;
        let end: u64 = 10;
        let num_packets: u64 = 2000;
        let packets = build_test_packets(num_packets.try_into().unwrap());
        let mut values: BTreeMap<u64, u64> = BTreeMap::new();
        for packet in &packets {
            let hash = packet.packet_hash_ecmp(
                u8::try_from(start).expect("Bad start"),
                u8::try_from(end).expect("Bad start"),
            );
            values
                .entry(hash)
                .and_modify(|counter| *counter += 1)
                .or_insert(1);
        }
        /* test bounds */
        assert_eq!(values.get(&(start - 1)), None);
        assert_eq!(values.get(&(end + 1)), None);

        /* distribution */
        let normalized: Vec<f64> = values
            .values()
            .map(|value| (value * 100 / num_packets) as f64)
            .collect();

        /* ideal frequency (in %): uniform */
        let ifreq = 100_f64 / (end - start + 1) as f64;

        /* This is not yet a test but we could require it to be
        Run with --nocapture to see the spread */
        for value in &normalized {
            print!("  {value} %");
            if *value < ifreq * 0.85 {
                println!(" : too low (15% below ideal)");
            } else if *value > ifreq * 1.15 {
                println!(" : too high (15% above ideal)");
            } else {
                println!(" : fair");
            }
        }
    }
}
