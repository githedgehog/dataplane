// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module to compute packet hashes

use crate::buffer::PacketBufferMut;
use crate::headers::{Net, Transport, TryHeaders, TryIp, TryTransport};
use crate::packet::Packet;
use ahash::AHasher;
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

#[cfg(test)]
mod tests {
    use crate::buffer::{PacketBufferMut, TestBuffer};
    use crate::packet::Packet;
    use crate::packet::test_utils::*;
    use ahash::AHasher;
    use ordermap::OrderMap;
    use std::collections::BTreeMap;
    use std::fs;
    use std::fs::File;
    use std::hash::Hasher;
    use std::io::Write;

    // compute ip hash using ahash hasher
    fn hash_ip_packet<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> u64 {
        let mut hasher = AHasher::default();
        packet.hash_ip(&mut hasher);
        hasher.finish()
    }
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
    // create fingerprint file
    fn create_ahash_fingerprint() {
        let packets = build_test_packets(500);
        let mut vals: OrderMap<u16, u64> = OrderMap::new();
        for (n, packet) in packets.iter().enumerate() {
            let hash_value = hash_ip_packet(packet);
            vals.insert(u16::try_from(n).expect("Conversion failed"), hash_value);
        }
        let mut file = File::create("net/artifacts/ahash_fingerprint.txt")
            .expect("Failed to open ahash fingerprint file");
        file.write_all(format!("{vals:#?}").as_bytes())
            .expect("Failed to write fingerprint");
    }

    // hashes the test packets storing the results in an ordermap and then compares
    // the whole ordermap with a reference stored in net/artifacts/ahash_fingerprint.
    // This test should fail if ahash changes to produce distinct output.
    // If that happens, set update_fingerprint to true and commit the fingerprint
    // file.
    #[test]
    fn test_ahash_detect_change() {
        let update_fingerprint = false;
        if update_fingerprint {
            create_ahash_fingerprint();
        }
        let packets = build_test_packets(500);
        let mut vals: OrderMap<u16, u64> = OrderMap::new();
        for (n, packet) in packets.iter().enumerate() {
            let hash_value = hash_ip_packet(packet);
            vals.insert(u16::try_from(n).expect("Conversion failed"), hash_value);
        }
        let fingerprint = format!("{vals:#?}");
        let reference = fs::read_to_string("net/artifacts/ahash_fingerprint.txt")
            .expect("Missing fingerprint file");
        assert_eq!(fingerprint, reference);
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
