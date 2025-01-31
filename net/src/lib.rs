// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library for working with and validating network data

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(clippy::should_panic_without_expect)] // we panic in contract checks with simple unwrap()

extern crate alloc;

pub mod vlan;
pub mod vxlan;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    pub fn gen_random_udp_packet() -> Vec<u8> {
        use etherparse::PacketBuilder;
        let src_mac: [u8; 6] = rand::random();
        let dst_mac: [u8; 6] = rand::random();
        let src_ip: [u8; 4] = rand::random();
        let dst_ip: [u8; 4] = rand::random();
        let src_port: u16 = rand::random();
        let dst_port: u16 = rand::random();
        let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
            .ipv4(src_ip, dst_ip, rand::random())
            .udp(src_port, dst_port);
        let payload_length = (rand::random::<u16>() % 1200) as usize;
        let mut payload = Vec::with_capacity(payload_length + 50);
        for _ in 0..payload_length {
            payload.push(rand::random());
        }
        let mut result = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut result, &payload).unwrap();
        result
    }

    #[test]
    pub fn parse_udp_packet() {
        use etherparse::PacketHeaders;
        let packet = gen_random_udp_packet();
        let headers = PacketHeaders::from_ethernet_slice(packet.as_slice()).unwrap();
        tracing::info!("Headers: {:?}", headers);
    }

    #[test]
    fn parse_udp_packet_bit_by_bit() {
        let packet = gen_random_udp_packet();
        let cursor = 0;
        let _eth = etherparse::Ethernet2Header::from_slice(&packet[cursor..]).unwrap();
    }
}
