// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg_attr(not(any(test, feature = "_assert-no-panic")), no_std)] // This library should always compile without std (even if we never ship that way)
#![forbid(unsafe_code)] // Validation logic should always be strictly safe
#![deny(missing_docs, clippy::all, clippy::pedantic)] // yeah, I'm that guy.  I'm not sorry.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Do you know where your towel is?

//! A library for working with and strictly validating network data

extern crate alloc;

pub mod vlan;
pub mod vxlan;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use etherparse::err::packet::SliceError;
    use etherparse::NetHeaders;
    use tracing::info;
    use tracing_test::traced_test;

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
    #[traced_test]
    pub fn parse_udp_packet() {
        use etherparse::PacketHeaders;
        let packet = gen_random_udp_packet();
        let headers = PacketHeaders::from_ethernet_slice(packet.as_slice()).unwrap();
        info!("Headers: {:?}", headers);
    }

    #[test]
    #[traced_test]
    fn parse_udp_packet_bit_by_bit() {
        let mut packet = gen_random_udp_packet();
        let mut header = etherparse::Ethernet2Header::from_slice(packet.as_slice())
            .unwrap()
            .0;
        header.source = [0, 1, 2, 3, 4, 5];
        header.destination = [6, 7, 8, 9, 10, 11];
        header.write_to_slice(packet.as_mut_slice()).unwrap();
        match etherparse::PacketHeaders::from_ethernet_slice(&packet) {
            Ok(headers) => {
                let eth = headers.link.unwrap().ethernet2().unwrap();
                assert_eq!(eth.source, [0, 1, 2, 3, 4, 5]);
                assert_eq!(eth.destination, [6, 7, 8, 9, 10, 11]);
            }
            Err(err) => {
                panic!("{err:?}");
            }
        };
    }
}
