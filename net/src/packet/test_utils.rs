// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]
#![allow(clippy::double_must_use)]
#![allow(missing_docs)]

use crate::buffer::TestBuffer;
use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::eth::mac::{DestinationMac, Mac, SourceMac};
use crate::headers::{HeadersBuilder, Net, Transport};
use crate::ip::NextHeader;
use crate::ipv4::Ipv4;
use crate::ipv4::addr::UnicastIpv4Addr;
use crate::packet::{InvalidPacket, Packet};
use crate::parse::DeParse;
use crate::udp::Udp;
use crate::udp::port::UdpPort;
use std::default::Default;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[must_use]
/// Builds a test packet with the given TTL value.
///
/// The packet is an IPv4 packet with a source IP address of 1.2.3.4 and a destination of 5.6.7.8.
/// The Ethernet source and destination MAC addresses are 0x02:00:00:00:00:01 and 0x02:00:00:00:00:02
/// respectively.
pub fn build_test_ipv4_packet(ttl: u8) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let mut headers = HeadersBuilder::default();
    headers.eth(Some(Eth::new(
        SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
        DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 2])).unwrap(),
        EthType::IPV4,
    )));
    let mut ipv4 = Ipv4::default();
    ipv4.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(1, 2, 3, 4)).unwrap());
    ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
    ipv4.set_ttl(ttl);
    headers.net(Some(Net::Ipv4(ipv4)));

    let headers = headers.build().unwrap();
    let mut buffer: TestBuffer = TestBuffer::new();
    headers.deparse(buffer.as_mut()).unwrap();
    Packet::new(buffer)
}

#[must_use]
/// Build an Ipv4 address from a &str
pub fn addr_v4(a: &str) -> Ipv4Addr {
    Ipv4Addr::from_str(a).expect("Bad IPv4 address")
}

#[must_use]
#[allow(unsafe_code)]
/// Builds a UDP/IPv4/Eth frame
pub fn build_test_udp_ipv4_frame(
    src_mac: Mac,
    dst_mac: Mac,
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
) -> Packet<TestBuffer> {
    let mut headers = HeadersBuilder::default();

    headers.eth(Some(Eth::new(
        SourceMac::new(src_mac).unwrap(),
        DestinationMac::new(dst_mac).unwrap(),
        EthType::IPV4,
    )));

    let mut ipv4 = Ipv4::default();
    ipv4.set_source(UnicastIpv4Addr::new(addr_v4(src_ip)).expect("Bad unicast IPv4"));
    ipv4.set_destination(addr_v4(dst_ip));
    ipv4.set_ttl(255);
    ipv4.set_next_header(NextHeader::UDP);
    headers.net(Some(Net::Ipv4(ipv4)));

    let mut udp = Udp::empty();
    udp.set_source(UdpPort::new_checked(sport).expect("Bad src port"));
    udp.set_destination(UdpPort::new_checked(dport).expect("Bad dst port"));
    headers.transport(Some(Transport::Udp(udp)));

    let mut buffer: TestBuffer = TestBuffer::new();
    headers.build().unwrap().deparse(buffer.as_mut()).unwrap();

    Packet::new(buffer).unwrap()
}

#[must_use]
#[allow(unsafe_code)]
pub fn build_test_udp_ipv4_packet(
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
) -> Packet<TestBuffer> {
    build_test_udp_ipv4_frame(
        Mac([0x2, 0, 0, 0, 0, 1]),
        Mac([0x2, 0, 0, 0, 0, 1]),
        src_ip,
        dst_ip,
        sport,
        dport,
    )
}
