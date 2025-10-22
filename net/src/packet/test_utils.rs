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
use crate::checksum::Checksum;
use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::eth::mac::{DestinationMac, Mac, SourceMac};
use crate::headers::{EmbeddedHeadersBuilder, EmbeddedTransport, HeadersBuilder, Net, Transport};
use crate::icmp4::Icmp4;
use crate::ip::NextHeader;
use crate::ipv4::Ipv4;
use crate::ipv4::addr::UnicastIpv4Addr;
use crate::ipv6::Ipv6;
use crate::ipv6::addr::UnicastIpv6Addr;
use crate::packet::{InvalidPacket, Packet};
use crate::parse::DeParse;
use crate::tcp::{Tcp, TcpChecksumPayload, TruncatedTcp};
use crate::udp::Udp;
use crate::udp::port::UdpPort;
use etherparse::icmpv4::DestUnreachableHeader;
use etherparse::{Icmpv4Header, Icmpv4Type};
use std::default::Default;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZero;
use std::str::FromStr;

#[must_use]
/// Builds a test ipv4 packet with the given TTL value and transport type.
///
/// The packet is an IPv4 packet with a source IP address of `1.2.3.4` and a destination of `5.6.7.8`.
/// The Ethernet source and destination MAC addresses are 0x02:00:00:00:00:01 and 0x02:00:00:00:00:02
/// respectively.  The source and destination ports are 123 and 456 respectively for TCP and UDP.
///
/// Tests can use the utility functions on [`Packet`] to then customize the addresses and ports as
/// desired.
///
/// # Panics
///
/// Panics if the transport type is anything other than `Some(NextHeader::TCP)`, `Some(NextHeader::UDP)`, or None
///
pub fn build_test_ipv4_packet_with_transport(
    ttl: u8,
    transport_type: Option<NextHeader>,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let mut headers = HeadersBuilder::default();

    let mut transport = match transport_type {
        Some(NextHeader::TCP) => {
            let mut tcp = Tcp::default();
            tcp.set_source(123.try_into().unwrap());
            tcp.set_destination(456.try_into().unwrap());
            tcp.set_syn(true);
            tcp.set_sequence_number(1);
            Some(Transport::Tcp(tcp))
        }

        Some(NextHeader::UDP) => {
            let mut udp = Udp::default();
            udp.set_source(123.try_into().unwrap());
            udp.set_destination(456.try_into().unwrap());
            Some(Transport::Udp(udp))
        }

        Some(transport_type) => panic!(
            "build_test_ipv4_packet_with_transport: Unsupported transport type: {transport_type:?}"
        ),
        None => None,
    };

    headers.eth(Some(Eth::new(
        SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
        DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 2])).unwrap(),
        EthType::IPV4,
    )));
    let mut ipv4 = Ipv4::default();
    ipv4.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(1, 2, 3, 4)).unwrap());
    ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
    ipv4.set_ttl(ttl);
    if let Some(transport) = transport.as_ref() {
        ipv4.set_payload_len(transport.size().get()).unwrap();
        if let Some(transport_type) = transport_type {
            ipv4.set_next_header(transport_type);
        } else {
            unreachable!("build_test_ipv4_packet_with_transport: Transport type is None here");
        }
    }

    let net = Net::Ipv4(ipv4);

    if let Some(transport) = transport.as_mut() {
        transport.update_checksum(&net, None, []);
    }

    headers.net(Some(net));
    headers.transport(transport);
    let headers = headers.build().unwrap();
    let mut buffer: TestBuffer = TestBuffer::new();
    headers.deparse(buffer.as_mut()).unwrap();
    Packet::new(buffer)
}

#[must_use]
/// Builds a test packet with the given TTL value.
///
/// The packet is an IPv4 packet with a source IP address of 1.2.3.4 and a destination of 5.6.7.8.
/// The Ethernet source and destination MAC addresses are 0x02:00:00:00:00:01 and 0x02:00:00:00:00:02
/// respectively.
pub fn build_test_ipv4_packet(ttl: u8) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    build_test_ipv4_packet_with_transport(ttl, None)
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
    use crate::ip::UnicastIpAddr;
    use std::net::IpAddr;

    let mut packet = build_test_ipv4_packet_with_transport(255, Some(NextHeader::UDP)).unwrap();
    packet
        .set_eth_source(src_mac)
        .expect("Could not set src mac");
    packet
        .set_eth_destination(dst_mac)
        .expect("Could not set dst mac");
    packet
        .set_ip_source(src_ip.parse::<UnicastIpAddr>().expect("Bad src ip"))
        .expect("Could not set src ip");
    packet
        .set_ip_destination(dst_ip.parse::<IpAddr>().expect("Bad dst ip"))
        .expect("Could not set dst ip");
    packet
        .set_udp_source_port(UdpPort::new_checked(sport).expect("Bad src port"))
        .expect("Could not set src port");
    packet
        .set_udp_destination_port(UdpPort::new_checked(dport).expect("Bad dst port"))
        .expect("Could not set dst port");

    packet
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

#[must_use]
/// Builds a test packet with the given TTL value.
///
/// The packet is an IPv6 packet with a source IP address of `::1.2.3.4` and a destination of `::5.6.7.8`.
/// The Ethernet source and destination MAC addresses are 0x02:00:00:00:00:01 and 0x02:00:00:00:00:02
/// respectively.
pub fn build_test_ipv6_packet(ttl: u8) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let mut headers = HeadersBuilder::default();
    headers.eth(Some(Eth::new(
        SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
        DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 2])).unwrap(),
        EthType::IPV6,
    )));
    let mut ipv6 = Ipv6::default();
    // To construct an Ipv6Addr from a string, use FromStr or "::1.2.3.4".parse()
    ipv6.set_source(UnicastIpv6Addr::new("::1.2.3.4".parse::<Ipv6Addr>().unwrap()).unwrap());
    ipv6.set_destination("::5.6.7.8".parse::<Ipv6Addr>().unwrap());
    ipv6.set_hop_limit(ttl);
    headers.net(Some(Net::Ipv6(ipv6)));

    let headers = headers.build().unwrap();
    let mut buffer: TestBuffer = TestBuffer::new();
    headers.deparse(buffer.as_mut()).unwrap();
    Packet::new(buffer)
}

#[must_use]
/// Builds a test `ICMPv4` Destination Unreachable packet with embedded headers.
///
/// The outer packet is an IPv4 packet with the specified source and destination addresses.
/// The Ethernet source and destination MAC addresses are `0x02:00:00:00:00:01` and `0x02:00:00:00:00:02`,
/// respectively.
///
/// The embedded (inner) packet is a TCP packet with the specified source and destination IP addresses
/// and ports. The inner TCP packet has a full (not-truncated) header, but an empty payload.
pub fn build_test_icmpv4_destination_unreachable_packet(
    outer_src_ip: Ipv4Addr,
    outer_dst_ip: Ipv4Addr,
    inner_src_ip: Ipv4Addr,
    inner_dst_ip: Ipv4Addr,
    inner_src_port: NonZero<u16>,
    inner_dst_port: NonZero<u16>,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let mut headers = HeadersBuilder::default();

    // Ethernet
    headers.eth(Some(Eth::new(
        SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
        DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 2])).unwrap(),
        EthType::IPV4,
    )));

    // Inner transport
    let mut inner_transport = EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(Tcp::default()));
    inner_transport.set_source(inner_src_port).unwrap();
    inner_transport.set_destination(inner_dst_port).unwrap();

    // Inner IPv4
    let mut inner_ipv4 = Ipv4::default();
    inner_ipv4.set_source(UnicastIpv4Addr::new(inner_src_ip).unwrap());
    inner_ipv4.set_destination(inner_dst_ip);
    inner_ipv4.set_ttl(4);
    inner_ipv4.set_next_header(NextHeader::TCP);
    inner_ipv4
        .set_payload_len(inner_transport.size().get())
        .unwrap();
    inner_ipv4.update_checksum(&()).unwrap();

    // ICMP
    let icmp = Icmp4(Icmpv4Header::new(Icmpv4Type::DestinationUnreachable(
        DestUnreachableHeader::Network,
    )));

    // Outer IPv4
    let mut outer_ipv4 = Ipv4::default();
    outer_ipv4.set_source(UnicastIpv4Addr::new(outer_src_ip).unwrap());
    outer_ipv4.set_destination(outer_dst_ip);
    outer_ipv4.set_ttl(8);
    outer_ipv4.set_next_header(NextHeader::ICMP);
    outer_ipv4
        .set_payload_len(icmp.size().get() + inner_ipv4.size().get() + inner_transport.size().get())
        .unwrap();
    outer_ipv4.update_checksum(&()).unwrap();
    let outer_net = Net::Ipv4(outer_ipv4);

    // Adjustments
    let inner_net = Net::Ipv4(inner_ipv4);
    if let EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(ref mut tcp)) = inner_transport {
        tcp.update_checksum(&TcpChecksumPayload::new(&inner_net, &[]))
            .unwrap();
    }

    // Embedded headers
    let mut embedded_headers = EmbeddedHeadersBuilder::default();
    embedded_headers.net(Some(inner_net));
    embedded_headers.transport(Some(inner_transport));
    let embedded_headers = embedded_headers.build().unwrap();

    // More adjustments
    let mut icmp_transport = Transport::Icmp4(icmp);
    icmp_transport.update_checksum(&outer_net, Some(&embedded_headers), []);

    // Headers
    headers.net(Some(outer_net));
    headers.transport(Some(icmp_transport));
    headers.embedded_ip(Some(embedded_headers));
    let headers = headers.build().unwrap();

    // Packet
    let data = vec![0u8; headers.size().get() as usize];
    let mut buffer = TestBuffer::from_raw_data(&data);
    headers.deparse(buffer.as_mut()).unwrap();
    Packet::new(buffer)
}
