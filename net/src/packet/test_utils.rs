// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    unsafe_code
)]
#![allow(clippy::double_must_use)]
#![allow(missing_docs)]

use crate::buffer::TestBuffer;
use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::eth::mac::{DestinationMac, Mac, SourceMac};
use crate::headers::MAX_VLANS;
use crate::headers::{HeadersBuilder, Net, Transport};
use crate::ip::NextHeader;
use crate::ipv4::Ipv4;
use crate::ipv4::addr::UnicastIpv4Addr;
use crate::ipv6::Ipv6;
use crate::ipv6::addr::UnicastIpv6Addr;
use crate::packet::{InvalidPacket, Packet};
use crate::parse::DeParse;
use crate::tcp::Tcp;
use crate::udp::Udp;
use crate::vlan::Vlan;
use crate::vlan::{Pcp, Vid};

use arrayvec::ArrayVec;
use etherparse::IpNumber;
use std::default::Default;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZero;
use std::str::FromStr;

#[derive(Debug)]
struct TestUdp {
    sport: u16,
    dport: u16,
}
impl TestUdp {
    pub fn sport(&mut self, value: u16) -> &mut Self {
        self.sport = value;
        self
    }
    pub fn dport(&mut self, value: u16) -> &mut Self {
        self.dport = value;
        self
    }
}
impl Default for TestUdp {
    fn default() -> Self {
        Self {
            sport: 123,
            dport: 456,
        }
    }
}

#[derive(Debug)]
struct TestTcp {
    sport: u16,
    dport: u16,
}
impl Default for TestTcp {
    fn default() -> Self {
        Self {
            sport: 123,
            dport: 456,
        }
    }
}
impl TestTcp {
    pub fn sport(&mut self, value: u16) -> &mut Self {
        self.sport = value;
        self
    }
    pub fn dport(&mut self, value: u16) -> &mut Self {
        self.dport = value;
        self
    }
}

#[derive(Debug)]
struct TestIcmp {
    //todo
}
impl Default for TestIcmp {
    fn default() -> Self {
        Self {
            // todo
        }
    }
}

#[derive(Debug)]
pub struct TestPacket {
    ttl: u8,
    vlanids: ArrayVec<u16, MAX_VLANS>,
    src_mac: String,
    dst_mac: String,
    src_ip: String,
    dst_ip: String,
    proto: u8,
    udp: Option<TestUdp>,
    tcp: Option<TestTcp>,
    icmp: Option<TestIcmp>,

    sport: u16, /* source port: ignored if transport is not UDP/TCP */
    dport: u16, /* dest port: ignored if transport is not UDP/TCP */
    data: Vec<u8>,
}
impl Default for TestPacket {
    fn default() -> Self {
        Self {
            ttl: 64,
            vlanids: ArrayVec::new(),
            src_mac: "02:00:00:00:00:01".to_string(),
            dst_mac: "02:00:00:00:00:02".to_string(),
            src_ip: "1.2.3.4".to_string(),
            dst_ip: "5.6.7.8".to_string(),
            proto: 17,
            udp: None,
            tcp: None,
            icmp: None,
            sport: 123,
            dport: 456,
            data: vec![],
        }
    }
}
impl TestPacket {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn ttl(mut self, value: u8) -> Self {
        self.ttl = value;
        self
    }
    pub fn src_mac(mut self, value: &str) -> Self {
        self.src_mac = value.to_owned();
        self
    }
    pub fn dst_mac(mut self, value: &str) -> Self {
        self.dst_mac = value.to_owned();
        self
    }
    pub fn vlan(mut self, value: u16) -> Self {
        if !self.vlanids.is_empty() {
            panic!("Only one vlan is currently supported");
        }
        self.vlanids.push(value);
        self
    }
    pub fn src_ip(mut self, value: &str) -> Self {
        self.src_ip = value.to_owned();
        self
    }
    pub fn dst_ip(mut self, value: &str) -> Self {
        self.dst_ip = value.to_owned();
        self
    }
    pub fn proto(mut self, value: u8) -> Self {
        self.proto = value;
        self
    }
    pub fn udp(&mut self) -> &mut TestUdp {
        if self.udp.is_none() {
            self.udp = Some(TestUdp::default())
        }
        self.udp.as_mut().unwrap()
    }
    pub fn tcp(&mut self) -> &mut TestTcp {
        if self.tcp.is_none() {
            self.tcp = Some(TestTcp::default())
        }
        self.tcp.as_mut().unwrap()
    }
    pub fn icmp(&mut self) -> &mut TestIcmp {
        if self.icmp.is_none() {
            self.icmp = Some(TestIcmp::default())
        }
        self.icmp.as_mut().unwrap()
    }
    pub fn sport(mut self, value: u16) -> Self {
        self.sport = value;
        self
    }
    pub fn dport(mut self, value: u16) -> Self {
        self.dport = value;
        self
    }
    pub fn set_data(mut self, data: &[u8]) -> Self {
        self.data = data.to_vec();
        self
    }
    pub fn data_len(&self) -> u16 {
        self.data.len() as u16
    }
    pub fn build(&self) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
        let transport_type = NextHeader::from(IpNumber::from(self.proto));
        let mut headers = HeadersBuilder::default();
        let mut transport = match transport_type {
            NextHeader::TCP => {
                let mut tcp = Tcp::default();
                tcp.set_source(self.sport.try_into().expect("Bad tcp source port"));
                tcp.set_destination(self.dport.try_into().expect("Bad tcp dst port"));
                tcp.set_syn(true);
                tcp.set_sequence_number(1);
                Some(Transport::Tcp(tcp))
            }
            NextHeader::UDP => {
                let mut udp = Udp::default();
                udp.set_source(self.sport.try_into().expect("Bad udp source port"));
                udp.set_destination(self.dport.try_into().expect("Bad udp dst port"));
                unsafe {
                    udp.set_length(NonZero::new(8 + self.data_len()).expect("Bad udp length"));
                }
                Some(Transport::Udp(udp))
            }
            _ => None,
        };

        // ============== ethernet ================= //
        let smac = Mac::try_from(self.src_mac.as_str()).expect("bad src mac");
        let dmac = Mac::try_from(self.dst_mac.as_str()).expect("bad dst mac");
        let ether_type = if self.vlanids.is_empty() {
            EthType::IPV4
        } else {
            EthType::VLAN
        };
        let eth = Eth::new(
            SourceMac::new(smac).unwrap(),
            DestinationMac::new(dmac).unwrap(),
            ether_type,
        );

        // ============== vlan ================= //
        let vlans: ArrayVec<_, MAX_VLANS> = self
            .vlanids
            .iter()
            .map(|vlanids| {
                let mut vlan = Vlan::new(
                    Vid::new(*vlanids).unwrap(),
                    EthType::IPV4,
                    Pcp::new(0).unwrap(),
                    false,
                );
                vlan.set_inner_ethtype(EthType::IPV4);
                vlan
            })
            .collect();

        // ============== IPv4 ================= //
        let mut ipv4 = Ipv4::default();
        let sip = Ipv4Addr::from_str(self.src_ip.as_str()).expect("Bad src ip");
        let dip = Ipv4Addr::from_str(self.dst_ip.as_str()).expect("Bad dst ip");

        ipv4.set_source(UnicastIpv4Addr::new(sip).unwrap());
        ipv4.set_destination(dip);
        ipv4.set_ttl(self.ttl);

        // ============== Transport ================= //
        if let Some(transport) = transport.as_ref() {
            ipv4.set_payload_len(transport.size().get() + self.data_len())
                .unwrap();
            ipv4.set_next_header(transport_type);
        }

        let mut net = Net::Ipv4(ipv4);
        net.update_checksum();
        if let Some(transport) = transport.as_mut() {
            transport.update_checksum(&net, None, &self.data);
        }

        // build headers
        headers.eth(Some(eth));
        headers.net(Some(net));
        headers.vlan(vlans);
        headers.transport(transport);
        let headers = headers.build().unwrap();

        // prepare buffer
        let headers_size = headers.size().get() as usize;
        let onwire = vec![0; headers_size + self.data_len() as usize];
        let mut buffer = TestBuffer::from_raw_data(&onwire);
        let len = headers.deparse(buffer.as_mut()).unwrap().get() as usize;
        buffer.as_mut()[len..len + self.data_len() as usize].copy_from_slice(&self.data);
        let buffer_clone = buffer.clone();

        let new = Packet::new(buffer_clone).unwrap();
        let new_clone = new.clone();

        let serialized_buff = new.serialize().unwrap();
        assert_eq!(buffer.as_ref(), serialized_buff.as_ref());
        Ok(new_clone)
    }
}

#[cfg(test)]
pub mod playground {
    use std::u8;

    use crate::packet::test_utils::TestPacket;

    #[test]
    fn packet_playground() {
        let mut data = vec![];
        for n in 0..4 as usize {
            let value = (n & u8::MAX as usize) as u8;
            data.push(value);
        }
        /*
              let packet = TestPacket::new()
                  .ttl(64)
                  .vlan(100)
                  .src_ip("4.4.4.4")
                  .dst_ip("8.8.8.8")
                  .proto(17)
                  .dport(53)
                  .set_data(data.as_slice())
                  .build()
                  .unwrap();
        */

        let mut packet = TestPacket::new();
        packet.udp().sport(555).dport(666);
        packet.tcp().sport(987).dport(777);
        packet.icmp();
        println!("{packet:#?}");
        let packet = packet.build().unwrap();

        println!("{packet}");
    }

    use crate::packet::test_utils::build_test_ipv4_packet;
    #[test]
    fn packet_util() {
        let packet = build_test_ipv4_packet(u8::MAX).unwrap();

        println!("{packet}")
    }
}

/// Builds a test ipv4 packet with the optional provided fields.
///
/// Unless overriden by arguments, the packet is an IPv4 packet with a source IP address of `1.2.3.4`
/// and a destination of `5.6.7.8`. The Ethernet source and destination MAC addresses are
/// 0x02:00:00:00:00:01 and 0x02:00:00:00:00:02 respectively.
/// The source and destination ports are 123 and 456 respectively for TCP and UDP.
///
/// Tests can use the utility functions on [`Packet`] to then customize the addresses and ports as
/// desired.
///
/// # Panics
///
/// Panics if the transport type is anything other than `Some(NextHeader::TCP)`, `Some(NextHeader::UDP)` or
/// if the provided arguments are invalid.
///
fn test_ipv4_packet_builder(
    ttl: Option<u8>,
    src_mac: Option<&str>,
    dst_mac: Option<&str>,
    ip_src: Option<&str>,
    ip_dst: Option<&str>,
    transport_type: Option<NextHeader>,
    sport: Option<u16>, /* source port: ignored if transport not set */
    dport: Option<u16>, /* dest port: ignored if transport not set */
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let mut headers = HeadersBuilder::default();

    let mut transport = match transport_type {
        Some(NextHeader::TCP) => {
            let mut tcp = Tcp::default();
            tcp.set_source(
                sport
                    .unwrap_or(123)
                    .try_into()
                    .expect("Bad tcp source port"),
            );
            tcp.set_destination(dport.unwrap_or(456).try_into().expect("Bad tcp dst port"));
            tcp.set_syn(true);
            tcp.set_sequence_number(1);
            Some(Transport::Tcp(tcp))
        }

        Some(NextHeader::UDP) => {
            let mut udp = Udp::default();
            udp.set_source(
                sport
                    .unwrap_or(123)
                    .try_into()
                    .expect("Bad udp source port"),
            );
            udp.set_destination(dport.unwrap_or(456).try_into().expect("Bad udp dst port"));
            Some(Transport::Udp(udp))
        }

        Some(transport_type) => panic!(
            "build_test_ipv4_packet_with_transport: Unsupported transport type: {transport_type:?}"
        ),
        None => None,
    };

    // ethernet
    let smac = Mac::try_from(src_mac.unwrap_or("02:00:00:00:00:01")).expect("bad src mac");
    let dmac = Mac::try_from(dst_mac.unwrap_or("02:00:00:00:00:02")).expect("bad dst mac");
    headers.eth(Some(Eth::new(
        SourceMac::new(smac).unwrap(),
        DestinationMac::new(dmac).unwrap(),
        EthType::IPV4,
    )));

    // Ipv4
    let mut ipv4 = Ipv4::default();
    let sip = Ipv4Addr::from_str(ip_src.unwrap_or("1.2.3.4")).expect("Bad src ip");
    let dip = Ipv4Addr::from_str(ip_dst.unwrap_or("5.6.7.8")).expect("Bad dst ip");

    ipv4.set_source(UnicastIpv4Addr::new(sip).unwrap());
    ipv4.set_destination(dip);
    ipv4.set_ttl(ttl.unwrap_or(64));
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
    test_ipv4_packet_builder(
        Some(ttl),
        None,
        None,
        None,
        None,
        transport_type,
        None,
        None,
    )
}

#[must_use]
/// Builds a test packet with the given TTL value.
///
/// The packet is an IPv4 packet with a source IP address of 1.2.3.4 and a destination of 5.6.7.8.
/// The Ethernet source and destination MAC addresses are 0x02:00:00:00:00:01 and 0x02:00:00:00:00:02
/// respectively.
pub fn build_test_ipv4_packet(ttl: u8) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    test_ipv4_packet_builder(Some(ttl), None, None, None, None, None, None, None)
}

#[must_use]
#[allow(unsafe_code)]
/// Builds a UDP/IPv4/Eth frame
pub fn build_test_udp_ipv4_frame(
    src_mac: &str,
    dst_mac: &str,
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
) -> Packet<TestBuffer> {
    test_ipv4_packet_builder(
        Some(255),
        Some(src_mac),
        Some(dst_mac),
        Some(src_ip),
        Some(dst_ip),
        Some(NextHeader::UDP),
        Some(sport),
        Some(dport),
    )
    .expect("Failed to build ipv4 packet/frame")
}

#[must_use]
#[allow(unsafe_code)]
pub fn build_test_udp_ipv4_packet(
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
) -> Packet<TestBuffer> {
    test_ipv4_packet_builder(
        Some(255),
        None,
        None,
        Some(src_ip),
        Some(dst_ip),
        Some(NextHeader::UDP),
        Some(sport),
        Some(dport),
    )
    .expect("Failed to build ipv4 packet/frame")
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
