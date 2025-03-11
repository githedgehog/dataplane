// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[cfg(test)]
#[allow(dead_code, unused_imports)]
#[allow(dead_code, unused_import_braces, clippy::unused_imports)]
pub mod packet_utils {
    use crate::packet::{InvalidPacket, Packet};
    use net::buffer::TestBuffer;
    use net::eth::Eth;
    use net::eth::ethtype::EthType;
    use net::eth::mac::{DestinationMac, Mac, SourceMac};
    use net::headers::{Headers, Net, Transport};
    use net::ip::NextHeader;
    use net::ipv4::Ipv4;
    use net::ipv4::addr::UnicastIpv4Addr;
    use net::parse::DeParse;
    use net::udp::Udp;
    use net::udp::port::UdpPort;
    use std::default::Default;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    /// Builds a test packet with the given TTL value.
    ///
    /// The packet is an IPv4 packet with a source and destination IP address of 1.2.3.4.
    /// The Ethernet source and destination MAC addresses are 0x02:00:00:00:00:01 and 0x02:00:00:00:00:02
    /// respectively.
    ///
    pub fn build_test_ipv4_packet(
        ttl: u8,
    ) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(1, 2, 3, 4)).unwrap());
        ipv4.set_destination(Ipv4Addr::new(1, 2, 3, 4));
        ipv4.set_ttl(ttl);

        let mut headers = Headers::new(Eth::new(
            SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
            DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 2])).unwrap(),
            EthType::IPV4,
        ));
        headers.net = Some(Net::Ipv4(ipv4));

        let mut buffer: TestBuffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();

        Packet::new(buffer)
    }

    /// Build an Ipv4 address from a &str
    pub fn addr_v4(a: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(a).expect("Bad IPv4 address")
    }

    /// Builds a UDP/IPv4/Eth frame
    #[allow(unsafe_code)]
    pub fn build_test_udp_ipv4_frame(
        src_mac: Mac,
        dst_mac: Mac,
        src_ip: &str,
        dst_ip: &str,
        sport: u16,
        dport: u16,
    ) -> Packet<TestBuffer> {
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(UnicastIpv4Addr::new(addr_v4(src_ip)).expect("Bad unicast IPv4"));
        ipv4.set_destination(addr_v4(dst_ip));
        ipv4.set_ttl(255);
        unsafe {
            ipv4.set_next_header(NextHeader::UDP);
        }

        let mut headers = Headers::new(Eth::new(
            SourceMac::new(src_mac).unwrap(),
            DestinationMac::new(dst_mac).unwrap(),
            EthType::IPV4,
        ));
        headers.net = Some(Net::Ipv4(ipv4));

        let mut udp = Udp::empty();
        udp.set_source(UdpPort::new_checked(sport).expect("Bad src port"));
        udp.set_destination(UdpPort::new_checked(dport).expect("Bad dst port"));
        headers.transport = Some(Transport::Udp(udp));

        let mut buffer: TestBuffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();

        Packet::new(buffer).unwrap()
    }

    #[allow(unsafe_code)]
    pub fn build_test_udp_ipv4_packet(
        src_ip: &str,
        dst_ip: &str,
        sport: u16,
        dport: u16,
    ) -> Packet<TestBuffer> {
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(UnicastIpv4Addr::new(addr_v4(src_ip)).expect("Bad unicast IPv4"));
        ipv4.set_destination(addr_v4(dst_ip));
        ipv4.set_ttl(255);
        unsafe {
            ipv4.set_next_header(NextHeader::UDP);
        }

        let mut headers = Headers::new(Eth::new(
            SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
            DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
            EthType::IPV4,
        ));
        headers.net = Some(Net::Ipv4(ipv4));

        let mut udp = Udp::empty();
        udp.set_source(UdpPort::new_checked(sport).expect("Bad src port"));
        udp.set_destination(UdpPort::new_checked(dport).expect("Bad dst port"));
        headers.transport = Some(Transport::Udp(udp));

        let mut buffer: TestBuffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();

        Packet::new(buffer).unwrap()
    }
}
