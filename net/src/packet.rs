//! Packet abstraction

use crate::eth::Mac;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use etherparse::err::packet::SliceError;
use etherparse::err::Layer;
use etherparse::{
    EtherType, Ethernet2Header, Ipv4Header, Ipv6Header, LaxPacketHeaders, LinkHeader, NetHeaders,
    TransportHeader, VlanHeader,
};

/// TODO
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpHeader {
    /// An IPv4 Header (does not include extensions)
    V4(Ipv4Header),
    /// An IPv6 Header (does not include extensions)
    V6(Ipv6Header),
}

/// TODO
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketHeader {
    /// Ethernet II header if present.
    link: Ethernet2Header,
    /// Single or double vlan headers if present.
    vlan: Option<VlanHeader>,
    /// IPv4 or IPv6 header and IP extension headers if present.
    net: Option<IpHeader>,
    /// TCP or UDP header if present.
    transport: Option<TransportHeader>,
}

impl PacketHeader {
    /// Return the source [`Mac`] of the parsed packet
    pub fn eth_src(&self) -> Mac {
        Mac::from(self.link.source)
    }

    /// Return the destination [`Mac`] of the parsed packet
    pub fn eth_dst(&self) -> Mac {
        Mac::from(self.link.destination)
    }

    /// Return the [`EtherType`] of the parsed packet
    pub fn ethertype(&self) -> EtherType {
        self.link.ether_type
    }

    /// Return the source ip of the parsed packet if available
    pub fn ipv4_src(&self) -> Option<Ipv4Addr> {
        match self.net.as_ref() {
            Some(IpHeader::V4(ip)) => Some(Ipv4Addr::from(ip.source)),
            Some(IpHeader::V6(_)) => None,
            None => None,
        }
    }

    /// Return the destination ip of the parsed packet if available
    pub fn ipv4_dst(&self) -> Option<Ipv4Addr> {
        match self.net.as_ref() {
            Some(IpHeader::V4(ip)) => Some(Ipv4Addr::from(ip.destination)),
            Some(IpHeader::V6(_)) => None,
            None => None,
        }
    }

    /// Return the source ip of the parsed packet if available
    pub fn ipv6_src(&self) -> Option<Ipv6Addr> {
        match self.net.as_ref() {
            Some(IpHeader::V6(ip)) => Some(Ipv6Addr::from(ip.source)),
            Some(IpHeader::V4(_)) => None,
            None => None,
        }
    }

    /// Return the destination ip of the parsed packet if available
    pub fn ipv6_dst(&self) -> Option<Ipv6Addr> {
        match self.net.as_ref() {
            Some(IpHeader::V6(ip)) => Some(Ipv6Addr::from(ip.destination)),
            Some(IpHeader::V4(_)) => None,
            None => None,
        }
    }

    /// Return the source ip of the parsed packet if available
    pub fn ip_src(&self) -> Option<IpAddr> {
        self.net.as_ref().map(|ip| match ip {
            IpHeader::V4(ip) => IpAddr::from(ip.source),
            IpHeader::V6(ip) => IpAddr::from(ip.source),
        })
    }

    /// Return the destination ip of the parsed packet if available
    pub fn ip_dst(&self) -> Option<IpAddr> {
        self.net.as_ref().map(|ip| match ip {
            IpHeader::V4(ip) => IpAddr::from(ip.destination),
            IpHeader::V6(ip) => IpAddr::from(ip.destination),
        })
    }
}

/// TODO
pub struct Packet {
    ingress_interface: u32, // TODO: proper type
    egress_interface: u32,  // TODO: proper type
    headers: PacketHeader,
}

impl PacketHeader {
    /// TODO
    ///
    /// # Errors
    ///
    /// TODO
    pub fn from_raw(raw: Vec<u8>) -> Result<PacketHeader, (SliceError, Layer)> {
        let headers = LaxPacketHeaders::from_ethernet(raw.as_ref())
            .map_err(|e| (SliceError::Len(e), Layer::Ethernet2Header))?;
        if let Some((err, layer)) = headers.stop_err {
            let err = match err {
                SliceError::Len(_) => {
                    unreachable!("buffer smaller than length of parsed packet headers");
                }
                SliceError::LinuxSll(_) => unreachable!("LinuxSll not currently supported"),
                _ => err,
            };
            return Err((err, layer));
        }
        Ok(PacketHeader {
            link: match headers.link.expect("link header missing") {
                LinkHeader::LinuxSll(_) => {
                    unreachable!("LinuxSll not currently supported")
                }
                LinkHeader::Ethernet2(link) => link,
            },
            vlan: headers.vlan,
            net: headers.net.map(|h| match h {
                NetHeaders::Ipv4(h, _) => IpHeader::V4(h),
                NetHeaders::Ipv6(h, _) => IpHeader::V6(h),
            }),
            transport: headers.transport,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod test {
    use crate::eth::Mac;
    use crate::ipv4::Ipv4;
    use crate::packet::{IpHeader, PacketHeader};
    use alloc::vec::Vec;
    use bolero::Driver;
    use core::net::Ipv4Addr;
    use core::num::NonZero;
    use core::ops::Bound;
    use etherparse::{IpNumber, PacketBuilder, TransportHeader};
    use tracing_test::traced_test;

    const MAX_PACKET_LENGTH: usize = 9200;

    #[derive(Clone, Debug)]
    #[cfg_attr(any(feature = "bolero", test, kani), derive(bolero::TypeGenerator))]
    struct Tcp4TestData {
        eth_src: Mac,
        eth_dst: Mac,
        ip_src: Ipv4,
        ip_dst: Ipv4,
        ttl: u8,
        src_port: NonZero<u16>,
        dst_port: NonZero<u16>,
        length: usize,
        sequence_number: u32,
        window_size: u16,
    }

    #[derive(Clone, Debug)]
    #[cfg_attr(any(feature = "bolero", test, kani), derive(bolero::TypeGenerator))]
    struct Udp4TestData {
        eth_src: Mac,
        eth_dst: Mac,
        ip_src: Ipv4,
        ip_dst: Ipv4,
        ttl: u8,
        src_port: NonZero<u16>,
        dst_port: NonZero<u16>,
        length: usize,
    }

    impl Udp4TestData {
        fn as_raw(&self) -> Vec<u8> {
            let builder = PacketBuilder::ethernet2(self.eth_src.into(), self.eth_dst.into())
                .ipv4(
                    self.ip_src.addr.octets(),
                    self.ip_dst.addr.octets(),
                    self.ttl,
                )
                .udp(self.src_port.get(), self.dst_port.get());
            let size = builder.size(0);
            let payload = [];
            let mut buffer = Vec::with_capacity(builder.size(0));
            builder.write(&mut buffer, &payload).unwrap();
            buffer
        }
    }

    impl Tcp4TestData {
        fn as_raw(&self) -> Vec<u8> {
            let builder = PacketBuilder::ethernet2(*self.eth_src.as_ref(), *self.eth_dst.as_ref())
                .ipv4(
                    self.ip_src.addr.octets(),
                    self.ip_dst.addr.octets(),
                    self.ttl,
                )
                .tcp(
                    self.src_port.get(),
                    self.dst_port.get(),
                    self.sequence_number,
                    self.window_size,
                );
            let mut payload = Vec::with_capacity(builder.size(self.length));
            for _ in 0..self.length {
                payload.push(rand::random());
            }
            let mut buffer = Vec::with_capacity(builder.size(payload.len()));
            builder.write(&mut buffer, &payload).unwrap();
            buffer
        }
    }

    #[test]
    fn from_raw_parse_udp_packet() {
        let eth_src = [0, 1, 2, 3, 4, 5];
        let eth_dst = [6, 7, 8, 9, 10, 11];
        let ip_src = [192, 168, 32, 53];
        let ip_dst = [169, 254, 32, 53];
        let ttl = 20;
        let src_port = 21;
        let dst_port = 1234;
        let mut builder = PacketBuilder::ethernet2(eth_src, eth_dst)
            .ipv4(ip_src, ip_dst, ttl)
            .udp(src_port, dst_port);
        let mut buffer = Vec::with_capacity(builder.size(0));
        builder.write(&mut buffer, &[]).unwrap();
        let headers = PacketHeader::from_raw(buffer).unwrap();
        assert_eq!(eth_src, headers.link.source);
        assert_eq!(eth_dst, headers.link.destination);
        let ip = match headers.net.expect("no ip header") {
            IpHeader::V4(v4) => v4,
            IpHeader::V6(v6) => unreachable!("not an ipv6 packet"),
        };
        assert_eq!(ip_src, ip.source);
        assert_eq!(ip_dst, ip.destination);
        assert_eq!(ip.protocol, IpNumber::UDP);
        let udp = match headers.transport.expect("no transport header") {
            TransportHeader::Udp(udp) => udp,
            _ => unreachable!("not a udp packet"),
        };
        assert_eq!(src_port, udp.source_port);
        assert_eq!(dst_port, udp.destination_port);
    }

    #[test]
    fn udp4_parse_fuzz_test() {
        bolero::check!().with_type().for_each(|val: &Udp4TestData| {
            let headers = PacketHeader::from_raw(val.as_raw()).expect("failed to parse packet");
            assert_eq!(
                val.eth_src,
                Mac::from(headers.link.source),
                "source mac mismatch"
            );
            assert_eq!(
                val.eth_dst,
                Mac::from(headers.link.destination),
                "destination mac mismatch"
            );
            let ip = match headers.net.expect("no ip header") {
                IpHeader::V4(v4) => v4,
                IpHeader::V6(_) => unreachable!("not an ipv6 packet"),
            };
            assert_eq!(val.ip_src.addr.octets(), ip.source);
            assert_eq!(val.ip_dst.addr.octets(), ip.destination);
            assert_eq!(val.ttl, ip.time_to_live);
            assert_eq!(ip.protocol, IpNumber::UDP, "protocol mismatch");
            let udp = match headers.transport.expect("no transport header") {
                TransportHeader::Udp(udp) => udp,
                _ => unreachable!("not a udp packet"),
            };
            assert_eq!(val.src_port.get(), udp.source_port, "source port mismatch");
            assert_eq!(
                val.dst_port.get(),
                udp.destination_port,
                "destination port mismatch"
            );
        });
    }

    #[test]
    fn tcp4_parse_fuzz_test() {
        bolero::check!().with_type().for_each(|val: &Tcp4TestData| {
            let headers = PacketHeader::from_raw(val.as_raw()).expect("failed to parse packet");
            assert_eq!(
                val.eth_src,
                Mac::from(headers.link.source),
                "source mac mismatch"
            );
            assert_eq!(
                val.eth_dst,
                Mac::from(headers.link.destination),
                "destination mac mismatch"
            );
            let ip = match headers.net.expect("no ip header") {
                IpHeader::V4(v4) => v4,
                IpHeader::V6(v6) => unreachable!("not an ipv6 packet"),
            };
            assert_eq!(val.ip_src.addr.octets(), ip.source);
            assert_eq!(val.ip_dst.addr.octets(), ip.destination);
            assert_eq!(val.ttl, ip.time_to_live);
            assert_eq!(ip.protocol, IpNumber::TCP, "protocol mismatch");
            let tcp = match headers.transport.expect("no transport header") {
                TransportHeader::Tcp(tcp) => tcp,
                _ => unreachable!("not a tcp packet"),
            };
            assert_eq!(val.src_port.get(), tcp.source_port, "source port mismatch");
            assert_eq!(
                val.dst_port.get(),
                tcp.destination_port,
                "destination port mismatch"
            );
        });
    }
}
