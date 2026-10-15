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
use crate::headers::Headers;
use crate::headers::builder::{
    Blank, BuildPacketError, EmbeddedAssembler, HeaderStack, Install, Within,
};
use crate::headers::{HeadersBuilder, Net, Transport};
use crate::icmp4::{Icmp4, Icmp4DestUnreachable, Icmp4EchoRequest, Icmp4Type};
use crate::icmp6::{Icmp6, Icmp6EchoRequest, Icmp6Type};
use crate::ip::NextHeader;
use crate::ipv4::Ipv4;
use crate::ipv4::addr::UnicastIpv4Addr;
use crate::ipv6::Ipv6;
use crate::ipv6::addr::UnicastIpv6Addr;
use crate::packet::{InvalidPacket, Packet};
use crate::parse::DeParse;
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::icmpv4::DestUnreachableHeader;
use etherparse::{Icmpv4Header, Icmpv4Type, Icmpv6Header};
use std::default::Default;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::ip::dscp::Dscp;
use crate::ip::ecn::Ecn;
use crate::vxlan::{Vni, Vxlan};

/// MACs of the default test frames.
const TEST_SRC_MAC: Mac = Mac([0x2, 0, 0, 0, 0, 1]);
const TEST_DST_MAC: Mac = Mac([0x2, 0, 0, 0, 0, 2]);

/// Map builder errors onto the helpers' error type. Only a parse failure fits; any
/// other error is a bug in the defaults.
fn into_packet(
    built: Result<Packet<TestBuffer>, BuildPacketError>,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    match built {
        Ok(packet) => Ok(packet),
        Err(BuildPacketError::Parse(invalid)) => Err(invalid),
        Err(e) => panic!("the default test packet does not build: {e}"),
    }
}

/// Add the default transport: a TCP SYN (seq 1) or UDP from port 123 to 456, or none.
#[track_caller]
fn with_default_transport<T>(
    ip: HeaderStack<T>,
    transport_type: Option<NextHeader>,
) -> Result<Packet<TestBuffer>, BuildPacketError>
where
    T: Blank,
    Headers: Install<T>,
    Tcp: Within<T>,
    Udp: Within<T>,
{
    match transport_type {
        None => ip.build_packet(),
        Some(NextHeader::TCP) => ip
            .tcp_ports(123, 456)
            .with(|tcp| {
                tcp.set_syn(true);
                tcp.set_sequence_number(1);
            })
            .build_packet(),
        Some(NextHeader::UDP) => ip.udp_ports(123, 456).build_packet(),
        Some(other) => panic!("unsupported transport type for a default test packet: {other:?}"),
    }
}

/// Creates a default Ethernet frame with the given [`EthType`].
///
/// The source MAC address is 0x02:00:00:00:00:01 and the destination MAC address is
/// 0x02:00:00:00:00:02.
#[must_use]
pub fn make_default_for_eth(ethtype: EthType) -> Eth {
    Eth::new(
        SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
        DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 2])).unwrap(),
        ethtype,
    )
}

#[must_use]
/// An IPv4 packet from `1.2.3.4` to `5.6.7.8` with the given TTL.
///
/// The transport is a TCP SYN or UDP from port 123 to 456, an ICMP echo request
/// (id 18, seq 2), or none.
pub fn build_test_ipv4_packet_with_transport(
    ttl: u8,
    transport_type: Option<NextHeader>,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    assert_ne!(transport_type, Some(NextHeader::ICMP6), "ICMPv6 over IPv4");
    let ip = HeaderStack::new()
        .eth_macs(TEST_SRC_MAC, TEST_DST_MAC)
        .ipv4_addrs("1.2.3.4", "5.6.7.8")
        .with(|ip| {
            ip.set_ttl(ttl);
        });
    into_packet(match transport_type {
        // Echo identifiers serve as ports for NAT and are covered by the ICMP checksum.
        Some(NextHeader::ICMP) => ip
            .icmp4(|_| {})
            .echo_request(|echo| *echo = Icmp4EchoRequest { id: 18, seq: 2 })
            .build_packet(),
        other => with_default_transport(ip, other),
    })
}

#[must_use]
/// [`build_test_ipv4_packet_with_transport`] with no transport.
pub fn build_test_ipv4_packet(ttl: u8) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    build_test_ipv4_packet_with_transport(ttl, None)
}

#[must_use]
/// Build an Ipv4 address from a &str
pub fn addr_v4(a: &str) -> Ipv4Addr {
    Ipv4Addr::from_str(a).expect("Bad IPv4 address")
}

#[must_use]
#[track_caller]
/// A UDP/IPv4 frame with TTL 255 and no payload.
pub fn build_test_udp_ipv4_frame(
    src_mac: Mac,
    dst_mac: Mac,
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
) -> Packet<TestBuffer> {
    HeaderStack::new()
        .eth_macs(src_mac, dst_mac)
        .ipv4_addrs(src_ip, dst_ip)
        .with(|ip| {
            ip.set_ttl(255);
        })
        .udp_ports(sport, dport)
        .build_packet()
        .expect("a valid UDP/IPv4 frame")
}

#[must_use]
#[track_caller]
/// [`build_test_udp_ipv4_frame`] with both MACs `02:00:00:00:00:01`.
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
#[track_caller]
/// A TCP SYN (seq 1) with TTL 255 and no payload, both MACs `02:00:00:00:00:01`.
pub fn build_test_tcp_ipv4_packet(
    src_ip: &str,
    dst_ip: &str,
    sport: u16,
    dport: u16,
) -> Packet<TestBuffer> {
    let mac = Mac([0x2, 0, 0, 0, 0, 1]);
    HeaderStack::new()
        .eth_macs(mac, mac)
        .ipv4_addrs(src_ip, dst_ip)
        .with(|ip| {
            ip.set_ttl(255);
        })
        .tcp_ports(sport, dport)
        .with(|tcp| {
            tcp.set_syn(true);
            tcp.set_sequence_number(1);
        })
        .build_packet()
        .expect("a valid TCP/IPv4 frame")
}

#[must_use]
/// [`build_test_ipv6_packet_with_transport`] with no transport.
pub fn build_test_ipv6_packet(ttl: u8) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    build_test_ipv6_packet_with_transport(ttl, None)
}

#[must_use]
/// An IPv6 packet from `::1.2.3.4` to `::5.6.7.8` with the given hop limit.
///
/// The transport is a TCP SYN or UDP from port 123 to 456, an `ICMPv6` echo request
/// (id 18, seq 2), or none.
pub fn build_test_ipv6_packet_with_transport(
    hl: u8,
    transport_type: Option<NextHeader>,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    assert_ne!(transport_type, Some(NextHeader::ICMP), "ICMPv4 over IPv6");
    let ip = HeaderStack::new()
        .eth_macs(TEST_SRC_MAC, TEST_DST_MAC)
        .ipv6_addrs("::1.2.3.4", "::5.6.7.8")
        .with(|ip| {
            ip.set_hop_limit(hl);
        });
    into_packet(match transport_type {
        // Echo identifiers serve as ports for NAT and are covered by the ICMP checksum.
        Some(NextHeader::ICMP6) => ip
            .icmp6(|_| {})
            .echo_request6(|echo| *echo = Icmp6EchoRequest { id: 18, seq: 2 })
            .build_packet(),
        other => with_default_transport(ip, other),
    })
}

#[must_use]
/// An `ICMPv4` network-unreachable error quoting a header-only packet.
///
/// The quoted TCP / UDP uses `inner_param_1` and `inner_param_2` as ports; a quoted
/// echo request uses them as id and seq.
pub fn build_test_icmp4_destination_unreachable_packet(
    outer_src_ip: Ipv4Addr,
    outer_dst_ip: Ipv4Addr,
    inner_src_ip: Ipv4Addr,
    inner_dst_ip: Ipv4Addr,
    next_header: NextHeader,
    inner_param_1: u16,
    inner_param_2: u16,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    build_test_icmp4_destination_unreachable_packet_with_code(
        Icmp4DestUnreachable::Network,
        IcmpErrorAddrs {
            outer_src: outer_src_ip,
            outer_dst: outer_dst_ip,
            inner_src: inner_src_ip,
            inner_dst: inner_dst_ip,
        },
        next_header,
        inner_param_1,
        inner_param_2,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpErrorAddrs {
    pub outer_src: Ipv4Addr,
    pub outer_dst: Ipv4Addr,
    pub inner_src: Ipv4Addr,
    pub inner_dst: Ipv4Addr,
}

pub fn build_test_icmp4_destination_unreachable_packet_with_code(
    unreachable: Icmp4DestUnreachable,
    addrs: IcmpErrorAddrs,
    next_header: NextHeader,
    inner_param_1: u16,
    inner_param_2: u16,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let inner_src = UnicastIpv4Addr::new(addrs.inner_src).unwrap();
    let packet = HeaderStack::new()
        .eth_macs(TEST_SRC_MAC, TEST_DST_MAC)
        .ipv4_addrs(addrs.outer_src, addrs.outer_dst)
        .with(|ip| {
            ip.set_ttl(8);
        })
        .icmp4(|_| {})
        .dest_unreachable(|u| *u = unreachable)
        .embedded(|inner| {
            let inner = inner.ipv4(|ip| {
                ip.set_source(inner_src)
                    .set_destination(addrs.inner_dst)
                    .set_ttl(4);
            });
            match next_header {
                NextHeader::ICMP => {
                    inner.icmp4(Icmp4::with_type(Icmp4Type::EchoRequest(Icmp4EchoRequest {
                        id: inner_param_1,
                        seq: inner_param_2,
                    })))
                }
                other => embed_ports(inner, other, inner_param_1, inner_param_2),
            }
        })
        .build_packet();
    into_packet(packet)
}

/// Quote a TCP or UDP header with these ports.
fn embed_ports(
    inner: EmbeddedAssembler,
    next_header: NextHeader,
    sport: u16,
    dport: u16,
) -> EmbeddedAssembler {
    match next_header {
        NextHeader::TCP => inner.tcp(sport.try_into().unwrap(), dport.try_into().unwrap(), |_| {}),
        NextHeader::UDP => inner.udp(sport.try_into().unwrap(), dport.try_into().unwrap(), |_| {}),
        _ => panic!("Unsupported next header: {next_header:?}"),
    }
}

/// Direction for ICMP Echo packets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpEchoDirection {
    /// Echo Request
    Request,
    /// Echo Reply
    Reply,
}

#[must_use]
/// An `ICMPv4` echo request or reply with TTL 8 and seq 0.
pub fn build_test_icmp4_echo(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    identifier: u16,
    direction: IcmpEchoDirection,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let icmp = HeaderStack::new()
        .eth_macs(TEST_SRC_MAC, TEST_DST_MAC)
        .ipv4_addrs(src_ip, dst_ip)
        .with(|ip| {
            ip.set_ttl(8);
        })
        .icmp4(|_| {});
    into_packet(match direction {
        IcmpEchoDirection::Request => icmp
            .echo_request(|echo| echo.id = identifier)
            .build_packet(),
        IcmpEchoDirection::Reply => icmp.echo_reply(|echo| echo.id = identifier).build_packet(),
    })
}

#[must_use]
/// A VXLAN packet over IPv4 with the given outer DSCP/ECN, carrying a minimal IPv4 frame.
pub fn build_test_vxlan_ipv4_packet_with_outer_qos(
    dscp: Dscp,
    ecn: Ecn,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let inner = build_test_ipv4_packet(64).unwrap();
    let inner_buf = inner.serialize().unwrap();
    build_test_vxlan_ipv4_packet_carrying(dscp, ecn, inner_buf.as_ref())
}

#[must_use]
pub fn build_test_vxlan_ipv4_packet_carrying(
    dscp: Dscp,
    ecn: Ecn,
    inner_bytes: &[u8],
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    build_test_vxlan_ipv4_packet_carrying_vni(
        Vni::new_checked(100).unwrap_or_else(|_| unreachable!()),
        dscp,
        ecn,
        inner_bytes,
    )
}

#[must_use]
pub fn build_test_vxlan_ipv4_packet_carrying_vni(
    vni: Vni,
    dscp: Dscp,
    ecn: Ecn,
    inner_bytes: &[u8],
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let udp = HeaderStack::new()
        .eth_macs(TEST_SRC_MAC, TEST_DST_MAC)
        .ipv4_addrs("1.2.3.4", "5.6.7.8")
        .with(|ip| {
            ip.set_dscp(dscp);
            ip.set_ecn(ecn);
        })
        .udp_ports(123, Vxlan::PORT.as_u16());
    vxlan_carrying(udp, vni, inner_bytes)
}

/// Finish `udp` as a VXLAN tunnel on `vni` carrying `inner_bytes`.
fn vxlan_carrying(
    udp: HeaderStack<Udp>,
    vni: Vni,
    inner_bytes: &[u8],
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    into_packet(
        udp.vxlan(|vxlan| *vxlan = Vxlan::new(vni))
            .build_packet_with_payload(inner_bytes),
    )
}

#[must_use]
/// A VXLAN packet over IPv6 with the given outer DSCP/ECN, carrying a minimal IPv4 frame.
pub fn build_test_vxlan_ipv6_packet_with_outer_qos(
    dscp: Dscp,
    ecn: Ecn,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let inner = build_test_ipv4_packet(64).unwrap().serialize().unwrap();
    let udp = HeaderStack::new()
        .eth_macs(TEST_SRC_MAC, TEST_DST_MAC)
        .ipv6_addrs("::1.2.3.4", "::5.6.7.8")
        .with(|ip| {
            ip.set_dscp(dscp);
            ip.set_ecn(ecn);
        })
        .udp_ports(123, Vxlan::PORT.as_u16());
    vxlan_carrying(udp, Vni::new_checked(100).unwrap(), inner.as_ref())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmp6ErrorAddrs {
    pub outer_src: Ipv6Addr,
    pub outer_dst: Ipv6Addr,
    pub inner_src: Ipv6Addr,
    pub inner_dst: Ipv6Addr,
}

#[must_use]
pub fn build_test_icmp6_error_packet(
    icmp_type: Icmp6Type,
    addrs: Icmp6ErrorAddrs,
    next_header: NextHeader,
    inner_param_1: u16,
    inner_param_2: u16,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let inner_src = UnicastIpv6Addr::new(addrs.inner_src).unwrap();
    let embed = |inner: EmbeddedAssembler| {
        let inner = inner.ipv6(|ip| {
            ip.set_source(inner_src)
                .set_destination(addrs.inner_dst)
                .set_hop_limit(4);
        });
        match next_header {
            NextHeader::ICMP6 => {
                inner.icmp6(Icmp6::with_type(Icmp6Type::EchoRequest(Icmp6EchoRequest {
                    id: inner_param_1,
                    seq: inner_param_2,
                })))
            }
            other => embed_ports(inner, other, inner_param_1, inner_param_2),
        }
    };
    let icmp = HeaderStack::new()
        .eth_macs(TEST_SRC_MAC, TEST_DST_MAC)
        .ipv6_addrs(addrs.outer_src, addrs.outer_dst)
        .with(|ip| {
            ip.set_hop_limit(8);
        })
        .icmp6(|_| {});
    into_packet(match icmp_type {
        Icmp6Type::DestUnreachable(t) => icmp
            .dest_unreachable6(|u| *u = t)
            .embedded(embed)
            .build_packet(),
        Icmp6Type::PacketTooBig(t) => icmp
            .packet_too_big6(|u| *u = t)
            .embedded(embed)
            .build_packet(),
        Icmp6Type::TimeExceeded(t) => icmp
            .time_exceeded6(|u| *u = t)
            .embedded(embed)
            .build_packet(),
        Icmp6Type::ParamProblem(t) => icmp
            .param_problem6(|u| *u = t)
            .embedded(embed)
            .build_packet(),
        other => panic!("not an ICMPv6 error message: {other:?}"),
    })
}

#[must_use]
pub fn build_test_icmp6_echo(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    identifier: u16,
    direction: IcmpEchoDirection,
) -> Result<Packet<TestBuffer>, InvalidPacket<TestBuffer>> {
    let icmp = HeaderStack::new()
        .eth_macs(TEST_SRC_MAC, TEST_DST_MAC)
        .ipv6_addrs(src_ip, dst_ip)
        .with(|ip| {
            ip.set_hop_limit(8);
        })
        .icmp6(|_| {});
    into_packet(match direction {
        IcmpEchoDirection::Request => icmp
            .echo_request6(|echo| echo.id = identifier)
            .build_packet(),
        IcmpEchoDirection::Reply => icmp.echo_reply6(|echo| echo.id = identifier).build_packet(),
    })
}

/// Build an `ICMPv4` error containing the raw `quote` bytes.
///
/// The quote starts at the offending packet's IP header and may be truncated or malformed.
/// Re-parse it to exercise embedded-header parsing, then compute the ICMP checksum. Return
/// `None` if the assembled packet cannot be parsed.
#[must_use]
pub fn build_icmp4_error_quoting(
    unreachable: Icmp4DestUnreachable,
    outer_src: Ipv4Addr,
    outer_dst: Ipv4Addr,
    quote: &[u8],
) -> Option<Packet<TestBuffer>> {
    let icmp = Icmp4(Icmpv4Header::new(Icmpv4Type::DestinationUnreachable(
        DestUnreachableHeader::from(unreachable),
    )));

    let mut outer = Ipv4::default();
    outer.set_source(UnicastIpv4Addr::new(outer_src).ok()?);
    outer.set_destination(outer_dst);
    outer.set_ttl(8);
    outer.set_next_header(NextHeader::ICMP);
    outer
        .set_payload_len(
            icmp.size()
                .get()
                .checked_add(u16::try_from(quote.len()).ok()?)?,
        )
        .ok()?;
    outer.update_checksum(&()).ok()?;

    let mut headers = HeadersBuilder::default();
    headers.eth(Some(make_default_for_eth(EthType::IPV4)));
    headers.net(Some(Net::Ipv4(outer)));
    headers.transport(Some(Transport::Icmp4(icmp)));
    assemble_quoted(&headers, quote)
}

/// Build an `ICMPv6` error containing the raw `quote` bytes. See [`build_icmp4_error_quoting`]
/// for parsing and checksum behavior.
#[must_use]
pub fn build_icmp6_error_quoting(
    icmp_type: Icmp6Type,
    outer_src: Ipv6Addr,
    outer_dst: Ipv6Addr,
    quote: &[u8],
) -> Option<Packet<TestBuffer>> {
    let icmp = Icmp6(Icmpv6Header::new(icmp_type.into()));

    let mut outer = Ipv6::default();
    outer.set_source(UnicastIpv6Addr::new(outer_src).ok()?);
    outer.set_destination(outer_dst);
    outer.set_hop_limit(8);
    outer.set_next_header(NextHeader::ICMP6);
    outer.set_payload_length(
        icmp.size()
            .get()
            .checked_add(u16::try_from(quote.len()).ok()?)?,
    );

    let mut headers = HeadersBuilder::default();
    headers.eth(Some(make_default_for_eth(EthType::IPV6)));
    headers.net(Some(Net::Ipv6(outer)));
    headers.transport(Some(Transport::Icmp6(icmp)));
    assemble_quoted(&headers, quote)
}

/// Serialize `headers`, append `quote`, and parse the result to construct embedded headers.
fn assemble_quoted(headers: &HeadersBuilder, quote: &[u8]) -> Option<Packet<TestBuffer>> {
    let headers = headers.build().ok()?;
    let front = headers.size().get() as usize;
    let mut data = vec![0u8; front + quote.len()];
    headers.deparse(&mut data[..front]).ok()?;
    data[front..].copy_from_slice(quote);

    let mut packet = Packet::new(TestBuffer::from_raw_data(&data)).ok()?;
    // Compute the checksum after appending and parsing the quote.
    packet.update_checksums();
    Some(packet)
}

/// Assert that the transport checksum is current or a refresh was requested.
///
/// IPv4 header checksums are recomputed at egress and are not checked here.
///
/// # Panics
///
/// Panics if no refresh was requested and recomputation changes the transport checksum.
pub fn assert_checksum_current_or_refresh_requested(packet: &Packet<TestBuffer>) {
    fn transport_checksum(packet: &Packet<TestBuffer>) -> Option<u16> {
        match packet.headers.transport.as_ref()? {
            Transport::Tcp(tcp) => tcp.checksum().map(u16::from),
            Transport::Udp(udp) => udp.checksum().map(u16::from),
            Transport::Icmp4(icmp) => icmp.checksum().map(u16::from),
            Transport::Icmp6(icmp) => icmp.checksum().map(u16::from),
        }
    }
    if packet.meta().checksum_refresh() {
        return;
    }
    let mut recomputed = packet.deep_copy().expect("copy test packet");
    recomputed.update_checksums();
    assert_eq!(
        transport_checksum(packet),
        transport_checksum(&recomputed),
        "the packet asked for no checksum recompute, but its transport checksum is stale:\n{packet}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::{TryHeaders, TryIpv4, TryIpv6, TryTcp, TryUdp};
    use crate::icmp4::Icmp4Type;
    use crate::icmp6::Icmp6Type as Icmp6Kind;

    /// Recomputing checksums on a copy must not change the headers.
    fn assert_checksums_current(packet: &Packet<TestBuffer>) {
        let mut recomputed = packet.deep_copy().unwrap();
        recomputed.update_checksums();
        assert_eq!(packet.headers(), recomputed.headers(), "stale checksum");
    }

    fn assert_default_eth(packet: &Packet<TestBuffer>) {
        let eth = packet.headers().eth().unwrap();
        assert_eq!(eth.source().inner(), TEST_SRC_MAC);
        assert_eq!(eth.destination().inner(), TEST_DST_MAC);
    }

    #[test]
    fn ipv4_defaults_for_every_transport() {
        for transport in [
            None,
            Some(NextHeader::TCP),
            Some(NextHeader::UDP),
            Some(NextHeader::ICMP),
        ] {
            let packet = build_test_ipv4_packet_with_transport(17, transport).unwrap();
            assert_default_eth(&packet);
            let ip = packet.try_ipv4().unwrap();
            assert_eq!(ip.source().inner(), Ipv4Addr::new(1, 2, 3, 4));
            assert_eq!(ip.destination(), Ipv4Addr::new(5, 6, 7, 8));
            assert_eq!(ip.ttl(), 17);
            assert_checksums_current(&packet);
        }
    }

    #[test]
    fn ipv6_defaults_for_every_transport() {
        for transport in [
            None,
            Some(NextHeader::TCP),
            Some(NextHeader::UDP),
            Some(NextHeader::ICMP6),
        ] {
            let packet = build_test_ipv6_packet_with_transport(17, transport).unwrap();
            assert_default_eth(&packet);
            let ip = packet.try_ipv6().unwrap();
            assert_eq!(
                ip.source().inner(),
                "::1.2.3.4".parse::<Ipv6Addr>().unwrap()
            );
            assert_eq!(ip.destination(), "::5.6.7.8".parse::<Ipv6Addr>().unwrap());
            assert_eq!(ip.hop_limit(), 17);
            assert_checksums_current(&packet);
        }
    }

    #[test]
    fn default_transports_keep_their_fields() {
        let packet = build_test_ipv4_packet_with_transport(64, Some(NextHeader::TCP)).unwrap();
        let tcp = packet.try_tcp().unwrap();
        assert_eq!(
            (tcp.source().as_u16(), tcp.destination().as_u16()),
            (123, 456)
        );
        assert!(tcp.syn());
        assert_eq!(tcp.sequence_number(), 1);

        let packet = build_test_ipv6_packet_with_transport(64, Some(NextHeader::UDP)).unwrap();
        let udp = packet.try_udp().unwrap();
        assert_eq!(
            (udp.source().as_u16(), udp.destination().as_u16()),
            (123, 456)
        );

        let packet = build_test_ipv4_packet_with_transport(64, Some(NextHeader::ICMP)).unwrap();
        let Some(Transport::Icmp4(icmp)) = packet.headers().transport() else {
            panic!("expected Icmp4");
        };
        assert!(matches!(
            icmp.icmp_type(),
            Icmp4Type::EchoRequest(Icmp4EchoRequest { id: 18, seq: 2 })
        ));

        let packet = build_test_ipv6_packet_with_transport(64, Some(NextHeader::ICMP6)).unwrap();
        let Some(Transport::Icmp6(icmp)) = packet.headers().transport() else {
            panic!("expected Icmp6");
        };
        assert!(matches!(
            icmp.icmp_type(),
            Icmp6Kind::EchoRequest(Icmp6EchoRequest { id: 18, seq: 2 })
        ));
    }

    /// The quoted transport checksum must be valid.
    fn assert_inner_checksum_valid(packet: &Packet<TestBuffer>) {
        use crate::headers::{EmbeddedTransport, TryEmbeddedTransport, TryInnerIp};
        use crate::icmp4::TruncatedIcmp4;
        use crate::icmp6::{Icmp6ChecksumPayload, TruncatedIcmp6};
        use crate::tcp::{TcpChecksumPayload, TruncatedTcp};
        use crate::udp::{TruncatedUdp, UdpChecksumPayload};

        let net = packet.try_inner_ip().expect("an embedded IP header");
        let valid = match packet
            .try_embedded_transport()
            .expect("an embedded transport")
        {
            EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(tcp)) => tcp
                .validate_checksum(&TcpChecksumPayload::new(net, &[]))
                .is_ok(),
            EmbeddedTransport::Udp(TruncatedUdp::FullHeader(udp)) => udp
                .validate_checksum(&UdpChecksumPayload::new(net, &[]))
                .is_ok(),
            EmbeddedTransport::Icmp4(TruncatedIcmp4::FullHeader(icmp)) => {
                icmp.validate_checksum(&[]).is_ok()
            }
            EmbeddedTransport::Icmp6(TruncatedIcmp6::FullHeader(icmp)) => {
                let Net::Ipv6(ip) = net else {
                    panic!("ICMPv6 quoted inside IPv4");
                };
                icmp.validate_checksum(&Icmp6ChecksumPayload::new(
                    ip.source().inner(),
                    ip.destination(),
                    &[],
                ))
                .is_ok()
            }
            other => panic!("expected a full quoted header, got {other:?}"),
        };
        assert!(valid, "the quoted transport checksum is not valid");
    }

    const V4_ERROR: IcmpErrorAddrs = IcmpErrorAddrs {
        outer_src: Ipv4Addr::new(10, 0, 0, 254),
        outer_dst: Ipv4Addr::new(10, 0, 0, 1),
        inner_src: Ipv4Addr::new(10, 0, 0, 1),
        inner_dst: Ipv4Addr::new(192, 168, 0, 1),
    };

    #[test]
    fn icmp4_errors_quote_a_valid_original() {
        for next_header in [NextHeader::TCP, NextHeader::UDP, NextHeader::ICMP] {
            let packet = build_test_icmp4_destination_unreachable_packet_with_code(
                Icmp4DestUnreachable::Host,
                V4_ERROR,
                next_header,
                1234,
                80,
            )
            .unwrap();
            assert_default_eth(&packet);
            let outer = packet.try_ipv4().unwrap();
            assert_eq!(outer.source().inner(), V4_ERROR.outer_src);
            assert_eq!(outer.ttl(), 8);
            let Some(Transport::Icmp4(icmp)) = packet.headers().transport() else {
                panic!("expected Icmp4");
            };
            assert_eq!(
                icmp.icmp_type(),
                Icmp4Type::DestUnreachable(Icmp4DestUnreachable::Host)
            );
            assert_checksums_current(&packet);
            assert_inner_checksum_valid(&packet);
        }
    }

    #[test]
    fn icmp6_errors_quote_a_valid_original() {
        use crate::icmp6::{
            Icmp6DestUnreachable, Icmp6PacketTooBig, Icmp6ParamProblem, Icmp6ParamProblemCode,
            Icmp6TimeExceeded,
        };

        let addrs = Icmp6ErrorAddrs {
            outer_src: "2001:db8::fe".parse().unwrap(),
            outer_dst: "2001:db8::1".parse().unwrap(),
            inner_src: "2001:db8::1".parse().unwrap(),
            inner_dst: "2001:db8:1::1".parse().unwrap(),
        };
        let errors = [
            Icmp6Kind::DestUnreachable(Icmp6DestUnreachable::NoRoute),
            Icmp6Kind::PacketTooBig(Icmp6PacketTooBig::new(1280).unwrap()),
            Icmp6Kind::TimeExceeded(Icmp6TimeExceeded::HopLimitExceeded),
            Icmp6Kind::ParamProblem(Icmp6ParamProblem {
                code: Icmp6ParamProblemCode::ErroneousHeaderField,
                pointer: 6,
            }),
        ];
        for error in errors {
            for next_header in [NextHeader::TCP, NextHeader::UDP, NextHeader::ICMP6] {
                let packet =
                    build_test_icmp6_error_packet(error.clone(), addrs, next_header, 1234, 80)
                        .unwrap();
                let Some(Transport::Icmp6(icmp)) = packet.headers().transport() else {
                    panic!("expected Icmp6");
                };
                assert_eq!(icmp.icmp_type(), error);
                assert_eq!(packet.try_ipv6().unwrap().hop_limit(), 8);
                assert_checksums_current(&packet);
                assert_inner_checksum_valid(&packet);
            }
        }
    }

    #[test]
    #[should_panic(expected = "not an ICMPv6 error message")]
    fn icmp6_error_rejects_a_query() {
        let addrs = Icmp6ErrorAddrs {
            outer_src: "2001:db8::fe".parse().unwrap(),
            outer_dst: "2001:db8::1".parse().unwrap(),
            inner_src: "2001:db8::1".parse().unwrap(),
            inner_dst: "2001:db8:1::1".parse().unwrap(),
        };
        let _ = build_test_icmp6_error_packet(
            Icmp6Kind::EchoRequest(Icmp6EchoRequest { id: 1, seq: 1 }),
            addrs,
            NextHeader::UDP,
            1,
            2,
        );
    }

    #[test]
    fn echo_helpers_set_direction_and_identifier() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        for (direction, expect_request) in [
            (IcmpEchoDirection::Request, true),
            (IcmpEchoDirection::Reply, false),
        ] {
            let packet = build_test_icmp4_echo(src, dst, 7, direction).unwrap();
            let Some(Transport::Icmp4(icmp)) = packet.headers().transport() else {
                panic!("expected Icmp4");
            };
            match icmp.icmp_type() {
                Icmp4Type::EchoRequest(echo) => {
                    assert!(expect_request);
                    assert_eq!((echo.id, echo.seq), (7, 0));
                }
                Icmp4Type::EchoReply(echo) => {
                    assert!(!expect_request);
                    assert_eq!((echo.id, echo.seq), (7, 0));
                }
                other => panic!("expected an echo, got {other:?}"),
            }
            assert_eq!(packet.try_ipv4().unwrap().ttl(), 8);
            assert_checksums_current(&packet);

            let packet = build_test_icmp6_echo(
                "2001:db8::1".parse().unwrap(),
                "2001:db8::2".parse().unwrap(),
                7,
                direction,
            )
            .unwrap();
            let Some(Transport::Icmp6(icmp)) = packet.headers().transport() else {
                panic!("expected Icmp6");
            };
            match icmp.icmp_type() {
                Icmp6Kind::EchoRequest(echo) => {
                    assert!(expect_request);
                    assert_eq!((echo.id, echo.seq), (7, 0));
                }
                Icmp6Kind::EchoReply(echo) => {
                    assert!(!expect_request);
                    assert_eq!((echo.id, echo.seq), (7, 0));
                }
                other => panic!("expected an echo, got {other:?}"),
            }
            assert_checksums_current(&packet);
        }
    }

    #[test]
    fn vxlan_helpers_carry_the_inner_frame() {
        use crate::headers::{TryUdp, TryVxlan};
        use crate::udp::UdpChecksum;

        let dscp = Dscp::new(46).unwrap();
        let ecn = Ecn::new(1).unwrap();
        let inner = build_test_ipv4_packet(64).unwrap().serialize().unwrap();
        let vni = Vni::new_checked(4242).unwrap();

        let v4 = build_test_vxlan_ipv4_packet_carrying_vni(vni, dscp, ecn, inner.as_ref()).unwrap();
        let ip = v4.try_ipv4().unwrap();
        assert_eq!((ip.dscp(), ip.ecn()), (dscp.into(), ecn.into()));
        assert_eq!(v4.try_vxlan().unwrap().vni(), vni);

        let v6 = build_test_vxlan_ipv6_packet_with_outer_qos(dscp, ecn).unwrap();
        let ip = v6.try_ipv6().unwrap();
        assert_eq!((ip.dscp(), ip.ecn()), (dscp.into(), ecn.into()));
        assert_eq!(v6.try_vxlan().unwrap().vni().as_u32(), 100);

        for packet in [&v4, &v6] {
            assert_default_eth(packet);
            assert_eq!(packet.payload().as_ref(), inner.as_ref());
            let udp = packet.try_udp().unwrap();
            assert_eq!(udp.destination(), Vxlan::PORT);
            assert_eq!(udp.checksum(), Some(UdpChecksum::ZERO));
            // UDP length covers the VXLAN header and the inner frame.
            assert_eq!(
                usize::from(udp.length().get()),
                usize::from(Udp::MIN_LENGTH.get() + Vxlan::MIN_LENGTH.get()) + inner.as_ref().len()
            );
            assert_checksums_current(packet);
        }
    }

    #[test]
    #[should_panic(expected = "ICMPv6 over IPv4")]
    fn icmp6_over_ipv4_is_rejected() {
        let _ = build_test_ipv4_packet_with_transport(64, Some(NextHeader::ICMP6));
    }

    #[test]
    #[should_panic(expected = "unsupported transport type")]
    fn unsupported_transport_is_rejected() {
        let _ = build_test_ipv4_packet_with_transport(64, Some(NextHeader::HOP_BY_HOP));
    }
}
