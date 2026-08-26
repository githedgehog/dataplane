// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT processing for `ICMPv4` and `ICMPv6` Error messages with embedded IP packets, common to
//! static and masquerade modes.

use crate::NatPort;
use crate::NatTranslationData;
use net::buffer::PacketBufferMut;
use net::checksum::Checksum;
use net::headers::{
    EmbeddedIpVersion, EmbeddedTransport, TryEmbeddedHeadersMut, TryEmbeddedTransportMut,
    TryInnerIpMut,
};
use net::icmp_any::TruncatedIcmpAny;
use net::packet::{DoneReason, Packet};
use std::net::IpAddr;
use std::num::NonZero;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IcmpErrorMsgError {
    #[error("failure to get embedded headers")]
    NoEmbeddedHeaders,
    #[error("failure to get inner IP header")]
    NoInnerIpHeader,
    #[error("invalid transport-layer port {0}")]
    InvalidPort(u16),
    #[error("invalid IP version")]
    InvalidIpVersion,
    #[error("IP address {0} is not unicast")]
    NotUnicast(IpAddr),
}

impl From<&IcmpErrorMsgError> for DoneReason {
    fn from(error: &IcmpErrorMsgError) -> Self {
        match error {
            IcmpErrorMsgError::InvalidIpVersion => DoneReason::InternalFailure,
            IcmpErrorMsgError::InvalidPort(_) => DoneReason::Malformed,
            IcmpErrorMsgError::NotUnicast(_) => DoneReason::NatFailure,
            IcmpErrorMsgError::NoEmbeddedHeaders | IcmpErrorMsgError::NoInnerIpHeader => {
                DoneReason::IcmpErrorIncomplete
            }
        }
    }
}

pub(crate) fn nat_translate_icmp_inner<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    state: &NatTranslationData,
) -> Result<(), IcmpErrorMsgError> {
    // From REQ-4 from RFC 5508, "NAT Behavioral Requirements for ICMP":
    //
    //    If the NAT has active mapping for the embedded payload, then the NAT MUST do the
    //    following prior to forwarding the packet, unless explicitly overridden by local
    //    policy:
    //
    //        a) Revert the IP and transport headers of the embedded IP packet to their original
    //        form, using the matching mapping;
    if let Some(src) = state.src {
        nat_translate_icmp_inner_src(packet, src.addr, src.port)?;
    }
    if let Some(dst) = state.dst {
        nat_translate_icmp_inner_dst(packet, dst.addr, dst.port)?;
    }
    Ok(())
}

pub(crate) fn nat_translate_icmp_inner_src<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    target_addr: IpAddr,
    target_port: Option<NatPort>,
) -> Result<(), IcmpErrorMsgError> {
    let embedded_headers = packet
        .embedded_headers_mut()
        .ok_or(IcmpErrorMsgError::NoEmbeddedHeaders)?;

    let inner_ip = embedded_headers
        .try_inner_ip_mut()
        .ok_or(IcmpErrorMsgError::NoInnerIpHeader)?;
    let old_addr = inner_ip.src_addr();
    inner_ip
        .try_set_source(
            target_addr
                .try_into()
                .map_err(|_| IcmpErrorMsgError::NotUnicast(target_addr))?,
        )
        .map_err(|_| IcmpErrorMsgError::InvalidIpVersion)?;

    fold_inner_address(embedded_headers, old_addr, target_addr);

    let Some(target_port) = target_port else {
        // No port to translate, we're done
        return Ok(());
    };
    let Some(transport) = embedded_headers.try_embedded_transport_mut() else {
        // No transport layer in the inner packet, that's fine, we're done here
        return Ok(());
    };

    match transport {
        EmbeddedTransport::Tcp(_) | EmbeddedTransport::Udp(_) => {
            translate_inner_tcp_udp_src(transport, quoted_version(old_addr), target_port)?;
        }
        EmbeddedTransport::Icmp4(icmp4) => {
            translate_inner_icmp(icmp4, target_port);
        }
        EmbeddedTransport::Icmp6(icmp6) => {
            translate_inner_icmp(icmp6, target_port);
        }
    }
    Ok(())
}

/// The IP version of the packet quoted inside the ICMP error.
///
/// Read off one of the quoted packet's own addresses, which is the only version the quote has:
/// address translation cannot cross families here, since setting an address of the other family
/// fails before this is reached.
fn quoted_version(addr: IpAddr) -> EmbeddedIpVersion {
    if addr.is_ipv4() {
        EmbeddedIpVersion::Ipv4
    } else {
        EmbeddedIpVersion::Ipv6
    }
}

/// Fold a rewrite of one of the quoted packet's addresses into the quoted transport checksum.
///
/// TCP, UDP and `ICMPv6` are checksummed over a pseudo-header built from the quoted packet's
/// addresses, so rewriting one leaves the quoted transport checksum describing an address that is
/// no longer there. That is true whether or not the same mapping also moves a port, which is why
/// this is its own step rather than part of port translation: a mapping that only moves an address
/// still owes the quote a checksum that agrees with it.
///
/// Deltas on a one's-complement sum commute, so folding the address before any port is a choice of
/// order and not of result.
fn fold_inner_address<H>(embedded_headers: &mut H, old_addr: IpAddr, new_addr: IpAddr)
where
    H: TryEmbeddedTransportMut + ?Sized,
{
    if old_addr == new_addr {
        return;
    }
    let Some(transport) = embedded_headers.try_embedded_transport_mut() else {
        // No transport layer in the quote, so no pseudo-header to keep in step.
        return;
    };
    transport.update_checksum_for_address(old_addr, new_addr);
}

pub(crate) fn nat_translate_icmp_inner_dst<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    target_addr: IpAddr,
    target_port: Option<NatPort>,
) -> Result<(), IcmpErrorMsgError> {
    let embedded_headers = packet
        .embedded_headers_mut()
        .ok_or(IcmpErrorMsgError::NoEmbeddedHeaders)?;

    let inner_ip = embedded_headers
        .try_inner_ip_mut()
        .ok_or(IcmpErrorMsgError::NoInnerIpHeader)?;
    let old_addr = inner_ip.dst_addr();
    inner_ip
        .try_set_destination(target_addr)
        .map_err(|_| IcmpErrorMsgError::InvalidIpVersion)?;

    fold_inner_address(embedded_headers, old_addr, target_addr);

    let Some(target_port) = target_port else {
        // No port to translate, we're done
        return Ok(());
    };
    let Some(transport) = embedded_headers.try_embedded_transport_mut() else {
        // No transport layer in the inner packet, that's fine, we're done here
        return Ok(());
    };

    match transport {
        EmbeddedTransport::Tcp(_) | EmbeddedTransport::Udp(_) => {
            translate_inner_tcp_udp_dst(transport, quoted_version(old_addr), target_port)
        }
        _ => Ok(()), // ICMP is dealt with when dealing with the source port
    }
}

fn translate_inner_icmp<T>(icmp: &mut T, target_identifier: NatPort)
where
    T: TruncatedIcmpAny + Checksum,
    u16: std::convert::From<<T as Checksum>::Checksum>,
{
    let Some(old_identifier) = icmp.identifier() else {
        // No identifier to translate, we're done
        return;
    };
    let new_identifier = target_identifier.as_u16();
    if new_identifier == old_identifier {
        // No change needed
        return;
    }

    icmp.try_set_identifier(new_identifier)
        .unwrap_or_else(|_| unreachable!()); // We found an old identifier, we can set a new one
    let Some(current_checksum) = icmp.checksum().map(u16::from) else {
        // No checksum to update, we're done
        return;
    };
    // As in `EmbeddedTransport::update_checksum`: `increment_update_checksum` hands the new
    // checksum back rather than storing it, so dropping the value leaves the quote's identifier
    // moved and its checksum describing the old one.
    let updated = icmp.increment_update_checksum(
        T::Checksum::from(current_checksum),
        old_identifier,
        new_identifier,
    );
    let _ = icmp.set_checksum(updated);
}

fn translate_inner_tcp_udp_src(
    transport: &mut EmbeddedTransport,
    quoted: EmbeddedIpVersion,
    target_port: NatPort,
) -> Result<(), IcmpErrorMsgError> {
    // Assume we have TCP or UDP, with source port always present
    let old_port = transport.source().unwrap_or_else(|| unreachable!()).into();
    let new_port: NonZero<u16> = target_port
        .try_into()
        .map_err(|_| IcmpErrorMsgError::InvalidPort(target_port.as_u16()))?;
    if old_port == new_port.get() {
        return Ok(());
    }
    transport
        .set_source(new_port)
        .unwrap_or_else(|_| unreachable!());
    // We don't know whether the header and payload are full: the easiest way to deal with
    // transport checksum update is to do an unconditional, incremental update here. Note
    // that this checksum will not be updated again when deparsing the packet.
    if let Some(current_checksum) = transport.checksum() {
        transport.update_checksum(quoted, current_checksum, old_port, new_port.get());
    }
    Ok(())
}

fn translate_inner_tcp_udp_dst(
    transport: &mut EmbeddedTransport,
    quoted: EmbeddedIpVersion,
    target_port: NatPort,
) -> Result<(), IcmpErrorMsgError> {
    // Assume we have TCP or UDP, with destination port always present
    let old_port = transport
        .destination()
        .unwrap_or_else(|| unreachable!())
        .into();
    let new_port: NonZero<u16> = target_port
        .try_into()
        .map_err(|_| IcmpErrorMsgError::InvalidPort(target_port.as_u16()))?;
    if old_port == new_port.get() {
        return Ok(());
    }
    transport
        .set_destination(new_port)
        .unwrap_or_else(|_| unreachable!());
    if let Some(current_checksum) = transport.checksum() {
        transport.update_checksum(quoted, current_checksum, old_port, new_port.get());
    }
    Ok(())
}

#[cfg(test)]
mod bolero_tests {
    use super::*;
    use crate::NatEndpoint;
    use crate::NatPort;
    use net::buffer::TestBuffer;
    use net::checksum::ChecksumError;
    use net::headers::TryHeaders;
    use net::headers::{
        Net, TryEmbeddedTransport, TryIcmpAnyMut, TryInnerIp, TryInnerIpv4Mut, TryIp, TryIpv4,
    };
    use net::icmp_any::IcmpAnyChecksum;
    use net::ipv4::{Ipv4Checksum, UnicastIpv4Addr};
    use net::ipv6::UnicastIpv6Addr;
    use net::packet::IcmpErrorMsg;
    use net::packet::icmp_err::{IcmpErrorPacket, IcmpErrorPacketError};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[derive(Debug, Clone, Copy)]
    enum TransportFields {
        Ports(u16, u16),
        Identifier(u16),
    }

    fn erase_checksums(packet: &mut Packet<TestBuffer>) {
        let _ = packet
            .try_icmp_any_mut()
            .unwrap()
            .set_checksum(IcmpAnyChecksum::new(0xffff));
        let _ = packet
            .try_inner_ipv4_mut()
            .ok_or(())
            .and_then(|ip| ip.set_checksum(Ipv4Checksum::new(0xffff)));
    }

    /// An all-wrong packet is refused and a repaired one is accepted.
    ///
    /// The RFC 5508 REQ-3 citations are on `net`'s
    /// `only_the_icmp_and_embedded_ip_checksums_decide_an_icmp_error` rather than here, for two
    /// reasons. `just spec-interlock` cannot check a citation whose implementation and test are in
    /// different crates, and it says so rather than passing. And this test breaks every checksum at
    /// once, which cannot distinguish a validator that checks too much from one that checks too
    /// little -- which is the whole of REQ-3(c).
    #[test]
    fn test_checksum_validation() {
        let generator = IcmpErrorMsg {};
        bolero::check!()
            .with_generator(generator)
            .for_each(|icmp_error_msg| {
                if IcmpErrorPacket::new(icmp_error_msg).is_none() {
                    // No embedded transport, that's fine, we just skip this input
                    return;
                }

                let mut icmp_error_msg_clone = icmp_error_msg.clone();
                // First check that checksum is incorrect. There's a super-high chance that it fails
                // with non-initialised checksums in all relevant haders, but 1) there may be only
                // one checksum to validate (for IPv6 packets, inner IP headers have no checksums)
                // and 2) sometimes Bolero reuses headers in which we set the correct checksums.
                // So we first "erase" all checksums by setting them to 0xffff.
                erase_checksums(&mut icmp_error_msg_clone);

                // Validate checksum is incorrect
                let res = IcmpErrorPacket::new(&icmp_error_msg_clone)
                    .unwrap()
                    .validate_checksums();
                assert!(matches!(
                    res,
                    Err(IcmpErrorPacketError::BadChecksumIcmp(
                        ChecksumError::Mismatch { .. }
                    ))
                ));

                // Update checksums for outer IP header, ICMP header, inner IP header; not the inner transport header
                icmp_error_msg_clone.update_checksums();

                // Now, ICMP and inner IP headers checksums should be valid
                let res = IcmpErrorPacket::new(&icmp_error_msg_clone)
                    .unwrap()
                    .validate_checksums();
                assert!(res.is_ok(), "Checksum validation failed: {res:?}");

                // Also check outer IP header checksum, since we're at it
                if let Some(ipv4) = icmp_error_msg_clone.headers().try_ipv4() {
                    let res = ipv4.validate_checksum(&());
                    assert!(res.is_ok(), "Checksum validation failed: {res:?}");
                }
            });
    }

    fn get_outer_addresses(packet: &Packet<TestBuffer>) -> Option<(IpAddr, IpAddr)> {
        packet.try_ip().map(|ip| (ip.src_addr(), ip.dst_addr()))
    }

    fn get_inner_addresses(packet: &Packet<TestBuffer>) -> Option<(IpAddr, IpAddr)> {
        packet
            .try_inner_ip()
            .map(|ip| (ip.src_addr(), ip.dst_addr()))
    }

    fn get_inner_ports(packet: &Packet<TestBuffer>) -> Option<TransportFields> {
        match packet.try_embedded_transport() {
            Some(EmbeddedTransport::Tcp(tcp)) => Some(TransportFields::Ports(
                tcp.source().into(),
                tcp.destination().into(),
            )),
            Some(EmbeddedTransport::Udp(udp)) => Some(TransportFields::Ports(
                udp.source().into(),
                udp.destination().into(),
            )),
            Some(EmbeddedTransport::Icmp4(icmp)) => {
                let identifier = icmp.identifier()?;
                Some(TransportFields::Identifier(identifier))
            }
            Some(EmbeddedTransport::Icmp6(icmp)) => {
                let identifier = icmp.identifier()?;
                Some(TransportFields::Identifier(identifier))
            }
            None => None,
        }
    }

    #[test]
    fn test_translation() {
        bolero::check!()
            .with_generator((
                IcmpErrorMsg {},
                bolero::generator::produce::<UnicastIpv4Addr>(),
                bolero::generator::produce::<Ipv4Addr>(),
                bolero::generator::produce::<UnicastIpv6Addr>(),
                bolero::generator::produce::<Ipv6Addr>(),
                bolero::generator::produce::<Option<NatPort>>(),
                bolero::generator::produce::<Option<NatPort>>(),
            ))
            .for_each(
                |(icmp_error_msg, src_v4, dst_v4, src_v6, dst_v6, src_port, dst_port)| {
                    let initial_outer_addresses = get_outer_addresses(icmp_error_msg).unwrap();
                    let initial_ports = get_inner_ports(icmp_error_msg);
                    let tr_data = match icmp_error_msg.headers().try_ip() {
                        Some(Net::Ipv4(_)) => NatTranslationData::default()
                            .with_src(NatEndpoint::new(
                                IpAddr::V4(Ipv4Addr::from(*src_v4)),
                                *src_port,
                            ))
                            .with_dst(NatEndpoint::new(IpAddr::V4(*dst_v4), *dst_port)),
                        Some(Net::Ipv6(_)) => NatTranslationData::default()
                            .with_src(NatEndpoint::new(
                                IpAddr::V6(Ipv6Addr::from(*src_v6)),
                                *src_port,
                            ))
                            .with_dst(NatEndpoint::new(IpAddr::V6(*dst_v6), *dst_port)),
                        None => unreachable!(),
                    };

                    // Translate inner IP addresses, and possibly inner ports
                    let mut icmp_error_msg_clone = icmp_error_msg.clone();
                    let inner_translation_result =
                        nat_translate_icmp_inner(&mut icmp_error_msg_clone, &tr_data);
                    if (*src_port == Some(NatPort::Identifier(0))
                        || *dst_port == Some(NatPort::Identifier(0)))
                        && matches!(
                            icmp_error_msg_clone.try_embedded_transport_mut(),
                            Some(EmbeddedTransport::Tcp(_) | EmbeddedTransport::Udp(_))
                        )
                    {
                        assert_eq!(
                            inner_translation_result,
                            Err(IcmpErrorMsgError::InvalidPort(0))
                        );
                        return;
                    }

                    // Translation can legitimately fail on fuzzed inputs
                    // (e.g., embedded headers too short to parse, IP
                    // version mismatch, non-unicast source).  Only
                    // verify post-conditions when translation succeeded.
                    if inner_translation_result.is_err() {
                        return;
                    }

                    let (translation_src_port, translation_dst_port) = (
                        tr_data.src.and_then(|src| src.port).map(NatPort::as_u16),
                        tr_data.dst.and_then(|dst| dst.port).map(NatPort::as_u16),
                    );
                    let new_outer_addresses = get_outer_addresses(&icmp_error_msg_clone).unwrap();
                    let new_inner_addresses = get_inner_addresses(&icmp_error_msg_clone).unwrap();
                    let new_ports = get_inner_ports(&icmp_error_msg_clone);

                    // Check outer IP addresses are unchanged
                    assert_eq!(initial_outer_addresses, new_outer_addresses);

                    // Check inner IP addresses have been updated
                    assert_eq!(Some(new_inner_addresses.0), tr_data.src.map(|src| src.addr));
                    assert_eq!(Some(new_inner_addresses.1), tr_data.dst.map(|dst| dst.addr));

                    // Check inner ports have been updated
                    match (initial_ports, new_ports) {
                        (
                            Some(TransportFields::Ports(initial_src, initial_dst)),
                            Some(TransportFields::Ports(new_src, new_dst)),
                        ) => {
                            match translation_src_port {
                                Some(tr_src) => assert_eq!(new_src, tr_src),
                                None => assert_eq!(new_src, initial_src),
                            }
                            match translation_dst_port {
                                Some(tr_dst) => assert_eq!(new_dst, tr_dst),
                                None => assert_eq!(new_dst, initial_dst),
                            }
                        }
                        (
                            Some(TransportFields::Identifier(initial)),
                            Some(TransportFields::Identifier(new)),
                        ) => match translation_src_port {
                            Some(tr_src) => assert_eq!(new, tr_src),
                            None => assert_eq!(new, initial),
                        },
                        (None, None) => {}
                        _ => unreachable!(),
                    }

                    if new_ports.is_some() {
                        // Update and validate checksums for inner IP header, ICMP header, and outer
                        // IP header. We only check this when we have an inner transport header.
                        icmp_error_msg_clone.update_checksums();
                        let res = IcmpErrorPacket::new(&icmp_error_msg_clone)
                            .unwrap()
                            .validate_checksums();
                        assert!(res.is_ok(), "Checksum validation failed: {res:?}");
                    }
                },
            );
    }
}

/// What a NAT rewrite leaves behind in the quoted transport checksum.
///
/// Nothing downstream will catch a wrong one. RFC 5508 REQ-3(c) tells a NAT not to validate the
/// quoted transport checksum of an error it receives, so a NAT that emits a wrong one is invisible
/// until the end host finally reads the quote and finds it disagrees with the addresses and ports
/// beside it.
///
/// The oracle is a second packet built from scratch carrying the values translation was supposed to
/// produce. The fixture computes its checksums rather than folding deltas into them, so agreeing
/// with it is a statement about the arithmetic and not a restatement of it.
#[cfg(test)]
mod quoted_transport_checksum {
    use super::*;
    use net::buffer::TestBuffer;
    use net::checksum::Checksum;
    use net::headers::{TryEmbeddedTransport, TryEmbeddedTransportMut};
    use net::icmp6::{Icmp6DestUnreachable, Icmp6Type};
    use net::ip::NextHeader;
    use net::packet::test_utils::{
        Icmp6ErrorAddrs, build_test_icmp4_destination_unreachable_packet,
        build_test_icmp6_error_packet,
    };
    use net::udp::UdpChecksum;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const OUTER_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const OUTER_DST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const INNER_SRC: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const INNER_DST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    const NAT_SRC: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 200);
    const NAT_DST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 250);

    const OUTER_SRC_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const OUTER_DST_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    const INNER_SRC_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 7);
    const INNER_DST_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 9);
    const NAT_SRC_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xfeed, 0xf00d, 0, 0, 0, 0xc8);

    const OLD_PORT: u16 = 1234;
    const PEER_PORT: u16 = 5678;
    const NEW_PORT: u16 = 4321;
    const OLD_ID: u16 = 0x1111;
    const NEW_ID: u16 = 0x7f7f;

    fn quote_v4(
        inner_src: Ipv4Addr,
        inner_dst: Ipv4Addr,
        next_header: NextHeader,
        param_1: u16,
        param_2: u16,
    ) -> Packet<TestBuffer> {
        build_test_icmp4_destination_unreachable_packet(
            OUTER_SRC,
            OUTER_DST,
            inner_src,
            inner_dst,
            next_header,
            param_1,
            param_2,
        )
        .unwrap_or_else(|_| unreachable!())
    }

    fn quote_v6(
        inner_src: Ipv6Addr,
        inner_dst: Ipv6Addr,
        next_header: NextHeader,
        param_1: u16,
        param_2: u16,
    ) -> Packet<TestBuffer> {
        build_test_icmp6_error_packet(
            Icmp6Type::DestUnreachable(Icmp6DestUnreachable::NoRoute),
            Icmp6ErrorAddrs {
                outer_src: OUTER_SRC_V6,
                outer_dst: OUTER_DST_V6,
                inner_src,
                inner_dst,
            },
            next_header,
            param_1,
            param_2,
        )
        .unwrap_or_else(|_| unreachable!())
    }

    fn quoted_checksum(packet: &Packet<TestBuffer>) -> u16 {
        packet
            .try_embedded_transport()
            .and_then(EmbeddedTransport::checksum)
            .unwrap_or_else(|| unreachable!())
    }

    fn port(value: u16) -> NatPort {
        NatPort::new_port(NonZero::new(value).unwrap_or_else(|| unreachable!()))
    }

    /// A mapping that moves only an address still owes the quote a checksum.
    ///
    /// This is the case port translation cannot reach: it returns before it looks at the transport
    /// header when there is no port to move, so an address-only mapping used to leave the quoted
    /// checksum describing an address that is no longer in the packet.
    #[test]
    fn an_address_only_rewrite_reaches_a_quoted_tcp_checksum() {
        let mut translated = quote_v4(INNER_SRC, INNER_DST, NextHeader::TCP, OLD_PORT, PEER_PORT);
        nat_translate_icmp_inner_src(&mut translated, IpAddr::V4(NAT_SRC), None)
            .unwrap_or_else(|_| unreachable!());

        let built = quote_v4(NAT_SRC, INNER_DST, NextHeader::TCP, OLD_PORT, PEER_PORT);
        assert_eq!(quoted_checksum(&translated), quoted_checksum(&built));
    }

    #[test]
    fn an_address_and_port_rewrite_reaches_a_quoted_udp_checksum() {
        let mut translated = quote_v4(INNER_SRC, INNER_DST, NextHeader::UDP, OLD_PORT, PEER_PORT);
        nat_translate_icmp_inner_src(&mut translated, IpAddr::V4(NAT_SRC), Some(port(NEW_PORT)))
            .unwrap_or_else(|_| unreachable!());

        let built = quote_v4(NAT_SRC, INNER_DST, NextHeader::UDP, NEW_PORT, PEER_PORT);
        assert_eq!(quoted_checksum(&translated), quoted_checksum(&built));
    }

    #[test]
    fn a_destination_rewrite_reaches_a_quoted_tcp_checksum() {
        let mut translated = quote_v4(INNER_SRC, INNER_DST, NextHeader::TCP, OLD_PORT, PEER_PORT);
        nat_translate_icmp_inner_dst(&mut translated, IpAddr::V4(NAT_DST), Some(port(NEW_PORT)))
            .unwrap_or_else(|_| unreachable!());

        let built = quote_v4(INNER_SRC, NAT_DST, NextHeader::TCP, OLD_PORT, NEW_PORT);
        assert_eq!(quoted_checksum(&translated), quoted_checksum(&built));
    }

    /// A 128-bit address is eight folds rather than two, and every one of them has to land.
    #[test]
    fn an_ipv6_address_rewrite_reaches_a_quoted_tcp_checksum() {
        let mut translated = quote_v6(
            INNER_SRC_V6,
            INNER_DST_V6,
            NextHeader::TCP,
            OLD_PORT,
            PEER_PORT,
        );
        nat_translate_icmp_inner_src(&mut translated, IpAddr::V6(NAT_SRC_V6), None)
            .unwrap_or_else(|_| unreachable!());

        let built = quote_v6(
            NAT_SRC_V6,
            INNER_DST_V6,
            NextHeader::TCP,
            OLD_PORT,
            PEER_PORT,
        );
        assert_eq!(quoted_checksum(&translated), quoted_checksum(&built));
    }

    /// `ICMPv4` has no pseudo-header, so only the identifier moves its checksum.
    #[test]
    fn an_identifier_rewrite_reaches_a_quoted_icmp_checksum() {
        let mut translated = quote_v4(INNER_SRC, INNER_DST, NextHeader::ICMP, OLD_ID, PEER_PORT);
        nat_translate_icmp_inner_src(
            &mut translated,
            IpAddr::V4(NAT_SRC),
            Some(NatPort::Identifier(NEW_ID)),
        )
        .unwrap_or_else(|_| unreachable!());

        let built = quote_v4(NAT_SRC, INNER_DST, NextHeader::ICMP, NEW_ID, PEER_PORT);
        assert_eq!(quoted_checksum(&translated), quoted_checksum(&built));
    }

    /// A UDP datagram over IPv4 may say it computed no checksum, and NAT does not get to change
    /// its mind (RFC 768).
    ///
    /// The quote is what the sender put on the wire, zero and all; folding a delta into that zero
    /// would hand the end host a checksum for a sum nobody ever took.
    #[test]
    fn a_disabled_ipv4_udp_quote_checksum_stays_disabled() {
        let mut packet = quote_v4(INNER_SRC, INNER_DST, NextHeader::UDP, OLD_PORT, PEER_PORT);
        match packet.try_embedded_transport_mut() {
            Some(EmbeddedTransport::Udp(udp)) => {
                udp.set_checksum(UdpChecksum::new(0))
                    .unwrap_or_else(|_| unreachable!());
            }
            _ => unreachable!(),
        }

        nat_translate_icmp_inner_src(&mut packet, IpAddr::V4(NAT_SRC), Some(port(NEW_PORT)))
            .unwrap_or_else(|_| unreachable!());

        assert_eq!(
            quoted_checksum(&packet),
            0,
            "a quote that carried no checksum came out carrying one"
        );
    }

    /// Over IPv6 the field is mandatory, so zero is a value to fold into and not a marker
    /// (RFC 8200, section 8.1).
    #[test]
    fn a_zero_ipv6_udp_quote_checksum_is_folded_into() {
        let mut packet = quote_v6(
            INNER_SRC_V6,
            INNER_DST_V6,
            NextHeader::UDP,
            OLD_PORT,
            PEER_PORT,
        );
        match packet.try_embedded_transport_mut() {
            Some(EmbeddedTransport::Udp(udp)) => {
                udp.set_checksum(UdpChecksum::new(0))
                    .unwrap_or_else(|_| unreachable!());
            }
            _ => unreachable!(),
        }

        nat_translate_icmp_inner_src(&mut packet, IpAddr::V6(NAT_SRC_V6), Some(port(NEW_PORT)))
            .unwrap_or_else(|_| unreachable!());

        assert_ne!(
            quoted_checksum(&packet),
            0,
            "an IPv6 quote was left with a checksum IPv6 forbids"
        );
    }
}
