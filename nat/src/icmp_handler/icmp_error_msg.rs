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
    let (target_src_addr, target_dst_addr, target_src_port, target_dst_port) = (
        state.src_addr,
        state.dst_addr,
        state.src_port,
        state.dst_port,
    );

    // From REQ-4 from RFC 5508, "NAT Behavioral Requirements for ICMP":
    //
    //    If the NAT has active mapping for the embedded payload, then the NAT MUST do the
    //    following prior to forwarding the packet, unless explicitly overridden by local
    //    policy:
    //
    //        a) Revert the IP and transport headers of the embedded IP packet to their original
    //        form, using the matching mapping;
    if let Some(src_addr) = target_src_addr {
        nat_translate_icmp_inner_src(packet, src_addr, target_src_port)?;
    }
    if let Some(dst_addr) = target_dst_addr {
        nat_translate_icmp_inner_dst(packet, dst_addr, target_dst_port)?;
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

    // The inner IP addresses belong to the pseudo-header covered by the checksum of the inner
    // transport header, for TCP/UDP/ICMPv6 (but not ICMPv4). Update the checksum if relevant.
    if let Some(transport) = embedded_headers.try_embedded_transport_mut() {
        // Note: update_checksum_for_address is a no-op for ICMPv4
        transport.update_checksum_for_address(old_addr, target_addr);
    }

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

    // See the comment on the source address translation: update the checksum of the inner
    // transport header to account for the new address in the pseudo-header.
    if let Some(transport) = embedded_headers.try_embedded_transport_mut() {
        transport.update_checksum_for_address(old_addr, target_addr);
    }

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

fn quoted_version(addr: IpAddr) -> EmbeddedIpVersion {
    if addr.is_ipv4() {
        EmbeddedIpVersion::Ipv4
    } else {
        EmbeddedIpVersion::Ipv6
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
    let _ = icmp.increment_update_checksum(
        T::Checksum::from(current_checksum),
        old_identifier,
        new_identifier,
    );
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
    use crate::NatPort;
    use net::buffer::TestBuffer;
    use net::checksum::ChecksumError;
    use net::headers::TryHeaders;
    use net::headers::{
        Net, TryEmbeddedHeaders, TryEmbeddedTransport, TryIcmpAnyMut, TryInnerIp, TryInnerIpv4Mut,
        TryIp, TryIpv4,
    };
    use net::icmp_any::IcmpAnyChecksum;
    use net::icmp6::Icmp6ChecksumPayload;
    use net::ipv4::{Ipv4Checksum, UnicastIpv4Addr};
    use net::ipv6::UnicastIpv6Addr;
    use net::packet::IcmpErrorMsg;
    use net::packet::icmp_err::{IcmpErrorPacket, IcmpErrorPacketError};
    use net::tcp::TcpChecksumPayload;
    use net::udp::UdpChecksumPayload;
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

    fn get_inner_transport_checksum(packet: &Packet<TestBuffer>) -> Option<u16> {
        packet
            .try_embedded_transport()
            .and_then(EmbeddedTransport::checksum)
    }

    // Compute from scratch the checksum of the embedded transport header, over the inner headers
    // and the embedded transport payload.
    //
    // Returns None when the embedded IP packet fragment is truncated, because we then miss some of
    // the data covered by the checksum, and can't recompute it.
    // Tell whether the embedded transport header is UDP, and if so whether it carries no checksum
    // at all, which RFC 768 allows over IPv4 only
    fn inner_udp_state(packet: &Packet<TestBuffer>) -> (bool, bool) {
        let is_udp = matches!(
            packet.try_embedded_transport(),
            Some(EmbeddedTransport::Udp(_))
        );
        let disabled = is_udp
            && matches!(packet.try_inner_ip(), Some(Net::Ipv4(_)))
            && get_inner_transport_checksum(packet) == Some(0);
        (is_udp, disabled)
    }

    // RFC 768: a UDP checksum that computes to zero travels as all ones, so that it is not mistaken
    // for the marker for "no checksum"
    fn spell_udp_zero(checksum: u16, is_udp: bool) -> u16 {
        if is_udp && checksum == 0 {
            u16::MAX
        } else {
            checksum
        }
    }

    fn compute_inner_transport_checksum(packet: &Packet<TestBuffer>) -> Option<u16> {
        let embedded_headers = packet.embedded_headers()?;
        // The bytes left in the packet hold the embedded transport payload, followed with the
        // optional ICMP padding and Extension Structures which are not covered by the checksum
        let payload_length = usize::from(embedded_headers.payload_length()?);
        let payload = packet.payload().as_ref().get(..payload_length)?;
        let inner_net = embedded_headers.try_inner_ip()?;
        match embedded_headers.try_embedded_transport()? {
            EmbeddedTransport::Tcp(tcp) => tcp
                .compute_checksum(&TcpChecksumPayload::new(inner_net, payload))
                .map(u16::from)
                .ok(),
            EmbeddedTransport::Udp(udp) => udp
                .compute_checksum(&UdpChecksumPayload::new(inner_net, payload))
                .map(|checksum| spell_udp_zero(u16::from(checksum), true))
                .ok(),
            EmbeddedTransport::Icmp4(icmp4) => icmp4.compute_checksum(payload).map(u16::from).ok(),
            EmbeddedTransport::Icmp6(icmp6) => {
                let Net::Ipv6(inner_ipv6) = inner_net else {
                    return None;
                };
                let checksum_payload = Icmp6ChecksumPayload::new(
                    inner_ipv6.source().inner(),
                    inner_ipv6.destination(),
                    payload,
                );
                icmp6
                    .compute_checksum(&checksum_payload)
                    .map(u16::from)
                    .ok()
            }
        }
    }

    fn set_inner_transport_checksum(packet: &mut Packet<TestBuffer>, checksum: u16) {
        if let Some(transport) = packet.try_embedded_transport_mut() {
            EmbeddedTransport::set_checksum_if_possible(transport, checksum);
        }
    }

    // Reference implementation of the incremental checksum update from RFC 1624, relying on
    //
    //     HC' = ~(~HC + ~m + m')    --    [Eqn. 3]
    //
    // instead of the [Eqn. 4] variant used by increment_update_checksum(), so that we don't
    // validate the implementation against itself.
    fn expected_incremental_checksum(current_checksum: u16, old_value: u16, new_value: u16) -> u16 {
        fn add_ones_complement(a: u16, b: u16) -> u16 {
            let mut sum = u32::from(a) + u32::from(b);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            u16::try_from(sum).unwrap_or_else(|_| unreachable!())
        }
        if old_value == new_value {
            // Like Checksum::incremental_checksum(), skip a value that doesn't change: folding it
            // in would be neutral, but for a 0xffff checksum, which it would rewrite as 0x0000
            return current_checksum;
        }
        !add_ones_complement(
            add_ones_complement(!current_checksum, !old_value),
            new_value,
        )
    }

    // Pair up the 16-bit words of an IP address change, in the order in which they are covered by
    // the pseudo-header. The translation skips the update altogether when the address doesn't
    // change, so return no pair in that case.
    fn address_word_changes(old: IpAddr, new: IpAddr) -> Vec<(u16, u16)> {
        fn words(addr: IpAddr) -> Vec<u16> {
            match addr {
                IpAddr::V4(addr) => {
                    let [a, b, c, d] = addr.octets();
                    vec![u16::from_be_bytes([a, b]), u16::from_be_bytes([c, d])]
                }
                IpAddr::V6(addr) => addr.segments().to_vec(),
            }
        }
        if old == new {
            return Vec::new();
        }
        words(old).into_iter().zip(words(new)).collect()
    }

    // Check that the checksum of the inner transport header accounts for the new addresses, ports
    // or ICMP identifier, with incremental updates. This is all we can check when the embedded IP
    // packet fragment is truncated, as we can't recompute the checksum from scratch in that case.
    fn check_inner_transport_checksum(
        packet: &Packet<TestBuffer>,
        initial_checksum: Option<u16>,
        initial_addresses: (IpAddr, IpAddr),
        initial_ports: Option<TransportFields>,
        new_ports: Option<TransportFields>,
        udp: (bool, bool),
    ) {
        let (is_udp, udp_checksum_disabled) = udp;
        // The checksum of ICMPv4 covers no pseudo-header, the inner IP addresses don't affect it
        let addresses_covered = !matches!(
            packet.try_embedded_transport(),
            Some(EmbeddedTransport::Icmp4(_))
        );
        let new_addresses = get_inner_addresses(packet).unwrap();

        // Replicate the incremental updates that the translation performs. The order in which we
        // chain them is indifferent: they are additions in one's complement arithmetic, which is
        // commutative, down to the representation of the resulting checksum.
        let mut changes = Vec::new();
        if addresses_covered {
            changes.extend(address_word_changes(initial_addresses.0, new_addresses.0));
        }
        match (initial_ports, new_ports) {
            (
                Some(TransportFields::Ports(initial_src, _)),
                Some(TransportFields::Ports(new_src, _)),
            ) if initial_src != new_src => changes.push((initial_src, new_src)),
            (
                Some(TransportFields::Identifier(initial)),
                Some(TransportFields::Identifier(new)),
            ) if initial != new => changes.push((initial, new)),
            _ => {}
        }
        if addresses_covered {
            changes.extend(address_word_changes(initial_addresses.1, new_addresses.1));
        }
        if let (
            Some(TransportFields::Ports(_, initial_dst)),
            Some(TransportFields::Ports(_, new_dst)),
        ) = (initial_ports, new_ports)
            && initial_dst != new_dst
        {
            changes.push((initial_dst, new_dst));
        }

        let expected = initial_checksum.map(|checksum| {
            if udp_checksum_disabled {
                // The quote carries no checksum for the translation to update
                return checksum;
            }
            changes
                .into_iter()
                .fold(checksum, |checksum, (old_value, new_value)| {
                    let updated = expected_incremental_checksum(checksum, old_value, new_value);
                    spell_udp_zero(updated, is_udp)
                })
        });
        assert_eq!(
            get_inner_transport_checksum(packet),
            expected,
            "inner transport checksum not incrementally updated as expected"
        );
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
    #[allow(clippy::too_many_lines)]
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
                    let mut icmp_error_msg_clone = icmp_error_msg.clone();

                    // The generator doesn't set checksums. When the embedded IP packet fragment is
                    // not truncated, set a valid checksum on the embedded transport header, so that
                    // we can recompute it from scratch after the translation and compare.
                    let inner_payload_is_full =
                        match compute_inner_transport_checksum(&icmp_error_msg_clone) {
                            Some(checksum) => {
                                set_inner_transport_checksum(&mut icmp_error_msg_clone, checksum);
                                true
                            }
                            None => false,
                        };
                    let (inner_is_udp, inner_udp_checksum_disabled) =
                        inner_udp_state(&icmp_error_msg_clone);

                    let initial_outer_addresses =
                        get_outer_addresses(&icmp_error_msg_clone).unwrap();
                    let initial_inner_addresses = get_inner_addresses(&icmp_error_msg_clone);
                    let initial_ports = get_inner_ports(&icmp_error_msg_clone);
                    let initial_inner_checksum =
                        get_inner_transport_checksum(&icmp_error_msg_clone);
                    let tr_data = match icmp_error_msg.headers().try_ip() {
                        Some(Net::Ipv4(_)) => NatTranslationData {
                            src_addr: Some(IpAddr::V4(Ipv4Addr::from(*src_v4))),
                            dst_addr: Some(IpAddr::V4(*dst_v4)),
                            src_port: *src_port,
                            dst_port: *dst_port,
                        },
                        Some(Net::Ipv6(_)) => NatTranslationData {
                            src_addr: Some(IpAddr::V6(Ipv6Addr::from(*src_v6))),
                            dst_addr: Some(IpAddr::V6(*dst_v6)),
                            src_port: *src_port,
                            dst_port: *dst_port,
                        },
                        None => unreachable!(),
                    };

                    // Translate inner IP addresses, and possibly inner ports
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
                        tr_data.src_port.map(NatPort::as_u16),
                        tr_data.dst_port.map(NatPort::as_u16),
                    );
                    let new_outer_addresses = get_outer_addresses(&icmp_error_msg_clone).unwrap();
                    let new_inner_addresses = get_inner_addresses(&icmp_error_msg_clone).unwrap();
                    let new_ports = get_inner_ports(&icmp_error_msg_clone);

                    // Check outer IP addresses are unchanged
                    assert_eq!(initial_outer_addresses, new_outer_addresses);

                    // Check inner IP addresses have been updated
                    assert_eq!(Some(new_inner_addresses.0), tr_data.src_addr);
                    assert_eq!(Some(new_inner_addresses.1), tr_data.dst_addr);

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

                    // Check the checksum of the inner transport header has been updated
                    if inner_payload_is_full {
                        assert_eq!(
                            get_inner_transport_checksum(&icmp_error_msg_clone).unwrap(),
                            compute_inner_transport_checksum(&icmp_error_msg_clone).unwrap(),
                            "inner transport checksum doesn't match the recomputed value"
                        );
                    } else {
                        check_inner_transport_checksum(
                            &icmp_error_msg_clone,
                            initial_inner_checksum,
                            initial_inner_addresses.unwrap(),
                            initial_ports,
                            new_ports,
                            (inner_is_udp, inner_udp_checksum_disabled),
                        );
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

#[cfg(test)]
mod quoted_transport_checksum {
    use super::*;
    use net::buffer::TestBuffer;
    use net::headers::{TryEmbeddedTransport, TryEmbeddedTransportMut};
    use net::ip::NextHeader;
    use net::packet::test_utils::build_test_icmp4_destination_unreachable_packet;
    use net::udp::UdpChecksum;
    use std::net::Ipv4Addr;

    const OUTER_SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const OUTER_DST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const INNER_SRC: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);
    const INNER_DST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
    const NAT_SRC: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 200);
    const OLD_PORT: u16 = 1234;
    const PEER_PORT: u16 = 5678;
    const NEW_PORT: u16 = 4321;

    fn quoted_checksum(packet: &Packet<TestBuffer>) -> Option<u16> {
        packet
            .try_embedded_transport()
            .and_then(EmbeddedTransport::checksum)
    }

    // Translating both the address and the port of a quote that carries no checksum must not
    // conjure one: this covers the IP version that we hand over to the net crate, too.
    #[test]
    fn a_disabled_ipv4_udp_quote_checksum_stays_disabled() {
        let mut packet = build_test_icmp4_destination_unreachable_packet(
            OUTER_SRC,
            OUTER_DST,
            INNER_SRC,
            INNER_DST,
            NextHeader::UDP,
            OLD_PORT,
            PEER_PORT,
        )
        .unwrap_or_else(|_| unreachable!());
        match packet.try_embedded_transport_mut() {
            Some(EmbeddedTransport::Udp(udp)) => {
                udp.set_checksum(UdpChecksum::new(0))
                    .unwrap_or_else(|_| unreachable!());
            }
            _ => unreachable!(),
        }

        let target_port =
            NatPort::new_port(NonZero::new(NEW_PORT).unwrap_or_else(|| unreachable!()));
        nat_translate_icmp_inner_src(&mut packet, IpAddr::V4(NAT_SRC), Some(target_port))
            .unwrap_or_else(|_| unreachable!());

        assert_eq!(
            quoted_checksum(&packet),
            Some(0),
            "a quote that carried no checksum came out carrying one"
        );
    }
}
