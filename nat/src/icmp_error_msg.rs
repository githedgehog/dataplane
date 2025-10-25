// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT processing for `ICMPv4` and `ICMPv6` Error messages with embedded IP packets, common to
//! stateless and stateful NAT modes

use super::NatTranslationData;
use net::buffer::PacketBufferMut;
use net::checksum::{Checksum, ChecksumError};
use net::headers::{
    EmbeddedTransport, TryEmbeddedHeaders, TryEmbeddedHeadersMut, TryEmbeddedTransportMut,
    TryHeaders, TryInnerIpMut, TryInnerIpv4, TryIp, TryTransport,
};
use net::icmp_any::{IcmpAny, IcmpAnyChecksumErrorPlaceholder, IcmpAnyChecksumPayload};
use net::ipv4::Ipv4;
use net::packet::Packet;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IcmpErrorMsgError {
    #[error("failure to get IP header")]
    BadIpHeader,
    #[error("failed to validate ICMP checksum")]
    BadChecksumIcmp(ChecksumError<IcmpAnyChecksumErrorPlaceholder>),
    #[error("failed to validate ICMP inner IP checksum")]
    BadChecksumInnerIpv4(ChecksumError<Ipv4>),
    #[error("invalid transport-layer port {0}")]
    InvalidPort(u16),
    #[error("invalid IP version")]
    InvalidIpVersion,
    #[error("IP address {0} is not unicast")]
    NotUnicast(IpAddr),
}

// # Return
//
// * An error if we fail to validate relevant checksums and packet should be dropped
// * `true` if checksums are valid and we need to translate the inner packet
// * `false` if we don't need to translate the inner packet
pub(crate) fn validate_checksums_icmp<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
) -> Result<bool, IcmpErrorMsgError> {
    let headers = packet.headers();
    let Some(net) = headers.try_ip() else {
        // No network layer, no translation needed
        return Ok(false);
    };
    let Some(transport) = packet.headers().try_transport() else {
        // No transport layer, no translation needed
        return Ok(false);
    };

    let Ok(icmp) = IcmpAny::try_from(transport) else {
        // Not ICMPv4 or ICMPv6, no translation needed
        return Ok(false);
    };
    if !icmp.is_error_message() {
        // Not an ICMP error message, no translation needed
        return Ok(false);
    }

    let icmp_payload =
        icmp.get_payload_for_checksum(packet.embedded_headers(), packet.payload().as_ref());
    let checksum_payload = IcmpAnyChecksumPayload::from_net(net, icmp_payload.as_ref());

    // From REQ-3 from RFC 5508, "NAT Behavioral Requirements for ICMP":
    //
    //    When an ICMP Error packet is received, if the ICMP checksum fails to validate, the NAT
    //    SHOULD silently drop the ICMP Error packet.
    icmp.validate_checksum(&checksum_payload)
        .map_err(|e| IcmpErrorMsgError::BadChecksumIcmp(e.into()))?;

    let Some(embedded_ip) = packet.embedded_headers() else {
        // No embedded IP packet to translate
        return Ok(false);
    };

    // From REQ-3 a) from RFC 5508, "NAT Behavioral Requirements for ICMP":
    //
    //    If the IP checksum of the embedded packet fails to validate, the NAT SHOULD silently
    //    drop the Error packet
    //
    // Note: IPv6 headers have no checksum so we only do IPv4
    if let Some(inner_ipv4) = embedded_ip.try_inner_ipv4() {
        inner_ipv4
            .validate_checksum(&())
            .map_err(IcmpErrorMsgError::BadChecksumInnerIpv4)?;
    }

    Ok(true)
}

pub(crate) fn stateful_translate_icmp_inner<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    state: &NatTranslationData,
) -> Result<(), IcmpErrorMsgError> {
    let (target_src_addr, target_dst_addr, target_src_port, target_dst_port) = (
        state.src_addr,
        state.dst_addr,
        state.src_port,
        state.dst_port,
    );
    let embedded_headers = packet
        .embedded_headers_mut()
        .ok_or(IcmpErrorMsgError::BadIpHeader)?;

    // From REQ-4 from RFC 5508, "NAT Behavioral Requirements for ICMP":
    //
    //    If the NAT has active mapping for the embedded payload, then the NAT MUST do the
    //    following prior to forwarding the packet, unless explicitly overridden by local
    //    policy:
    //
    //        a) Revert the IP and transport headers of the embedded IP packet to their original
    //        form, using the matching mapping;
    let net = embedded_headers
        .try_inner_ip_mut()
        .ok_or(IcmpErrorMsgError::BadIpHeader)?;
    if let Some(target_src_ip) = target_src_addr {
        net.try_set_source(
            target_src_ip
                .try_into()
                .map_err(|_| IcmpErrorMsgError::NotUnicast(target_src_ip))?,
        )
        .map_err(|_| IcmpErrorMsgError::InvalidIpVersion)?;
    }

    let net = embedded_headers
        .try_inner_ip_mut()
        .ok_or(IcmpErrorMsgError::BadIpHeader)?;
    if let Some(target_dst_ip) = target_dst_addr {
        net.try_set_destination(target_dst_ip)
            .map_err(|_| IcmpErrorMsgError::InvalidIpVersion)?;
    }

    let Some(transport) = embedded_headers.try_embedded_transport_mut() else {
        // No transport layer in the inner packet, that's fine, we're done here
        // TODO: Log trace anyway?
        return Ok(());
    };
    if matches!(
        transport,
        EmbeddedTransport::Icmp4(_) | EmbeddedTransport::Icmp6(_)
    ) {
        // FIXME: We don't support ICMP identifier's translation yet. We're done (for now).
        return Ok(());
    }
    // We returned early for ICMP, so we have TCP or UDP, and always source and destination ports
    let (old_src_port, old_dst_port) = (
        transport.source().unwrap_or_else(|| unreachable!()).into(),
        transport
            .destination()
            .unwrap_or_else(|| unreachable!())
            .into(),
    );

    if let Some(target_src_port) = target_src_port {
        transport
            .set_source(
                target_src_port
                    .try_into()
                    .map_err(|_| IcmpErrorMsgError::InvalidPort(target_src_port.as_u16()))?,
            )
            .unwrap_or_else(|_| unreachable!());
        // We don't know whether the header and payload are full: the easiest way to deal with
        // transport checksum update is to do an unconditional, incremental update here. Note
        // that this checksum will not be updated again when deparsing the packet.
        if let Some(current_checksum) = transport.checksum() {
            transport.update_checksum(current_checksum, old_src_port, target_src_port.as_u16());
        }
    }
    if let Some(target_dst_port) = target_dst_port {
        transport
            .set_destination(
                target_dst_port
                    .try_into()
                    .map_err(|_| IcmpErrorMsgError::InvalidPort(target_dst_port.as_u16()))?,
            )
            .unwrap_or_else(|_| unreachable!());
        if let Some(current_checksum) = transport.checksum() {
            transport.update_checksum(current_checksum, old_dst_port, target_dst_port.as_u16());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::icmpv4::DestUnreachableHeader;
    use etherparse::{IcmpEchoHeader, Icmpv4Type};
    use net::buffer::TestBuffer;
    use net::eth::Eth;
    use net::eth::ethtype::EthType;
    use net::eth::mac::{DestinationMac, Mac, SourceMac};
    use net::headers::{HeadersBuilder, Net, Transport};
    use net::icmp4::Icmp4;
    use net::ip::NextHeader;
    use net::ipv4::Ipv4;
    use net::packet::Packet;
    use net::parse::DeParse;
    use std::net::Ipv4Addr;

    #[test]
    fn test_validate_checksums_icmp_no_network_layer() {
        // Build a packet without IP header
        let mut headers = HeadersBuilder::default();
        headers.eth(Some(Eth::new(
            SourceMac::new(Mac([0x2, 0, 0, 0, 0, 1])).unwrap(),
            DestinationMac::new(Mac([0x2, 0, 0, 0, 0, 2])).unwrap(),
            EthType::IPV4,
        )));
        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let result = validate_checksums_icmp(&packet);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_validate_checksums_icmp_no_transport_layer() {
        // Build a packet with IP but no transport
        let mut headers = HeadersBuilder::default();
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        headers.net(Some(Net::Ipv4(ipv4)));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let result = validate_checksums_icmp(&packet);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_validate_checksums_icmp_not_icmp() {
        // Build a TCP packet
        let mut headers = HeadersBuilder::default();
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        ipv4.set_next_header(NextHeader::TCP);

        let tcp = net::tcp::Tcp::default();

        headers.net(Some(Net::Ipv4(ipv4)));
        headers.transport(Some(Transport::Tcp(tcp)));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let result = validate_checksums_icmp(&packet);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_validate_checksums_icmp_query_message() {
        // Build an ICMP Echo Request (query message)
        let mut headers = HeadersBuilder::default();
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        ipv4.set_next_header(NextHeader::ICMP);

        let icmp_type = Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 1, seq: 1 });
        let icmp = Icmp4::with_type(icmp_type);

        headers.net(Some(Net::Ipv4(ipv4)));
        headers.transport(Some(Transport::Icmp4(icmp)));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let result = validate_checksums_icmp(&packet);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_validate_checksums_icmp_error_no_embedded_headers() {
        // Build an ICMP error message without embedded headers
        let mut headers = HeadersBuilder::default();
        let mut ipv4 = Ipv4::default();
        ipv4.set_source(Ipv4Addr::new(1, 2, 3, 4).try_into().unwrap());
        ipv4.set_destination(Ipv4Addr::new(5, 6, 7, 8));
        ipv4.set_next_header(NextHeader::ICMP);

        let icmp_type = Icmpv4Type::DestinationUnreachable(DestUnreachableHeader::Network);
        let icmp = Icmp4::with_type(icmp_type);

        headers.net(Some(Net::Ipv4(ipv4)));
        headers.transport(Some(Transport::Icmp4(icmp)));

        let headers = headers.build().unwrap();
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).unwrap();
        let packet = Packet::new(buffer).unwrap();

        let result = validate_checksums_icmp(&packet);
        assert_eq!(result, Ok(false));
    }
}

#[cfg(test)]
mod bolero_tests {
    use super::*;
    use crate::NatPort;
    use net::buffer::TestBuffer;
    use net::headers::{
        Net, TryEmbeddedTransport, TryIcmpAnyMut, TryInnerIp, TryInnerIpv4Mut, TryIpv4,
    };
    use net::icmp_any::IcmpAnyChecksum;
    use net::ipv4::{Ipv4Checksum, UnicastIpv4Addr};
    use net::ipv6::UnicastIpv6Addr;
    use net::packet::IcmpErrorMsg;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
                let mut icmp_error_msg_clone = icmp_error_msg.clone();
                // First check that checksum is incorrect. There's a super-high chance that it fails
                // with non-initialised checksums in all relevant haders, but 1) there may be only
                // one checksum to validate (for IPv6 packets, inner IP headers have no checksums)
                // and 2) sometimes Bolero reuses headers in which we set the correct checksums.
                // So we first "erase" all checksums by setting them to 0xffff.
                erase_checksums(&mut icmp_error_msg_clone);
                // Validate checksum is incorrect
                let res = validate_checksums_icmp::<TestBuffer>(&icmp_error_msg_clone);
                assert!(matches!(
                    res,
                    Err(IcmpErrorMsgError::BadChecksumIcmp(
                        ChecksumError::Mismatch { .. }
                    ))
                ));

                // Update checksums for outer IP header, ICMP header, inner IP header; not the inner transport header
                icmp_error_msg_clone.update_checksums();

                // Now, ICMP and inner IP headers checksums should be valid
                let res = validate_checksums_icmp::<TestBuffer>(&icmp_error_msg_clone);
                assert_eq!(res, Ok(true), "Checksum validation failed: {res:?}");

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
                    let mut icmp_error_msg_clone = icmp_error_msg.clone();
                    let inner_translation_result =
                        stateful_translate_icmp_inner(&mut icmp_error_msg_clone, &tr_data);
                    if *src_port == Some(NatPort::Identifier(0))
                        || *dst_port == Some(NatPort::Identifier(0))
                    {
                        match icmp_error_msg_clone.try_embedded_transport_mut() {
                            Some(EmbeddedTransport::Tcp(_) | EmbeddedTransport::Udp(_)) => {
                                assert_eq!(
                                    inner_translation_result,
                                    Err(IcmpErrorMsgError::InvalidPort(0))
                                );
                                return;
                            }
                            _ => {
                                assert!(inner_translation_result.is_ok());
                            }
                        }
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

                    // Update and validate checksums for inner IP header, ICMP header, and outer IP header
                    icmp_error_msg_clone.update_checksums();
                    let res = validate_checksums_icmp::<TestBuffer>(&icmp_error_msg_clone);
                    assert_eq!(res, Ok(true), "Checksum validation failed: {res:?}");
                },
            );
    }
}
