// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT processing for `ICMPv4` and `ICMPv6` Error messages with embedded IP packets, common to
//! stateless and stateful NAT modes

use crate::NatPort;
use crate::NatTranslationData;
use net::buffer::PacketBufferMut;
use net::checksum::Checksum;
use net::headers::{
    EmbeddedTransport, TryEmbeddedHeadersMut, TryEmbeddedTransportMut, TryInnerIpMut,
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

impl From<IcmpErrorMsgError> for DoneReason {
    fn from(error: IcmpErrorMsgError) -> Self {
        (&error).into()
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

    embedded_headers
        .try_inner_ip_mut()
        .ok_or(IcmpErrorMsgError::NoInnerIpHeader)?
        .try_set_source(
            target_addr
                .try_into()
                .map_err(|_| IcmpErrorMsgError::NotUnicast(target_addr))?,
        )
        .map_err(|_| IcmpErrorMsgError::InvalidIpVersion)?;

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
            translate_inner_tcp_udp_src(transport, target_port)?;
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

    embedded_headers
        .try_inner_ip_mut()
        .ok_or(IcmpErrorMsgError::NoInnerIpHeader)?
        .try_set_destination(target_addr)
        .map_err(|_| IcmpErrorMsgError::InvalidIpVersion)?;

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
            translate_inner_tcp_udp_dst(transport, target_port)
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
    let _ = icmp.increment_update_checksum(
        T::Checksum::from(current_checksum),
        old_identifier,
        new_identifier,
    );
}

fn translate_inner_tcp_udp_src(
    transport: &mut EmbeddedTransport,
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
        transport.update_checksum(current_checksum, old_port, new_port.get());
    }
    Ok(())
}

fn translate_inner_tcp_udp_dst(
    transport: &mut EmbeddedTransport,
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
        transport.update_checksum(current_checksum, old_port, new_port.get());
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
