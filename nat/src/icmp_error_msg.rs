// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT processing for `ICMPv4` and `ICMPv6` Error messages with embedded IP packets, common to
//! stateless and stateful NAT modes

use super::NatTranslationData;
use net::buffer::PacketBufferMut;
use net::checksum::{Checksum, ChecksumError};
use net::headers::{
    TryEmbeddedHeaders, TryEmbeddedHeadersMut, TryEmbeddedTransportMut, TryHeaders, TryInnerIpMut,
    TryInnerIpv4, TryIp, TryTransport,
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
    let (old_src_port, old_dst_port) = (transport.source().into(), transport.destination().into());

    if let Some(target_src_port) = target_src_port {
        transport.set_source(target_src_port.into());
        // We don't know whether the header and payload are full: the easiest way to deal with
        // transport checksum update is to do an unconditional, incremental update here. Note
        // that this checksum will not be updated again when deparsing the packet.
        if let Some(current_checksum) = transport.checksum() {
            transport.update_checksum(current_checksum, old_src_port, target_src_port.as_u16());
        }
    }
    if let Some(target_dst_port) = target_dst_port {
        transport.set_destination(target_dst_port.into());
        if let Some(current_checksum) = transport.checksum() {
            transport.update_checksum(current_checksum, old_dst_port, target_dst_port.as_u16());
        }
    }

    Ok(())
}
