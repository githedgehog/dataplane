// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding packet helpers. These helpers are only meaningful
//! in a port-forwarding context since they expect packets to be IPv4/IPv6
//! with UDP/TCP payloads.

use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{NetError, Transport, TransportError, TryHeadersMut};
use net::ip::{NextHeader, UnicastIpAddr};
use net::packet::Packet;
use std::net::IpAddr;
use std::num::NonZero;

use crate::common::NatAction;
use crate::portfw::PortFwState;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NatPacketError {
    #[error("Failed to update ip header")]
    UpdateNet(#[from] NetError),
    #[error("Failed to update transport header")]
    UpdateTransport(#[from] TransportError),
    #[error("Failed to NAT packet: unsupported traffic")]
    UnsupportedTraffic,
}

#[inline]
fn is_port_forwardable(net: &Net) -> bool {
    matches!(net.next_header(), NextHeader::UDP | NextHeader::TCP)
}

#[inline]
fn is_icmp(net: &Net) -> bool {
    match net {
        Net::Ipv4(ipv4) => ipv4.next_header() == NextHeader::ICMP,
        Net::Ipv6(ipv6) => ipv6.next_header() == NextHeader::ICMP6,
    }
}

#[inline]
/// Perform source-nat/pat for a packet
fn snat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_src_ip: UnicastIpAddr,
    new_src_port: NonZero<u16>,
) -> Result<bool, NatPacketError> {
    debug_assert!(
        !packet.meta().is_src_natted(),
        "Trying to apply double source NAT to packet!"
    );

    let mut modified = false;
    // See `masquerade::packet`: set only where an incremental update is impossible, so the ordinary
    // case skips the full payload recompute in `ipforward`.
    let mut needs_full_recompute = false;
    match packet
        .headers_mut()
        .pat_mut()
        .eth()
        .net()
        .transport()
        .done()
    {
        // traffic can be port forwarded: it's Ip + UDP/TCP
        Some((_, ip, tp)) if is_port_forwardable(ip) => {
            let old_addr = ip.src_addr();
            if old_addr != new_src_ip.inner() {
                ip.try_set_source(new_src_ip)?;
                if !tp.increment_checksum_for_address(old_addr, new_src_ip.inner()) {
                    // An IP version change is not an incremental update; fall back.
                    needs_full_recompute = true;
                }
                modified = true;
            }
            if let Some(p) = tp.src_port()
                && p != new_src_port
            {
                tp.try_set_source(new_src_port)?;
                tp.increment_checksum_for_u16(p.get(), new_src_port.get());
                modified = true;
            }
        }
        // needed for ICMP error handling. Only the address changes here -- the identifier is left
        // alone -- so this is a no-op for `ICMPv4` (no pseudo-header) and a real delta for `ICMPv6`.
        // Matched on the `Transport` rather than the inner header so the helper can tell them apart.
        Some((_, ip, tp))
            if matches!(tp, Transport::Icmp4(_) | Transport::Icmp6(_)) && is_icmp(ip) =>
        {
            let old_addr = ip.src_addr();
            if old_addr != new_src_ip.inner() {
                ip.try_set_source(new_src_ip)?;
                if !tp.increment_checksum_for_address(old_addr, new_src_ip.inner()) {
                    needs_full_recompute = true;
                }
                modified = true;
            }
        }
        _ => {
            return Err(NatPacketError::UnsupportedTraffic);
        }
    }
    if modified {
        packet.meta_mut().set_checksum_refresh(needs_full_recompute);
        packet.meta_mut().src_natted(true);
    }
    Ok(modified)
}

#[inline]
/// Perform dst-nat/pat for a packet
fn dnat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_dst_ip: IpAddr,
    new_dst_port: NonZero<u16>,
) -> Result<bool, NatPacketError> {
    debug_assert!(
        !packet.meta().is_dst_natted(),
        "Trying to apply double destination NAT to packet!"
    );

    let mut modified = false;
    let mut needs_full_recompute = false;
    match packet
        .headers_mut()
        .pat_mut()
        .eth()
        .net()
        .transport()
        .done()
    {
        Some((_, ip, tp)) if is_port_forwardable(ip) => {
            let old_addr = ip.dst_addr();
            if old_addr != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                if !tp.increment_checksum_for_address(old_addr, new_dst_ip) {
                    needs_full_recompute = true;
                }
                modified = true;
            }
            if let Some(p) = tp.dst_port()
                && p != new_dst_port
            {
                tp.try_set_destination(new_dst_port)?;
                tp.increment_checksum_for_u16(p.get(), new_dst_port.get());
                modified = true;
            }
        }
        // needed for ICMP error handling; see `snat_packet` for why this matches on `Transport`.
        Some((_, ip, tp))
            if matches!(tp, Transport::Icmp4(_) | Transport::Icmp6(_)) && is_icmp(ip) =>
        {
            let old_addr = ip.dst_addr();
            if old_addr != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                if !tp.increment_checksum_for_address(old_addr, new_dst_ip) {
                    needs_full_recompute = true;
                }
                modified = true;
            }
        }
        _ => {
            return Err(NatPacketError::UnsupportedTraffic);
        }
    }
    if modified {
        packet.meta_mut().set_checksum_refresh(needs_full_recompute);
        packet.meta_mut().dst_natted(true);
    }
    Ok(modified)
}

/// Perform src or dst nat for a packet, depending on the action indicated in state
pub(crate) fn nat_packet<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    state: &PortFwState,
) -> Result<bool, NatPacketError> {
    match state.action() {
        NatAction::DstNat => dnat_packet(packet, state.use_ip().inner(), state.use_port()),
        NatAction::SrcNat => snat_packet(packet, state.use_ip(), state.use_port()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod checksum_test {
    use super::*;
    use net::buffer::TestBuffer;
    use net::checksum::Checksum;
    use net::headers::{TryHeaders, TryTransport};
    use net::ip::NextHeader;
    use net::packet::test_utils::{
        build_test_ipv4_packet_with_transport, build_test_ipv6_packet_with_transport,
        build_test_tcp_ipv4_packet,
    };

    fn transport_checksum(packet: &Packet<TestBuffer>) -> Option<u16> {
        packet.headers().try_transport().and_then(|tp| match tp {
            Transport::Tcp(tcp) => tcp.checksum().map(u16::from),
            Transport::Udp(udp) => udp.checksum().map(u16::from),
            Transport::Icmp4(icmp) => icmp.checksum().map(u16::from),
            Transport::Icmp6(icmp) => icmp.checksum().map(u16::from),
        })
    }

    /// The incremental result must equal a full recompute, and the recompute must be skipped.
    ///
    /// Asserting both matters: a conversion that silently keeps setting `checksum_refresh` would
    /// still be *correct*, and would look like it passed while delivering none of the benefit.
    fn agrees_with_recompute(mut packet: Packet<TestBuffer>, source: bool) {
        packet.update_checksums();

        let new_ip = UnicastIpAddr::try_from(IpAddr::from([9, 9, 9, 9])).unwrap();
        let new_port = NonZero::new(4321).unwrap();
        let modified = if source {
            snat_packet(&mut packet, new_ip, new_port).expect("snat_packet")
        } else {
            dnat_packet(&mut packet, new_ip.inner(), new_port).expect("dnat_packet")
        };
        assert!(modified, "the test packet was not actually translated");
        assert!(
            !packet.meta().checksum_refresh(),
            "port forwarding asked for a full payload recompute; the incremental path was skipped"
        );

        let incremental = transport_checksum(&packet);
        packet.update_checksums();
        assert_eq!(
            incremental,
            transport_checksum(&packet),
            "the incremental checksum disagrees with a full recompute"
        );
    }

    #[test]
    fn tcp_snat_agrees_with_a_recompute() {
        agrees_with_recompute(
            build_test_tcp_ipv4_packet("1.2.3.4", "5.6.7.8", 1234, 80),
            true,
        );
    }

    #[test]
    fn tcp_dnat_agrees_with_a_recompute() {
        agrees_with_recompute(
            build_test_tcp_ipv4_packet("1.2.3.4", "5.6.7.8", 1234, 80),
            false,
        );
    }

    /// `ICMPv4` has no pseudo-header, so translating the address must leave its checksum *alone*.
    ///
    /// The interesting assertion is the negative one: an implementation that folded the address
    /// delta into an `ICMPv4` checksum would corrupt every forwarded ICMP error, and it would look
    /// exactly like working code until something downstream dropped the packet.
    #[test]
    fn icmp4_address_translation_does_not_move_the_checksum() {
        let mut packet: Packet<TestBuffer> =
            build_test_ipv4_packet_with_transport(64, Some(NextHeader::ICMP)).unwrap();
        packet.update_checksums();
        let before = transport_checksum(&packet);

        let new_ip = UnicastIpAddr::try_from(IpAddr::from([9, 9, 9, 9])).unwrap();
        snat_packet(&mut packet, new_ip, NonZero::new(4321).unwrap()).expect("snat_packet");

        assert_eq!(
            transport_checksum(&packet),
            before,
            "an ICMPv4 checksum moved when only the IP address changed; ICMPv4 has no \
             pseudo-header, so the address is not covered"
        );
        // And it still agrees with a recompute, i.e. it was right to leave it alone.
        packet.update_checksums();
        assert_eq!(transport_checksum(&packet), before);
    }

    /// `ICMPv6` *does* have a pseudo-header, so the same translation must move its checksum.
    #[test]
    fn icmp6_address_translation_does_move_the_checksum() {
        let mut packet: Packet<TestBuffer> =
            build_test_ipv6_packet_with_transport(64, Some(NextHeader::ICMP6)).unwrap();
        packet.update_checksums();
        let before = transport_checksum(&packet);

        let new_ip = UnicastIpAddr::try_from(IpAddr::from([
            0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
        ]))
        .unwrap();
        snat_packet(&mut packet, new_ip, NonZero::new(4321).unwrap()).expect("snat_packet");

        let incremental = transport_checksum(&packet);
        assert_ne!(
            incremental, before,
            "an ICMPv6 checksum did not move when the address changed; ICMPv6 has a \
             pseudo-header, so the address is covered"
        );
        packet.update_checksums();
        assert_eq!(
            incremental,
            transport_checksum(&packet),
            "the incremental ICMPv6 checksum disagrees with a full recompute"
        );
    }
}
