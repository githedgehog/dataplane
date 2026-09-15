// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet mangling routines specific to masquerade

use crate::NatPort;
use crate::common::NatAction;
use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{NetError, Transport, TransportError, TryHeadersMut};
use net::icmp4::Icmp4Error;
use net::icmp6::Icmp6Error;
use net::ip::UnicastIpAddr;
use net::packet::Packet;
use std::net::IpAddr;

use tracing::debug;

#[derive(Debug, thiserror::Error)]
pub(crate) enum NatPacketError {
    #[error("Failed to update ip header")]
    UpdateNet(#[from] NetError),
    #[error("Failed to update transport header")]
    UpdateTransport(#[from] TransportError),
    #[error("Failed to update `ICMPv4` header")]
    UpdateIcmpv4(#[from] Icmp4Error),
    #[error("Failed to update `ICMPv6` header")]
    UpdateIcmpv6(#[from] Icmp6Error),
    #[error("Failed to NAT packet: unsupported traffic")]
    UnsupportedTraffic,
}

fn snat<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_src: UnicastIpAddr,
    natport: NatPort,
) -> Result<(), NatPacketError> {
    let mut modified = false;
    // Set only where an incremental update is not possible (an ICMP path that carries no usable
    // old value, or an IP version change). `ipforward` then does the full payload recompute; the
    // ordinary case skips it entirely.
    let mut needs_full_recompute = false;
    match packet
        .headers_mut()
        .pat_mut()
        .eth()
        .net()
        .transport()
        .done()
    {
        Some((_, ip, tp)) if matches!(tp, Transport::Udp(_) | Transport::Tcp(_)) => {
            // Both fields are covered by the TCP/UDP pseudo-header, so each change is folded into
            // the transport checksum incrementally (RFC 1624) rather than by re-summing the
            // payload. The old value has to be read *before* the set, which is the only reason
            // these are bound rather than compared inline.
            let old_addr = ip.src_addr();
            if old_addr != new_src.inner() {
                ip.try_set_source(new_src)?;
                if tp.increment_checksum_for_address(old_addr, new_src.inner()) {
                    modified = true;
                } else {
                    // An IP version change is not an incremental update; fall back.
                    needs_full_recompute = true;
                    modified = true;
                }
            }
            if let NatPort::Port(port) = natport {
                let old_port = tp.src_port();
                tp.try_set_source(port)?;
                if let Some(old_port) = old_port {
                    tp.increment_checksum_for_u16(old_port.get(), port.get());
                } else {
                    needs_full_recompute = true;
                }
                modified = true;
            }
        }
        Some((_, Net::Ipv6(_), Transport::Icmp4(_)) | (_, Net::Ipv4(_), Transport::Icmp6(_))) => {
            return Err(NatPacketError::UnsupportedTraffic);
        }
        // Matched on the `Transport` rather than destructured into the inner `Icmp4`/`Icmp6`, so
        // the checksum helpers -- which know that `ICMPv4` has no pseudo-header and `ICMPv6` does --
        // stay reachable. Destructuring hands out an `&mut Icmp4`, which cannot answer that
        // question, and that is precisely how the two get confused.
        Some((_, ip, tp)) if matches!(tp, Transport::Icmp4(_) | Transport::Icmp6(_)) => {
            let old_addr = ip.src_addr();
            if old_addr != new_src.inner() {
                ip.try_set_source(new_src)?;
                // A no-op for `ICMPv4` (the address is not covered) and a real delta for `ICMPv6`.
                if !tp.increment_checksum_for_address(old_addr, new_src.inner()) {
                    needs_full_recompute = true;
                }
                modified = true;
            }
            if let NatPort::Identifier(id) = natport
                && let Some(current) = tp.identifier()
                && current != id
            {
                tp.try_set_identifier(id)?;
                // The identifier lives inside the ICMP header, which the ICMP checksum covers --
                // for both versions.
                tp.increment_checksum_for_u16(current, id);
                modified = true;
            }
        }
        _ => return Err(NatPacketError::UnsupportedTraffic),
    }
    if modified {
        packet.meta_mut().src_natted(true);
        packet.meta_mut().set_checksum_refresh(needs_full_recompute);
    }
    Ok(())
}

fn dnat<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_dst_ip: IpAddr,
    natport: NatPort,
) -> Result<(), NatPacketError> {
    let mut modified = false;
    // See `snat`: set only where an incremental update is impossible, so the ordinary case skips
    // the full payload recompute in `ipforward`.
    let mut needs_full_recompute = false;

    match packet
        .headers_mut()
        .pat_mut()
        .eth()
        .net()
        .transport()
        .done()
    {
        // ipv4|ipv6 + UDP/TCP
        Some((_, ip, tp)) if matches!(tp, Transport::Udp(_) | Transport::Tcp(_)) => {
            let old_addr = ip.dst_addr();
            if old_addr != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                if !tp.increment_checksum_for_address(old_addr, new_dst_ip) {
                    // An IP version change is not an incremental update; fall back.
                    needs_full_recompute = true;
                }
                modified = true;
            }
            if let NatPort::Port(port) = natport {
                let old_port = tp.dst_port();
                tp.try_set_destination(port)?;
                if let Some(old_port) = old_port {
                    tp.increment_checksum_for_u16(old_port.get(), port.get());
                } else {
                    needs_full_recompute = true;
                }
                modified = true;
            }
        }
        Some((_, Net::Ipv6(_), Transport::Icmp4(_)) | (_, Net::Ipv4(_), Transport::Icmp6(_))) => {
            return Err(NatPacketError::UnsupportedTraffic);
        }

        // `ICMPv4` and `ICMPv6`. Matched on the `Transport` rather than destructured, so the checksum
        // helpers can apply the rule that differs between them: `ICMPv4` has no pseudo-header and so
        // is untouched by an address change, `ICMPv6` has one and is not.
        Some((_, ip, tp)) if matches!(tp, Transport::Icmp4(_) | Transport::Icmp6(_)) => {
            let old_addr = ip.dst_addr();
            if old_addr != new_dst_ip {
                ip.try_set_destination(new_dst_ip)?;
                if !tp.increment_checksum_for_address(old_addr, new_dst_ip) {
                    needs_full_recompute = true;
                }
                modified = true;
            }
            if let NatPort::Identifier(id) = natport
                && let Some(current) = tp.identifier()
                && current != id
            {
                tp.try_set_identifier(id)?;
                // The identifier is inside the ICMP header, which the checksum covers, for both
                // versions.
                tp.increment_checksum_for_u16(current, id);
                modified = true;
            }
        }
        _ => return Err(NatPacketError::UnsupportedTraffic),
    }

    if modified {
        packet.meta_mut().dst_natted(true);
        packet.meta_mut().set_checksum_refresh(needs_full_recompute);
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct NatTranslate {
    pub action: NatAction,
    pub use_ip: UnicastIpAddr,
    pub nat_port: NatPort,
}

impl std::fmt::Display for NatTranslate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "action: {} with {}:{}",
            self.action, self.use_ip, self.nat_port
        )
    }
}

pub(super) fn masquerade<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    xlate: &NatTranslate,
) -> Result<(), NatPacketError> {
    debug!("Natting packet using {xlate} (masquerading flow)");
    match xlate.action {
        NatAction::SrcNat => snat(packet, xlate.use_ip, xlate.nat_port),
        NatAction::DstNat => dnat(packet, xlate.use_ip.inner(), xlate.nat_port),
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
    use net::packet::test_utils::build_test_tcp_ipv4_packet;
    use std::num::NonZero;

    /// Same requirement, for the ICMP paths.
    ///
    /// Separate from the TCP case because the rules differ and getting them confused is exactly how
    /// this breaks: an **`ICMPv4`** checksum does not cover the address (no pseudo-header) but *does*
    /// cover the identifier, while an **`ICMPv6`** checksum covers both. A conversion that handles
    /// only TCP/UDP leaves these arms mutating the packet with no checksum update at all -- which
    /// is worse than the full recompute it replaced, and invisible until something far away drops
    /// the packet.
    fn icmp_translation_agrees_with_a_recompute(next_header: NextHeader, ipv6: bool, source: bool) {
        use net::packet::test_utils::{
            build_test_ipv4_packet_with_transport, build_test_ipv6_packet_with_transport,
        };

        let mut packet: Packet<TestBuffer> = if ipv6 {
            build_test_ipv6_packet_with_transport(64, Some(next_header)).unwrap()
        } else {
            build_test_ipv4_packet_with_transport(64, Some(next_header)).unwrap()
        };
        packet.update_checksums();

        let new_src = if ipv6 {
            UnicastIpAddr::try_from(IpAddr::from([
                0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
            ]))
            .unwrap()
        } else {
            UnicastIpAddr::try_from(IpAddr::from([9, 9, 9, 9])).unwrap()
        };
        if source {
            snat(&mut packet, new_src, NatPort::Identifier(4321)).expect("snat");
        } else {
            dnat(&mut packet, new_src.inner(), NatPort::Identifier(4321)).expect("dnat");
        }

        let before = icmp_checksum(&packet);
        if packet.meta().checksum_refresh() {
            // Falling back is allowed; it is silently doing neither that is not.
            return;
        }
        packet.update_checksums();
        assert_eq!(
            before,
            icmp_checksum(&packet),
            "after an ICMP translation the checksum disagrees with a full recompute, and \
             checksum_refresh was not set either -- so nothing would ever fix it"
        );
    }

    fn icmp_checksum(packet: &Packet<TestBuffer>) -> Option<u16> {
        packet.headers().try_transport().and_then(|tp| match tp {
            Transport::Icmp4(icmp) => icmp.checksum().map(u16::from),
            Transport::Icmp6(icmp) => icmp.checksum().map(u16::from),
            _ => None,
        })
    }

    #[test]
    fn icmp4_snat_agrees_with_a_recompute() {
        icmp_translation_agrees_with_a_recompute(NextHeader::ICMP, false, true);
    }

    #[test]
    fn icmp6_snat_agrees_with_a_recompute() {
        icmp_translation_agrees_with_a_recompute(NextHeader::ICMP6, true, true);
    }

    #[test]
    fn icmp4_dnat_agrees_with_a_recompute() {
        icmp_translation_agrees_with_a_recompute(NextHeader::ICMP, false, false);
    }

    #[test]
    fn icmp6_dnat_agrees_with_a_recompute() {
        icmp_translation_agrees_with_a_recompute(NextHeader::ICMP6, true, false);
    }

    /// The destination-translation counterpart of
    /// [`snat_leaves_a_checksum_a_full_recompute_would_agree_with`]. Return traffic goes through
    /// `dnat`, so leaving it on the full recompute would have halved the benefit and hidden any
    /// mistake behind the direction that was tested.
    #[test]
    fn dnat_leaves_a_checksum_a_full_recompute_would_agree_with() {
        let mut packet: Packet<TestBuffer> =
            build_test_tcp_ipv4_packet("1.2.3.4", "5.6.7.8", 1234, 80);
        packet.update_checksums();

        let new_dst = IpAddr::from([9, 9, 9, 9]);
        dnat(
            &mut packet,
            new_dst,
            NatPort::Port(NonZero::new(4321).unwrap()),
        )
        .expect("dnat");

        assert!(
            !packet.meta().checksum_refresh(),
            "dnat asked for a full payload recompute; the incremental path was not taken"
        );

        let checksum_of = |p: &Packet<TestBuffer>| {
            p.headers().try_transport().map(|tp| match tp {
                Transport::Tcp(tcp) => tcp.checksum().map(u16::from),
                Transport::Udp(udp) => udp.checksum().map(u16::from),
                _ => None,
            })
        };
        let incremental = checksum_of(&packet).expect("a transport header");
        packet.update_checksums();
        assert_eq!(
            incremental,
            checksum_of(&packet).expect("a transport header"),
            "the incremental checksum after dnat disagrees with a full recompute"
        );
    }

    /// After a source translation, the transport checksum must equal what a full recompute gives.
    ///
    /// This is the test that makes the incremental path trustworthy, and it did not exist before:
    /// **no NAT test validated a checksum at all** (only the ICMP handler did), so the whole suite
    /// would have passed just as happily with the arithmetic wrong. A bad checksum is not rejected
    /// here -- it is rejected several hops away, by someone else, long after the fact.
    #[test]
    fn snat_leaves_a_checksum_a_full_recompute_would_agree_with() {
        let mut packet: Packet<TestBuffer> =
            build_test_tcp_ipv4_packet("1.2.3.4", "5.6.7.8", 1234, 80);
        // Start from a packet whose checksum is right, or the comparison proves nothing.
        packet.update_checksums();

        let new_src = UnicastIpAddr::try_from(IpAddr::from([9, 9, 9, 9])).unwrap();
        let new_port = NatPort::Port(NonZero::new(4321).unwrap());
        snat(&mut packet, new_src, new_port).expect("snat");

        // The whole point: the ordinary path must not ask for a full recompute.
        assert!(
            !packet.meta().checksum_refresh(),
            "snat asked for a full payload recompute; the incremental path was not taken"
        );

        let checksum_of = |p: &Packet<TestBuffer>| {
            p.headers().try_transport().map(|tp| match tp {
                Transport::Tcp(tcp) => tcp.checksum().map(u16::from),
                Transport::Udp(udp) => udp.checksum().map(u16::from),
                _ => None,
            })
        };
        let incremental = checksum_of(&packet).expect("a transport header");

        // Force the full recompute over the same, already-translated packet and compare. Done in
        // place rather than on a copy because `Packet` deliberately has no `Clone`.
        packet.update_checksums();
        let expected = checksum_of(&packet).expect("a transport header");

        assert_eq!(
            incremental, expected,
            "the incremental checksum after snat disagrees with a full recompute"
        );
    }
}
