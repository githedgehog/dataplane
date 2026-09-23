// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet mangling routines specific to masquerade

use crate::NatPort;
use crate::common::NatAction;
use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{NetError, Transport, TransportError, TryHeaders, TryHeadersMut};
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
    // Request a full recomputation when a checksum delta cannot be applied, including to an IPv6
    // UDP checksum of zero.
    let mut needs_full_recompute = packet.headers().has_zero_ipv6_udp_checksum();
    match packet
        .headers_mut()
        .pat_mut()
        .eth()
        .net()
        .transport()
        .done()
    {
        Some((_, ip, tp)) if matches!(tp, Transport::Udp(_) | Transport::Tcp(_)) => {
            if ip.src_addr() != new_src.inner() {
                ip.try_set_source_updating_checksum(new_src, Some(tp))?;
                modified = true;
            }
            if let NatPort::Port(port) = natport {
                // Capture the old value before applying its checksum delta.
                let old_port = tp.src_port();
                tp.try_set_source(port)?;
                if let Some(old_port) = old_port {
                    if !tp.increment_checksum_for_u16(old_port.get(), port.get()) {
                        needs_full_recompute = true;
                    }
                } else {
                    needs_full_recompute = true;
                }
                modified = true;
            }
        }
        Some((_, Net::Ipv6(_), Transport::Icmp4(_)) | (_, Net::Ipv4(_), Transport::Icmp6(_))) => {
            return Err(NatPacketError::UnsupportedTraffic);
        }
        // Keep `Transport` to apply the checksum rules for each ICMP version.
        Some((_, ip, tp)) if matches!(tp, Transport::Icmp4(_) | Transport::Icmp6(_)) => {
            if ip.src_addr() != new_src.inner() {
                // Only ICMPv6 includes the address in its checksum.
                ip.try_set_source_updating_checksum(new_src, Some(tp))?;
                modified = true;
            }
            if let NatPort::Identifier(id) = natport
                && let Some(current) = tp.identifier()
                && current != id
            {
                tp.try_set_identifier(id)?;
                if !tp.increment_checksum_for_u16(current, id) {
                    // ICMPv4 zero results require full recomputation.
                    needs_full_recompute = true;
                }
                modified = true;
            }
        }
        _ => return Err(NatPacketError::UnsupportedTraffic),
    }
    if modified {
        packet.meta_mut().src_natted(true);
        if needs_full_recompute {
            // Preserve refresh requests from earlier stages.
            packet.meta_mut().set_checksum_refresh(true);
        }
    }
    Ok(())
}

fn dnat<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    new_dst_ip: IpAddr,
    natport: NatPort,
) -> Result<(), NatPacketError> {
    let mut modified = false;
    let mut needs_full_recompute = packet.headers().has_zero_ipv6_udp_checksum();

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
            if ip.dst_addr() != new_dst_ip {
                ip.try_set_destination_updating_checksum(new_dst_ip, Some(tp))?;
                modified = true;
            }
            if let NatPort::Port(port) = natport {
                let old_port = tp.dst_port();
                tp.try_set_destination(port)?;
                if let Some(old_port) = old_port {
                    if !tp.increment_checksum_for_u16(old_port.get(), port.get()) {
                        needs_full_recompute = true;
                    }
                } else {
                    needs_full_recompute = true;
                }
                modified = true;
            }
        }
        Some((_, Net::Ipv6(_), Transport::Icmp4(_)) | (_, Net::Ipv4(_), Transport::Icmp6(_))) => {
            return Err(NatPacketError::UnsupportedTraffic);
        }

        // Keep `Transport` to apply the checksum rules for each ICMP version.
        Some((_, ip, tp)) if matches!(tp, Transport::Icmp4(_) | Transport::Icmp6(_)) => {
            if ip.dst_addr() != new_dst_ip {
                ip.try_set_destination_updating_checksum(new_dst_ip, Some(tp))?;
                modified = true;
            }
            if let NatPort::Identifier(id) = natport
                && let Some(current) = tp.identifier()
                && current != id
            {
                tp.try_set_identifier(id)?;
                if !tp.increment_checksum_for_u16(current, id) {
                    // ICMPv4 zero results require full recomputation.
                    needs_full_recompute = true;
                }
                modified = true;
            }
        }
        _ => return Err(NatPacketError::UnsupportedTraffic),
    }

    if modified {
        packet.meta_mut().dst_natted(true);
        if needs_full_recompute {
            // Preserve refresh requests from earlier stages.
            packet.meta_mut().set_checksum_refresh(true);
        }
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

    /// Check address and identifier updates for both ICMP versions.
    /// Only `ICMPv6` includes addresses in its checksum.
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
            // ICMPv4 zero results may require full recomputation.
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

    /// An IPv6 UDP checksum of zero cannot take a delta, so translation must request a recompute.
    #[test]
    fn a_zero_ipv6_udp_checksum_asks_for_a_recompute() {
        use net::headers::TryTransportMut;
        use net::packet::test_utils::build_test_ipv6_packet_with_transport;

        for source in [true, false] {
            let mut packet: Packet<TestBuffer> =
                build_test_ipv6_packet_with_transport(64, Some(NextHeader::UDP)).unwrap();
            match packet.headers_mut().try_transport_mut() {
                Some(Transport::Udp(udp)) => {
                    udp.set_checksum(net::udp::UdpChecksum::new(0)).unwrap();
                }
                _ => unreachable!(),
            }
            let new = UnicastIpAddr::try_from(IpAddr::from([
                0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
            ]))
            .unwrap();
            let port = NatPort::Port(NonZero::new(4321).unwrap());
            if source {
                snat(&mut packet, new, port).expect("snat");
            } else {
                dnat(&mut packet, new.inner(), port).expect("dnat");
            }
            assert!(
                packet.meta().checksum_refresh(),
                "a zero IPv6 UDP checksum was translated without requesting a recompute"
            );
        }
    }

    /// Check that destination NAT updates the checksum without requesting recomputation.
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

    /// Check that source NAT updates the checksum without requesting recomputation.
    #[test]
    fn snat_leaves_a_checksum_a_full_recompute_would_agree_with() {
        let mut packet: Packet<TestBuffer> =
            build_test_tcp_ipv4_packet("1.2.3.4", "5.6.7.8", 1234, 80);
        // Incremental updates require a valid starting checksum.
        packet.update_checksums();

        let new_src = UnicastIpAddr::try_from(IpAddr::from([9, 9, 9, 9])).unwrap();
        let new_port = NatPort::Port(NonZero::new(4321).unwrap());
        snat(&mut packet, new_src, new_port).expect("snat");

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

        // Compare with a full recomputation of the translated packet.
        packet.update_checksums();
        let expected = checksum_of(&packet).expect("a transport header");

        assert_eq!(
            incremental, expected,
            "the incremental checksum after snat disagrees with a full recompute"
        );
    }
}
