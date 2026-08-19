// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Functions to represent tiny state machines for flows in the context
//! of masquerading. We currently use these to know how much to extend the lifetime of flows
//! for port conservation.

use crate::common::{NatAction, NatFlowStatus};
use crate::masquerade::contract::rfc4787::Req12;
use net::buffer::PacketBufferMut;
use net::headers::{TryHeaders, TryIp, TryTcp};

use net::ip::NextHeader;
use net::packet::Packet;
use net::tcp::Tcp;

impl NatFlowStatus {
    //= https://www.rfc-editor.org/rfc/rfc4787#section-4.3
    //# a) For specific destination ports in the well-known port range
    //# (ports 0-1023), a NAT MAY have shorter UDP mapping timers that
    //# are specific to the IANA-registered application running over
    //# that specific destination port.
    //
    // This is the exemption REQ-5a describes, and it is the only port-specific timer we have. The
    // match is on the reply's *source* port, which is the destination port of the session that
    // asked -- the thing REQ-5a is written about.
    //
    // Two of the three ports qualify. 53 and 853 are inside the well-known range and are the
    // IANA registrations for DNS and DNS-over-TLS. 8853 is not: it is above 1023, so REQ-5a does
    // not reach it and closing that flow immediately is a plain deviation from REQ-5 rather than a
    // permitted optimisation. It is a small one -- the flow is a resolver exchange either way --
    // but it is not covered by the exemption the other two sit under.
    fn udp_status_patch_dnat<Buf: PacketBufferMut>(self, packet: &Packet<Buf>) -> NatFlowStatus {
        match packet.headers().pat().eth().net().udp().done() {
            Some((_, _, udp)) => match udp.source().as_u16() {
                53 | 853 | 8853 => NatFlowStatus::Closed, // DNS|DNS-over-quic|nextdns
                _ => self,
            },
            _ => self,
        }
    }

    // Refine the status of a UDP flow based on the application
    fn udp_status_patch<Buf: PacketBufferMut>(
        self,
        packet: &Packet<Buf>,
        action: NatAction,
    ) -> NatFlowStatus {
        match action {
            NatAction::SrcNat => self,
            NatAction::DstNat => self.udp_status_patch_dnat(packet),
        }
    }
}

fn next_flow_status_udp(action: NatAction, status: NatFlowStatus) -> NatFlowStatus {
    match action {
        NatAction::SrcNat => match status {
            NatFlowStatus::TwoWay => NatFlowStatus::Established,
            _ => status,
        },
        NatAction::DstNat => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            _ => status,
        },
    }
}

//= https://www.rfc-editor.org/rfc/rfc5382#section-8
//= type=implementation
//# REQ-10:  Receipt of any sort of ICMP message MUST NOT terminate the
//# NAT mapping or TCP connection for which the ICMP was generated.
//
//= https://www.rfc-editor.org/rfc/rfc4787#section-9
//= type=implementation
//# REQ-12:  Receipt of any sort of ICMP message MUST NOT terminate the
//# NAT mapping.
//
// Held by construction: no arm below yields `Closed` or `Reset`. The `debug_assert!` is what keeps
// it that way, and it is the same predicate the test cited `type=test` calls -- see
// `contract::rfc4787::Req12`.
#[allow(clippy::match_single_binding)]
fn next_flow_status_icmp(action: NatAction, status: NatFlowStatus) -> NatFlowStatus {
    let next = match action {
        NatAction::SrcNat => match status {
            _ => status,
        },
        NatAction::DstNat => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            _ => status,
        },
    };
    debug_assert!(
        Req12::new(status, next).check().is_ok(),
        "{action} {status:?} -> {next:?}"
    );
    next
}

fn next_flow_status_tcp(action: NatAction, status: NatFlowStatus, tcp: &Tcp) -> NatFlowStatus {
    match action {
        NatAction::SrcNat => match status {
            NatFlowStatus::TwoWay if !tcp.syn() && tcp.ack() => NatFlowStatus::Established,
            NatFlowStatus::Established if tcp.fin() => NatFlowStatus::CClosing,
            NatFlowStatus::SClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::SHalfClose,
            NatFlowStatus::SClosing if tcp.fin() && tcp.ack() => NatFlowStatus::LastAck,
            NatFlowStatus::SHalfClose if tcp.fin() => NatFlowStatus::LastAck,
            NatFlowStatus::LastAck if tcp.ack() => NatFlowStatus::Closed,
            _other if tcp.rst() => NatFlowStatus::Reset,
            other => other,
        },
        NatAction::DstNat => match status {
            NatFlowStatus::OneWay if tcp.syn() && tcp.ack() => NatFlowStatus::TwoWay,
            NatFlowStatus::Established if tcp.fin() => NatFlowStatus::SClosing,
            NatFlowStatus::CClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::CHalfClose,
            NatFlowStatus::CClosing if tcp.fin() && tcp.ack() => NatFlowStatus::LastAck,
            NatFlowStatus::CHalfClose if tcp.fin() => NatFlowStatus::LastAck,
            NatFlowStatus::LastAck if tcp.ack() => NatFlowStatus::Closed,
            _other if tcp.rst() => NatFlowStatus::Reset,
            other => other,
        },
    }
}

// Compute the next `NatFlowStatus` of a flow, given the current, the received packet and
// the direction
pub(crate) fn next_flow_status<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
    action: NatAction,     // action of the flow hit
    status: NatFlowStatus, // current status
) -> NatFlowStatus {
    let proto = packet
        .try_ip()
        .unwrap_or_else(|| unreachable!()) // packet without IP hdr should not make it here
        .next_header();

    // match on next-header, instead of relying on headers, as those may not be present w/ fragmentation
    match proto {
        NextHeader::UDP => next_flow_status_udp(action, status).udp_status_patch(packet, action),
        NextHeader::ICMP | NextHeader::ICMP6 => next_flow_status_icmp(action, status),
        NextHeader::TCP => {
            if let Some(tcp) = packet.try_tcp() {
                next_flow_status_tcp(action, status, tcp)
            } else {
                status
            }
        }
        _ => status,
    }
}
