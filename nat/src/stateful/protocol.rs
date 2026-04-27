// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Functions to represent tiny state machines for flows in the context
//! of masquerading. We currently use these to know how much to extend the lifetime of flows
//! for port conservation.

use crate::common::{NatAction, NatFlowStatus};
use net::buffer::PacketBufferMut;
use net::headers::{TryHeaders, TryIp, TryTcp};

use net::ip::NextHeader;
use net::packet::Packet;
use net::tcp::Tcp;

impl NatFlowStatus {
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

#[allow(clippy::match_single_binding)]
fn next_flow_status_icmp(action: NatAction, status: NatFlowStatus) -> NatFlowStatus {
    match action {
        NatAction::SrcNat => match status {
            _ => status,
        },
        NatAction::DstNat => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            _ => status,
        },
    }
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
            NatFlowStatus::CClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::CHalfClose,
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
