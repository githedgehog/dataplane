// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Functions to represent tiny state machines for flows in the context
//! of port forwarding. These models are very simple and aim at helping to
//! determine how much the lifetime of flows should be extended based on
//! the activity. This module is only for port-forwarding.

use net::buffer::PacketBufferMut;
use net::headers::TryTcp;
use net::packet::Packet;
use net::tcp::Tcp;

use super::PortFwState;
use crate::common::{NatAction, NatFlowStatus};

fn next_flow_status_tcp(pfw_state: &PortFwState, tcp: &Tcp) -> NatFlowStatus {
    let status = pfw_state.status.load();
    match pfw_state.action {
        NatAction::DstNat => match status {
            NatFlowStatus::TwoWay if !tcp.syn() && tcp.ack() => NatFlowStatus::Established,
            NatFlowStatus::Established if tcp.fin() => NatFlowStatus::CClosing,
            NatFlowStatus::SClosing if !tcp.fin() && tcp.ack() => NatFlowStatus::SHalfClose,
            NatFlowStatus::SClosing if tcp.fin() && tcp.ack() => NatFlowStatus::LastAck,
            NatFlowStatus::SHalfClose if tcp.fin() => NatFlowStatus::LastAck,
            NatFlowStatus::LastAck if tcp.ack() => NatFlowStatus::Closed,
            _other if tcp.rst() => NatFlowStatus::Reset,
            other => other,
        },
        NatAction::SrcNat => match status {
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
fn next_flow_status_non_tcp(pfw_state: &PortFwState) -> NatFlowStatus {
    let status = pfw_state.status.load();
    match pfw_state.action {
        NatAction::DstNat => match status {
            NatFlowStatus::TwoWay => NatFlowStatus::Established,
            other => other,
        },
        NatAction::SrcNat => match status {
            NatFlowStatus::OneWay => NatFlowStatus::TwoWay,
            other => other,
        },
    }
}

/// Compute the next `NatFlowStatus` of a flow, given the current, the received packet and
/// the direction, which is implicit in `PortFwState::action` (`NatAction`):
///     `DstNat` is the forward path and
///     `SrcNat` the reverse path.
pub(crate) fn next_flow_status<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    pfw_state: &PortFwState,
) -> NatFlowStatus {
    if let Some(tcp) = packet.try_tcp() {
        next_flow_status_tcp(pfw_state, tcp)
    } else {
        next_flow_status_non_tcp(pfw_state)
    }
}
