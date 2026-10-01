// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow status updates for masquerading. We currently use these to know how much to extend the
//! lifetime of flows for port conservation.

use crate::common::{NatAction, NatFlowStatus};
use crate::flow_tracking::{self, FlowSide};
use net::buffer::PacketBufferMut;
use net::packet::Packet;

/// The side of the connection that sent a packet, given the action of the flow it hit: the
/// initiator's packets are source-NATed.
pub(crate) fn flow_side(action: NatAction) -> FlowSide {
    match action {
        NatAction::SrcNat => FlowSide::Initiator,
        NatAction::DstNat => FlowSide::Responder,
    }
}

// Compute the next `NatFlowStatus` of a flow, given the current, the received packet and
// the direction
pub(crate) fn next_flow_status<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
    action: NatAction,     // action of the flow hit
    status: NatFlowStatus, // current status
) -> NatFlowStatus {
    let side = flow_side(action);
    let next = flow_tracking::next_status(packet, side, status);
    flow_tracking::close_dns_on_reply(packet, side, next)
}
