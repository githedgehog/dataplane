// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State kept in tracked flows.

use super::{FlowSide, next_status};
use crate::common::{AtomicNatFlowStatus, NatFlowStatus};
use net::buffer::PacketBufferMut;
use net::flows::{FlowInfoItem, FlowInfoLocked};
use net::packet::Packet;

/// State that a mode keeps in each half of a tracked pair of flows. Both halves of a pair share
/// the same status.
pub(crate) trait TrackedState: FlowInfoItem + Sized {
    /// The content of the field of a flow that holds this state.
    fn slot(locked: &FlowInfoLocked) -> Option<&dyn FlowInfoItem>;

    /// The field of a flow that holds this state, mutable.
    fn slot_mut(locked: &mut FlowInfoLocked) -> &mut Option<Box<dyn FlowInfoItem>>;

    /// The state of this type held by a flow, if any.
    fn of(locked: &FlowInfoLocked) -> Option<&Self> {
        Self::slot(locked)?.downcast_ref::<Self>()
    }

    /// The status shared by both halves of the pair.
    fn status(&self) -> &AtomicNatFlowStatus;

    /// The side of the connection that sends the packets hitting this half of the pair.
    fn side(&self) -> FlowSide;

    /// Whether UDP flows close on the first reply from a DNS server.
    const CLOSE_DNS_ON_REPLY: bool = false;

    /// Compute the next status of the pair, after a packet hit this half.
    fn next_status<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
        status: NatFlowStatus,
    ) -> NatFlowStatus {
        next_status(packet, self.side(), status, Self::CLOSE_DNS_ON_REPLY)
    }
}
