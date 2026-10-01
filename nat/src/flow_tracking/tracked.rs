// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State kept in tracked flows.

use super::{FlowSide, next_status};
use crate::common::{AtomicNatFlowStatus, NatFlowStatus};
use net::buffer::PacketBufferMut;
use net::packet::Packet;

/// State that a mode keeps in each half of a tracked pair of flows. Both halves of a pair share
/// the same status.
pub(crate) trait TrackedState {
    /// The status shared by both halves of the pair.
    fn status(&self) -> &AtomicNatFlowStatus;

    /// The side of the connection that sends the packets hitting this half of the pair.
    fn side(&self) -> FlowSide;

    /// Compute the next status of the pair, after a packet hit this half.
    fn next_status<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
        status: NatFlowStatus,
    ) -> NatFlowStatus {
        next_status(packet, self.side(), status)
    }
}
