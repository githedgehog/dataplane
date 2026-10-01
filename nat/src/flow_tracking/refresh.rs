// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Status and lifetime updates for tracked flows.

use super::TrackedState;
use crate::common::NatFlowStatus;
use concurrency::sync::Weak;
use net::buffer::PacketBufferMut;
use net::flows::FlowInfo;
use net::packet::Packet;
use std::time::Duration;
use tracing::debug;

/// Update the status of a tracked pair of flows, after a packet hit `flow`, which holds `state`.
///
/// If the connection is over, invalidate the pair. Otherwise, reset the expiry of both halves of
/// the pair to the duration that `timeout` returns for the new status, if any.
///
/// Return the new status.
pub(crate) fn advance_flow<Buf: PacketBufferMut, S: TrackedState>(
    packet: &Packet<Buf>,
    flow: &FlowInfo,
    state: &S,
    timeout: impl FnOnce(NatFlowStatus) -> Option<Duration>,
) -> NatFlowStatus {
    let current = state.status().load();
    let next = state.next_status(packet, current);
    if next != current {
        debug!(
            "Status of flow {} changed: {current} -> {next}",
            flow.flowkey()
        );
        state.status().store(next);
    }

    if next.is_terminal() {
        flow.invalidate_pair();
    } else if let Some(duration) = timeout(next) {
        reset_pair_expiry(flow, duration);
    }
    next
}

fn reset_pair_expiry(flow: &FlowInfo, duration: Duration) {
    // An error means the expiry was already later, which is fine.
    let _ = flow.reset_expiry_unchecked(duration);
    if let Some(related) = flow.related.as_ref().and_then(Weak::upgrade) {
        let _ = related.reset_expiry_unchecked(duration);
    }
}
