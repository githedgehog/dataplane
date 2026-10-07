// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Status and lifetime updates for tracked flows.

use super::{ConnState, FlowSide, next_status};
use crate::buffer::PacketBufferMut;
use crate::flows::FlowInfo;
use crate::packet::Packet;
use concurrency::sync::Weak;
use std::time::Duration;
use tracing::debug;

/// Update the connection status shared by a tracked pair of flows, after a packet hit `flow`.
///
/// If the connection is over, invalidate the pair. Otherwise, reset the expiry of both halves of
/// the pair to the duration that `timeout` returns for the new status, if any.
///
/// Return the new status, or `None` if `flow` is not part of a pair and tracks no connection.
pub fn advance_flow<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
    flow: &FlowInfo,
    timeout: impl FnOnce(ConnState) -> Option<Duration>,
) -> Option<ConnState> {
    let Some(status) = flow.conn_state() else {
        debug!("Flow {} tracks no connection", flow.flowkey());
        return None;
    };
    let current = status.load();
    let next = next_status(packet, FlowSide::from(flow.get_flags()), current);
    if next != current {
        debug!(
            "Status of flow {} changed: {current} -> {next}",
            flow.flowkey()
        );
        status.store(next);
    }

    if next.is_terminal() {
        flow.invalidate_pair();
    } else if let Some(duration) = timeout(next) {
        reset_pair_expiry(flow, duration);
    }
    Some(next)
}

fn reset_pair_expiry(flow: &FlowInfo, duration: Duration) {
    // An error means the expiry was already later, which is fine.
    let _ = flow.reset_expiry_unchecked(duration);
    if let Some(related) = flow.related.as_ref().and_then(Weak::upgrade) {
        let _ = related.reset_expiry_unchecked(duration);
    }
}
