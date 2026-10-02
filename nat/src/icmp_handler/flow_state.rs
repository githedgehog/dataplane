// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Translation of ICMP errors for tracked flows.

use crate::NatTranslationData;
use crate::common::NatFlowStatus;
use crate::flow_tracking::TrackedState;
use crate::icmp_handler::icmp_error_msg::nat_translate_icmp_inner;
use net::buffer::PacketBufferMut;
use net::flows::FlowInfo;
use net::packet::{DoneReason, Packet};
use std::fmt::Display;
use tracing::debug;

/// State of a tracked flow that can translate the ICMP errors for this flow.
pub(crate) trait IcmpErrorTranslation: TrackedState {
    /// Name of the mode, for logs.
    const MODE: &'static str;

    type Error: Display;

    /// The translation for the packet quoted in an ICMP error.
    fn quoted_translation(&self) -> NatTranslationData;

    /// Translate the ICMP error packet itself.
    fn translate<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) -> Result<(), Self::Error>;
}

/// Translate an ICMP error packet, and the packet it quotes, with the state of type `S` in
/// `flow_info`. Return the status of the flow.
pub(crate) fn translate_icmp_error<Buf: PacketBufferMut, S: IcmpErrorTranslation>(
    packet: &mut Packet<Buf>,
    flow_info: &FlowInfo,
) -> Result<NatFlowStatus, DoneReason> {
    let mode = S::MODE;
    let f = flow_info.logfmt();
    if let Some(src_vpcd) = packet.meta().src_vpcd {
        debug!("({mode}): Processing ICMP error message from {src_vpcd} with flow {f}");
    } else {
        // The missing source only affects this log line.
        debug!("({mode}): Processing ICMP error message with flow {f}");
    }

    let flow_info_locked = flow_info.locked.read();
    let Some(state) = S::of(&flow_info_locked) else {
        debug!("({mode}): ICMP error hit a flow carrying no {mode} state");
        return Err(DoneReason::InternalFailure);
    };

    // translate inner packet fragment with the common API object `NatTranslationData`
    let nat_translation = state.quoted_translation();
    if let Err(e) = nat_translate_icmp_inner(packet, &nat_translation) {
        debug!("({mode}): Translation of ICMP error inner packet failed: {e}");
        return Err(DoneReason::InternalFailure);
    }
    // Recompute the outer ICMP checksum after changing the quoted packet.
    // The quote's checksum may be absent or truncated, so its updates may change the outer sum.
    packet.meta_mut().set_checksum_refresh(true);

    // translate the ICMP error packet (outer)
    if let Err(e) = state.translate(packet) {
        debug!("({mode}): Failed to translate ICMP error packet: {e}");
        return Err(DoneReason::InternalFailure);
    }
    Ok(state.status().load())
}
