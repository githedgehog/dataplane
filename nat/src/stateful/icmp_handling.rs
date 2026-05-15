// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Handling of ICMP errors in stateful NAT (masquerading)

use crate::common::NatFlowStatus;
use crate::icmp_handler::icmp_error_msg::nat_translate_icmp_inner;
use crate::stateful::packet::masquerade;
use crate::stateful::state::MasqueradeState;
use net::buffer::PacketBufferMut;
use net::flows::ExtractRef;
use net::flows::FlowInfo;
use net::packet::{DoneReason, Packet};
use tracing::debug;

pub(crate) fn handle_icmp_error_masquerading<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    flow_info: &FlowInfo,
) -> Result<NatFlowStatus, DoneReason> {
    let src_vpcd = packet.meta().src_vpcd.unwrap_or_else(|| unreachable!());
    let f = flow_info.logfmt();
    debug!("(masquerade): Processing ICMP error message from {src_vpcd} with flow {f}");

    let flow_info_locked = flow_info.locked.read();
    let state = flow_info_locked
        .nat_state
        .extract_ref::<MasqueradeState>()
        .unwrap_or_else(|| unreachable!());

    // translate inner packet fragment with the common API object `NatTranslationData`
    let nat_translation = state.reverse_translation_data();
    if let Err(e) = nat_translate_icmp_inner(packet, &nat_translation) {
        debug!("(masquerade): Translation of ICMP error inner packet failed: {e}");
        return Err(DoneReason::InternalFailure);
    }

    // translate the ICMP error packet (outer)
    let xlate = state.as_translate();
    if let Err(e) = masquerade(packet, &xlate) {
        debug!("(masquerade): Failed to translate ICMP error packet with {xlate}: {e}");
        return Err(DoneReason::InternalFailure);
    }
    Ok(state.status.load())
}
