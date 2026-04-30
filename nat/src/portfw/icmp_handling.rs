// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::doc_markdown)]

//! Handling of ICMP errors in port-forwarded traffic.
//! ```text
//! Sketch of ICMP error processing with port forwarding. The arrow indicates the
//! direction of the ICMP error.
//!
//!                    ICMP-error                                 ICMP-error
//!               ───┬────────────────┬─►                    ───┬────────────────┬─►
//!                  │                │                         │                │
//!              ◄───▼──                                    ◄───▼──
//!             offending packet      │                    offending packet      │
//!            (embedded in ICMP                          (embedded in ICMP
//!             error packet)         │                    error packet)         │
//!
//!                                   │                                          │
//!                     ┌──────────┐                               ┌──────────┐
//!                 ◄───┼   DNAT   │  │                        ◄───┼   SNAT   │  │
//!                     └──────────┘                               └──────────┘
//!                     ┌──────────┐  ▼                            ┌──────────┐  ▼
//!                (*)  │   SNAT   ┼───►                      (*)  │   DNAT   ┼───►
//!                     └──────────┘                               └──────────┘
//!
//! If the offending packet was port-forwarded           If the offending packet was in the reverse
//! (DNATed) we must SNAT the ICMP packet                sense of port-forwarding (was SNATed), we
//! and undo the DNATing of the innner packet.           must DNAT the ICMP packet and undo the
//!                                                      SNATing of the inner packet.
//!
//! Wether we get an ICMP error in the forward or reverse direction of port-forwarding
//! we need to treat the ICMP packet (outer) according to the rule that would be used to process
//! the traffic in the reverse direction of the offending packet.
//! ```

use net::buffer::PacketBufferMut;
use net::flows::ExtractRef;
use net::flows::FlowInfo;
use net::packet::{DoneReason, Packet};

use super::flow_state::PortFwState;
use super::packet::nat_packet;
use crate::common::{NatAction, NatFlowStatus};
use crate::icmp_handler::icmp_error_msg::nat_translate_icmp_inner;
use crate::{NatPort, NatTranslationData};

use tracing::debug;

// Build `NatTranslationData` from `PortFwState` to translate the packet embedded in the ICMP error
fn as_nat_translation(pfw_state: &PortFwState) -> NatTranslationData {
    match pfw_state.action {
        NatAction::SrcNat => NatTranslationData::default()
            .dst_addr(pfw_state.use_ip().inner())
            .dst_port(NatPort::Port(pfw_state.use_port())),
        NatAction::DstNat => NatTranslationData::default()
            .src_addr(pfw_state.use_ip().inner())
            .src_port(NatPort::Port(pfw_state.use_port())),
    }
}

pub(crate) fn handle_icmp_error_port_forwarding<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    flow_info: &FlowInfo,
) -> Result<NatFlowStatus, DoneReason> {
    let src_vpcd = packet.meta().src_vpcd.unwrap_or_else(|| unreachable!());
    let f = flow_info.logfmt();
    debug!("(port-forwarding): Processing ICMP error packet from {src_vpcd} using flow {f}");

    let flow_info_locked = flow_info.locked.read().unwrap();
    let state = flow_info_locked
        .port_fw_state
        .extract_ref::<PortFwState>()
        .unwrap_or_else(|| unreachable!());

    // translate the inner packet depending on the port-forwarding state associated to the
    // reverse flow of the offending packet.
    let translation_data = as_nat_translation(state);
    if let Err(e) = nat_translate_icmp_inner(packet, &translation_data) {
        debug!("(port-forwarding): Translation of ICMP error inner packet failed: {e}");
        return Err(DoneReason::InternalFailure);
    }

    // NAT the ICMP packet according to the port-fw state of the reverse flow of the offending packet
    if let Err(e) = nat_packet(packet, state) {
        debug!("(port-forwarding): Failed to NAT ICMP error packet: {e}");
        return Err(DoneReason::InternalFailure);
    }
    Ok(state.status.load())
}
