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

use crate::icmp_handler::icmp_error_msg::nat_translate_icmp_inner;
use crate::portfw::packet::nat_packet;
use crate::{NatPort, NatTranslationData};

use super::flow_state::PortFwState;
use crate::portfw::flow_state::PortFwAction;

use tracing::debug;

// Build `NatTranslationData` from `PortFwState` to translate the packet embedded in the ICMP error
fn as_nat_translation(pfw_state: &PortFwState) -> NatTranslationData {
    match pfw_state.action {
        PortFwAction::SrcNat => NatTranslationData::default()
            .dst_addr(pfw_state.use_ip().inner())
            .dst_port(NatPort::Port(pfw_state.use_port())),
        PortFwAction::DstNat => NatTranslationData::default()
            .src_addr(pfw_state.use_ip().inner())
            .src_port(NatPort::Port(pfw_state.use_port())),
    }
}

pub(crate) fn handle_icmp_error_port_forwarding<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    flow_info: &FlowInfo,
) {
    let flow_info_locked = flow_info.locked.read().unwrap();
    let pfw_state = flow_info_locked
        .port_fw_state
        .extract_ref::<PortFwState>()
        .unwrap_or_else(|| unreachable!());

    let src_vpcd = packet.meta().src_vpcd.unwrap_or_else(|| unreachable!());
    let f = flow_info.logfmt();
    debug!("Processing ICMP error packet from {src_vpcd} using flow {f}");

    // this is informational and to drop ICMP errors that need not be processed: if the flow for the offending
    // packet is no longer valid, no need to process the ICMP error.
    if let Some(related) = flow_info
        .related
        .as_ref()
        .and_then(std::sync::Weak::upgrade)
    {
        debug!(
            "The flow for the offending packet is {} {related}",
            related.flowkey().unwrap_or_else(|| unreachable!())
        );
        if !related.is_active() {
            packet.done(DoneReason::Filtered);
            return;
        }
    }

    // translate the inner packet depending on the port-forwarding state associated to the
    // reverse flow of the offending packet.
    let translation_data = as_nat_translation(pfw_state);
    if let Err(e) = nat_translate_icmp_inner(packet, &translation_data) {
        debug!("Translation of inner packet failed: {e}\n{packet}");
        packet.done(DoneReason::InternalFailure);
        return;
    }

    // NAT the ICMP packet according to the port-fw state of the reverse flow of the offending packet
    if !nat_packet(packet, pfw_state) {
        debug!("Failed to NAT ICMP error packet: {packet}");
        packet.done(DoneReason::InternalFailure);
        return;
    }
    debug!("Successfully NATed ICMP error packet");
}
