// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Handling of ICMP errors in stateful NAT (masquerading)

use crate::icmp_handler::icmp_error_msg::nat_translate_icmp_inner;
use crate::stateful::state::MasqueradeState;
use net::buffer::PacketBufferMut;
use net::flows::ExtractRef;
use net::flows::FlowInfo;
use net::headers::{TryInnerIp, TryIpMut};
use net::packet::{DoneReason, Packet};
use tracing::debug;

pub(crate) fn handle_icmp_error_masquerading<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    flow_info: &FlowInfo,
) {
    let src_vpcd = packet.meta().src_vpcd.unwrap_or_else(|| unreachable!());
    debug!(
        "Processing ICMP error message from {src_vpcd} with flow {}",
        flow_info.logfmt()
    );

    let flow_info_locked = flow_info.locked.read().unwrap();

    let nat_translation = flow_info_locked
        .nat_state
        .extract_ref::<MasqueradeState>()
        .unwrap_or_else(|| unreachable!())
        .reverse_translation_data();

    // translate inner packet fragment
    if let Err(e) = nat_translate_icmp_inner(packet, &nat_translation) {
        debug!("Translation of inner packet failed: {e}\n{packet}");
        packet.done(DoneReason::InternalFailure);
        return;
    }

    // translate ICMP (outer) packet
    let inner_src_addr = packet.try_inner_ip().unwrap().src_addr();
    if packet
        .try_ip_mut()
        .unwrap_or_else(|| unreachable!())
        .try_set_destination(inner_src_addr)
        .is_err()
    {
        packet.done(DoneReason::InternalFailure);
        return;
    }

    packet.meta_mut().set_checksum_refresh(true);
}
