// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Handling of ICMP errors in stateful NAT (masquerading)

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::icmp_handler::icmp_error_msg::nat_translate_icmp_inner;
use net::buffer::PacketBufferMut;
use net::flows::ExtractRef;
use net::flows::FlowInfo;
use net::headers::{TryInnerIp, TryIp, TryIpMut};
use net::packet::{DoneReason, Packet};

use crate::StatefulNat;
use crate::stateful::NatFlowState;

use tracing::debug;

pub(crate) fn handle_icmp_error_masquerading<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    flow_info: &FlowInfo,
) {
    let f = flow_info.logfmt();
    debug!("Processing ICMP error message with flow {f}");

    let flow_info_locked = flow_info.locked.read().unwrap();

    let nat_translation = if packet
        .try_ip()
        .unwrap_or_else(|| unreachable!())
        .src_addr()
        .is_ipv4()
    {
        let nat_state = flow_info_locked
            .nat_state
            .extract_ref::<NatFlowState<Ipv4Addr>>()
            .unwrap_or_else(|| unreachable!());

        StatefulNat::get_translation_data(&nat_state.dst_alloc, &nat_state.src_alloc)
    } else {
        let nat_state = flow_info_locked
            .nat_state
            .extract_ref::<NatFlowState<Ipv6Addr>>()
            .unwrap_or_else(|| unreachable!());

        StatefulNat::get_translation_data(&nat_state.dst_alloc, &nat_state.src_alloc)
    };

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
