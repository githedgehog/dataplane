// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end tests for the flow-filter network function.

#![cfg(test)]

use crate::FlowFilter;
use crate::context::{FlowFilterContext, FlowFilterContextWriter};
use crate::test_utils::{
    build_icmp_packet, build_nonip_packet, build_tcp_packet, build_tcp_packet_v6, build_udp_packet,
    context, expose, expose_masquerade, expose_port_forwarding, expose_static, peering, v4, v6,
    vpcd,
};
use concurrency::sync::Arc;
use lpm::prefix::L4Protocol;
use net::FlowKey;
use net::buffer::TestBuffer;
use net::flows::{FlowInfo, FlowStatus};
use net::headers::Headers;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::parse::DeParse;
use pipeline::{NetworkFunction, PipelineData};
use std::time::{Duration, Instant};

// -------------------------------------------------------------------------------------------------
// Helpers

// Serialize built headers into a parseable test packet, marked as overlay traffic with the given
// source VPC (the pipeline only processes overlay packets that still lack a destination VPC).
fn packet(src_vpcd: Option<VpcDiscriminant>, headers: Headers) -> Packet<TestBuffer> {
    let mut buffer = TestBuffer::new();
    headers.deparse(buffer.as_mut()).unwrap();
    let mut packet = Packet::new(buffer).unwrap();
    packet.meta_mut().set_overlay(true);
    packet.meta_mut().src_vpcd = src_vpcd;
    packet
}

// Attach a flow session, the way a downstream stateful NF would. `active` controls the flow status
// (only active flows can be used to bypass the filter); `dst_vpcd` is the flow's recorded
// destination (`None` models a buggy flow with no destination); `nat_state` / `port_fw_state` model
// stored masquerade / port-forwarding state. Returns the shared `FlowInfo` so a test can inspect it
// after processing (e.g. to check invalidation).
fn attach_flow(
    packet: &mut Packet<TestBuffer>,
    dst_vpcd: Option<VpcDiscriminant>,
    active: bool,
    nat_state: bool,
    port_fw_state: bool,
) -> Arc<FlowInfo> {
    let flow_key = FlowKey::try_from(&*packet).unwrap();

    let expires_at = Instant::now() + Duration::from_secs(60);
    let (flow_info, _) = FlowInfo::related_pair(
        expires_at,
        flow_key,
        packet.meta().compute_flow_flags_forward(),
        flow_key.reverse(dst_vpcd),
        packet.meta().compute_flow_flags_reverse(),
    );

    if active {
        flow_info.update_status(FlowStatus::Active);
    }
    {
        let mut locked = flow_info.locked.write();
        locked.dst_vpcd = dst_vpcd;
        if nat_state {
            // The concrete type would be a NatState; a bool is enough here since the flow filter
            // only checks for presence, never downcasts it.
            locked.nat_state = Some(Box::new(true));
        }
        if port_fw_state {
            locked.port_fw_state = Some(Box::new(true));
        }
    }
    packet.meta_mut().flow_info = Some(flow_info.clone());
    flow_info
}

fn make_flow_filter(ctx: FlowFilterContext) -> (FlowFilter, FlowFilterContextWriter) {
    let writer = FlowFilterContextWriter::default();
    writer.store(ctx);
    (
        FlowFilter::new("test-flow-filter", writer.get_reader()),
        writer,
    )
}

// Set the configuration generation id the filter compares flows against.
fn set_genid(flow_filter: &mut FlowFilter, genid: i64) {
    <FlowFilter as NetworkFunction<TestBuffer>>::set_data(
        flow_filter,
        Arc::new(PipelineData::new(genid)),
    );
}

fn run(flow_filter: &mut FlowFilter, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
    flow_filter.process([packet].into_iter()).next().unwrap()
}

// vpc1 <-> vpc2: vpc1 (source side) exposes a plain prefix, a static-NAT prefix and a masquerade
// prefix; vpc2 (destination side) exposes a plain prefix.
fn source_nat_context() -> FlowFilterContext {
    context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            (
                "vpc1",
                vec![
                    expose("1.0.0.0/24"),
                    expose_static("2.0.0.0/24", "20.0.0.0/24"),
                    expose_masquerade("3.0.0.0/24", "30.0.0.0/24"),
                ],
            ),
            ("vpc2", vec![expose("5.0.0.0/24")]),
        )],
    )
}

// vpc1 <-> vpc2 with a TCP-only port-forwarding destination on vpc2.
fn dst_port_forwarding_context() -> FlowFilterContext {
    context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("10.0.0.0/24")]),
            (
                "vpc2",
                vec![expose_port_forwarding(
                    "192.168.80.5/32",
                    (22, 22),
                    "80.0.0.5/32",
                    (2222, 2222),
                    Some(L4Protocol::Tcp),
                )],
            ),
        )],
    )
}

// vpc1 <-> vpc2 with a static-NAT destination on vpc2.
fn dst_static_context() -> FlowFilterContext {
    context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("10.0.0.0/24")]),
            ("vpc2", vec![expose_static("192.168.6.0/24", "60.0.0.0/24")]),
        )],
    )
}

// vpc1 <-> vpc2: vpc1 (source side) exposes a masquerade prefix; vpc2 (destination side) exposes a
// static-NAT prefix.
fn static_nat_plus_masquerade_context() -> FlowFilterContext {
    context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose_masquerade("1.0.0.0/24", "10.0.0.0/24")]),
            ("vpc2", vec![expose_static("2.0.0.0/24", "20.0.0.0/24")]),
        )],
    )
}

// vpc1 <-> vpc2 over IPv6.
fn ipv6_context() -> FlowFilterContext {
    context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("2001:db8::/32")]),
            ("vpc2", vec![expose("2001:db9::/32")]),
        )],
    )
}

// -------------------------------------------------------------------------------------------------
// Basic acceptance / rejection

#[test]
fn allowed_packet_sets_destination_and_no_nat() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ),
    );
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(!out.meta().requires_masquerade());
    assert!(!out.meta().requires_static_nat());
    assert!(!out.meta().requires_port_forwarding());
}

#[test]
fn unmatched_destination_is_filtered() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("1.0.0.5"), v4("9.9.9.9"), 1234, 5678),
        ),
    );
    assert_eq!(out.get_done(), Some(DoneReason::Filtered));
    assert_eq!(out.meta().dst_vpcd, None);
}

#[test]
fn missing_source_vpc_is_unroutable() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let out = run(
        &mut flow_filter,
        packet(
            None,
            build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ),
    );
    assert_eq!(out.get_done(), Some(DoneReason::Unroutable));
}

#[test]
fn non_overlay_packet_is_left_untouched() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    p.meta_mut().set_overlay(false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done());
    assert_eq!(out.meta().dst_vpcd, None);
}

#[test]
fn packet_with_destination_already_set_is_left_untouched() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    p.meta_mut().dst_vpcd = Some(vpcd(777));
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(777)));
}

#[test]
fn icmp_packet_is_allowed() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_icmp_packet(v4("1.0.0.5"), v4("5.0.0.10")),
        ),
    );
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
}

// -------------------------------------------------------------------------------------------------
// NAT requirement flags derived from the lookup

#[test]
fn static_nat_source_sets_static_flag() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("2.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ),
    );
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(out.meta().requires_static_nat());
    assert!(out.meta().requires_static_nat_src());
    assert!(!out.meta().requires_masquerade());
}

#[test]
fn masquerade_source_sets_masquerade_flag() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("3.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ),
    );
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(out.meta().requires_masquerade());
    assert!(!out.meta().requires_static_nat());
}

#[test]
fn port_forwarding_destination_sets_flag_and_is_protocol_aware() {
    let (mut flow_filter, _) = make_flow_filter(dst_port_forwarding_context());

    // TCP packet into the port-forwarding range: allowed, flag set.
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
        ),
    );
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(out.meta().requires_port_forwarding());

    // UDP packet into the same range: TCP-only forwarding does not match -> filtered.
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_udp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
        ),
    );
    assert_eq!(out.get_done(), Some(DoneReason::Filtered));
}

// -------------------------------------------------------------------------------------------------
// Stateful flows

#[test]
fn active_flow_state_is_honored() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    // Route itself requires no NAT, but the attached active flow carries masquerade state, so the
    // bypass path tags the packet for masquerade. Flow genid (0) matches the NF's default genid
    // (0), so the flow is considered up-to-date and is not invalidated.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, true, false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(out.meta().requires_masquerade());
    assert_eq!(flow.status(), FlowStatus::Active);
}

#[test]
fn outdated_flow_is_invalidated() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    // Advance the configuration generation so the flow (genid 0) is outdated.
    set_genid(&mut flow_filter, 5);

    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    // The flow points at the wrong destination VPC for the current config.
    let flow = attach_flow(&mut p, Some(vpcd(300)), true, false, false);
    let out = run(&mut flow_filter, p);

    // The packet is re-evaluated from the tables (resolving to vpc2) and the stale flow is cancelled.
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

// -------------------------------------------------------------------------------------------------
// More NAT flags, protocols and batching

#[test]
fn static_nat_destination_sets_static_dst_flag() {
    let (mut flow_filter, _) = make_flow_filter(dst_static_context());
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("10.0.0.5"), v4("60.0.0.10"), 1234, 5678),
        ),
    );
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(out.meta().requires_static_nat());
    assert!(out.meta().requires_static_nat_dst());
    assert!(!out.meta().requires_static_nat_src());
}

#[test]
fn ipv6_packet_through_the_nf() {
    let (mut flow_filter, _) = make_flow_filter(ipv6_context());
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet_v6(v6("2001:db8::1"), v6("2001:db9::1"), 1234, 5678),
        ),
    );
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
}

#[test]
fn non_ip_packet_is_dropped() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let out = run(
        &mut flow_filter,
        packet(Some(vpcd(100)), build_nonip_packet()),
    );
    assert_eq!(out.get_done(), Some(DoneReason::NotIp));
}

#[test]
fn batch_of_packets_is_processed_independently() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    let packets = vec![
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ), // allowed, no NAT
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("1.0.0.5"), v4("9.9.9.9"), 1234, 5678),
        ), // filtered
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("3.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ), // allowed, masquerade
    ];
    let out: Vec<_> = flow_filter.process(packets.into_iter()).collect();
    assert_eq!(out.len(), 3);

    assert!(!out[0].is_done());
    assert_eq!(out[0].meta().dst_vpcd, Some(vpcd(200)));
    assert!(!out[0].meta().requires_masquerade());

    assert_eq!(out[1].get_done(), Some(DoneReason::Filtered));

    assert!(!out[2].is_done());
    assert_eq!(out[2].meta().dst_vpcd, Some(vpcd(200)));
    assert!(out[2].meta().requires_masquerade());
}

// -------------------------------------------------------------------------------------------------
// Stateful flows: bypass eligibility

#[test]
fn active_flow_port_forwarding_state_is_honored() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    // No-NAT route, but the active flow carries port-forwarding state -> tagged for port forwarding.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, false, true);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(out.meta().requires_port_forwarding());
    assert_eq!(flow.status(), FlowStatus::Active);
}

#[test]
fn inactive_flow_state_is_not_honored() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    // The flow carries masquerade state but is not active, so it must not be used to bypass the
    // filter: the packet is evaluated purely from the tables (no NAT) and the flow is left alone.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), false, true, false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(!out.meta().requires_masquerade());
    assert_ne!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn active_flow_without_destination_is_invalidated() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    // An active, up-to-date flow that records no destination VPC is a bug: it is invalidated.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, None, true, false, false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

// -------------------------------------------------------------------------------------------------
// Stateful flows: invalidation of outdated flows (each `should_invalidate_flow` branch)

#[test]
fn outdated_flow_that_no_longer_needs_state_is_invalidated() {
    // Outdated flow, correct destination, but the (no-NAT) route no longer requires any state.
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    set_genid(&mut flow_filter, 5);
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, false, false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn outdated_flow_missing_masquerade_state_is_invalidated() {
    // Outdated flow, correct destination, route now requires masquerade, but the flow has no
    // masquerade state.
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    set_genid(&mut flow_filter, 5);
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("3.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, false, false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_masquerade());
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn outdated_flow_missing_port_forwarding_state_is_invalidated() {
    // Outdated flow, correct destination, route now requires port forwarding, but the flow has no
    // port-forwarding state.
    let (mut flow_filter, _) = make_flow_filter(dst_port_forwarding_context());
    set_genid(&mut flow_filter, 5);
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, false, false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_port_forwarding());
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn outdated_flow_with_consistent_state_is_kept() {
    // Outdated flow, correct destination, route requires masquerade and the flow already has
    // masquerade state: the filter cannot prove it stale, so it is left for the stateful NFs.
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    set_genid(&mut flow_filter, 5);
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("3.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, true, false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_masquerade());
    assert_ne!(flow.status(), FlowStatus::Cancelled);
}

// -------------------------------------------------------------------------------------------------
// Stateful reply traffic across config changes. The tables cannot answer for the reverse direction
// of stateful-NAT sessions (masquerade destinations are only markers, port-forwarding sources are
// absent altogether), so after a genid bump those packets must ride their established flow instead
// of being dropped -- while packets with no such flow, and flows whose peering is gone, still fail
// closed.

#[test]
fn masquerade_reply_on_established_flow_survives_config_change() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    set_genid(&mut flow_filter, 5);
    // Reply direction of a masqueraded session: vpc2 answers towards vpc1's masquerade public
    // range. The flow (genid 0) is outdated, so the bypass is refused and the packet goes through
    // the tables, which resolve a masquerade marker.
    let mut p = packet(
        Some(vpcd(200)),
        build_tcp_packet(v4("5.0.0.10"), v4("30.0.0.5"), 5678, 1234),
    );
    let flow = attach_flow(&mut p, Some(vpcd(100)), true, true, false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(100)));
    assert!(out.meta().requires_masquerade());
    assert_ne!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn masquerade_reply_without_flow_is_filtered() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    // No established flow: a masquerade destination cannot accept a new connection.
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(200)),
            build_tcp_packet(v4("5.0.0.10"), v4("30.0.0.5"), 5678, 1234),
        ),
    );
    assert_eq!(out.get_done(), Some(DoneReason::Filtered));
}

#[test]
fn masquerade_reply_with_inactive_flow_is_filtered() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    set_genid(&mut flow_filter, 5);
    let mut p = packet(
        Some(vpcd(200)),
        build_tcp_packet(v4("5.0.0.10"), v4("30.0.0.5"), 5678, 1234),
    );
    attach_flow(&mut p, Some(vpcd(100)), false, true, false);
    let out = run(&mut flow_filter, p);
    assert_eq!(out.get_done(), Some(DoneReason::Filtered));
}

#[test]
fn masquerade_reply_with_mismatched_flow_destination_is_filtered() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    set_genid(&mut flow_filter, 5);
    let mut p = packet(
        Some(vpcd(200)),
        build_tcp_packet(v4("5.0.0.10"), v4("30.0.0.5"), 5678, 1234),
    );
    // The flow's recorded destination does not match what the tables resolve: stale, drop.
    let flow = attach_flow(&mut p, Some(vpcd(300)), true, true, false);
    let out = run(&mut flow_filter, p);
    assert_eq!(out.get_done(), Some(DoneReason::Filtered));
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn port_forwarding_reply_on_established_flow_survives_config_change() {
    let (mut flow_filter, _) = make_flow_filter(dst_port_forwarding_context());
    set_genid(&mut flow_filter, 5);
    // Reply direction of a forwarded session: the forwarded host answers from its private
    // address, which is (deliberately) not in the local tables.
    let mut p = packet(
        Some(vpcd(200)),
        build_tcp_packet(v4("192.168.80.5"), v4("10.0.0.5"), 22, 1234),
    );
    let flow = attach_flow(&mut p, Some(vpcd(100)), true, false, true);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(100)));
    assert!(out.meta().requires_port_forwarding());
    assert_ne!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn port_forwarding_reply_without_flow_is_filtered() {
    let (mut flow_filter, _) = make_flow_filter(dst_port_forwarding_context());
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(200)),
            build_tcp_packet(v4("192.168.80.5"), v4("10.0.0.5"), 22, 1234),
        ),
    );
    assert_eq!(out.get_done(), Some(DoneReason::Filtered));
}

#[test]
fn stateful_flow_does_not_survive_peering_removal() {
    // The peering is gone from the new config: even an active, state-consistent flow must not let
    // reply traffic through (stage 1 finds no marker to trust), and the flow pair is invalidated.
    let (mut flow_filter, writer) = make_flow_filter(source_nat_context());
    writer.store(context(&[], vec![]));
    set_genid(&mut flow_filter, 5);
    let mut p = packet(
        Some(vpcd(200)),
        build_tcp_packet(v4("5.0.0.10"), v4("30.0.0.5"), 5678, 1234),
    );
    let flow = attach_flow(&mut p, Some(vpcd(100)), true, true, false);
    let out = run(&mut flow_filter, p);
    assert_eq!(out.get_done(), Some(DoneReason::Filtered));
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

// -------------------------------------------------------------------------------------------------
// Stateful flows: flow-key attachment for the {masquerade|port-forwarding} + static-NAT combination

#[test]
fn flow_key_attached_for_stateful_plus_static_nat_first_packet() {
    let (mut flow_filter, _) = make_flow_filter(static_nat_plus_masquerade_context());
    // Masquerade on the source combined with static-NAT on the destination, assuming this is the
    // first packet of a flow: we don't bypass the lookup, and we also need to have a flow key
    // attached for the stateful NFs to create a flow with the relevant information for both NAT
    // modes.
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("1.0.0.5"), v4("20.0.0.10"), 1234, 5678),
        ),
    );
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_masquerade());
    assert!(out.meta().requires_static_nat());
    assert!(out.meta().flow_key.is_some());
}

#[test]
fn flow_key_attached_for_stateful_plus_static_nat_followup_packet() {
    let (mut flow_filter, _) = make_flow_filter(static_nat_plus_masquerade_context());
    // Masquerade on the source combined with static-NAT on the destination, assuming we already
    // have an existing flow with the relevant information for both NAT modes: both modes are added
    // to packet metadata, but there's no need to attach a new flow key (only required for flow
    // creation).
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("20.0.0.10"), 1234, 5678),
    );
    // Set source static-NAT flag manually just for flow attachment, to have the created flow
    // contain the static-NAT state.
    p.meta_mut().set_static_nat_src(true);
    attach_flow(&mut p, Some(vpcd(200)), true, true, false);
    // Undo source static NAT flag.
    p.meta_mut().set_static_nat_src(false);
    let out = run(&mut flow_filter, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_masquerade());
    assert!(out.meta().requires_static_nat());
    assert!(out.meta().flow_key.is_none());
}

// -------------------------------------------------------------------------------------------------
// Context hot-swap via the control-plane writer

// A context published through the writer handle is observed by a running the NF on its next packet:
// the same packet routes before the swap and is filtered after it.
#[test]
fn context_writer_hot_swaps_routing() {
    let (mut flow_filter, writer) = make_flow_filter(source_nat_context());
    // Before the swap: 1.0.0.5 -> 5.0.0.10 is routed to vpc2.
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ),
    );
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));

    // Publish an empty context (no peerings); the running NF observes it on the next packet.
    writer.store(context(&[], vec![]));
    let out = run(
        &mut flow_filter,
        packet(
            Some(vpcd(100)),
            build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ),
    );
    assert_eq!(out.get_done(), Some(DoneReason::Filtered));
    assert_eq!(out.meta().dst_vpcd, None);
}

// -------------------------------------------------------------------------------------------------
// Batched processing: a burst larger than MAX_BATCH (exercises per-version chunking), and a mixed
// v4/v6 burst (exercises the version partition + output-order preservation).

#[test]
fn burst_larger_than_max_batch_is_processed() {
    let (mut flow_filter, _) = make_flow_filter(source_nat_context());
    // 40 packets (> MAX_BATCH = 32): even indices routed to vpc2, odd indices filtered.
    let packets: Vec<_> = (0..40)
        .map(|i| {
            let dst = if i % 2 == 0 { "5.0.0.10" } else { "9.9.9.9" };
            packet(
                Some(vpcd(100)),
                build_tcp_packet(v4("1.0.0.5"), v4(dst), 1234, 5678),
            )
        })
        .collect();
    let out: Vec<_> = flow_filter.process(packets.into_iter()).collect();
    // `enforce` marks (does not drop) filtered packets, so all 40 come out in order: even indices
    // routed to vpc2, odd indices marked Filtered.
    assert_eq!(out.len(), 40);
    for (i, pkt) in out.iter().enumerate() {
        if i % 2 == 0 {
            assert!(!pkt.is_done(), "{:?}", pkt.get_done());
            assert_eq!(pkt.meta().dst_vpcd, Some(vpcd(200)));
        } else {
            assert_eq!(pkt.get_done(), Some(DoneReason::Filtered));
        }
    }
}

#[test]
fn mixed_v4_v6_burst_partitions_by_version_and_preserves_order() {
    let ctx = context(
        &[("vpc1", 100), ("vpc2", 200), ("vpc3", 300)],
        vec![
            peering(
                "vpc1-to-vpc2",
                ("vpc1", vec![expose("1.0.0.0/24")]),
                ("vpc2", vec![expose("5.0.0.0/24")]),
            ),
            peering(
                "vpc1-to-vpc3",
                ("vpc1", vec![expose("2001:db8::/32")]),
                ("vpc3", vec![expose("2001:db9::/32")]),
            ),
        ],
    );
    let (mut flow_filter, _) = make_flow_filter(ctx);
    // Interleave v4 (-> vpc2) and v6 (-> vpc3). Nothing is dropped, so output order == input order.
    let packets: Vec<_> = (0..8)
        .map(|i| {
            if i % 2 == 0 {
                packet(
                    Some(vpcd(100)),
                    build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
                )
            } else {
                packet(
                    Some(vpcd(100)),
                    build_tcp_packet_v6(v6("2001:db8::1"), v6("2001:db9::1"), 1234, 5678),
                )
            }
        })
        .collect();
    let out: Vec<_> = flow_filter.process(packets.into_iter()).collect();
    assert_eq!(out.len(), 8);
    for (i, pkt) in out.iter().enumerate() {
        let expected = if i % 2 == 0 { vpcd(200) } else { vpcd(300) };
        assert_eq!(pkt.meta().dst_vpcd, Some(expected), "packet {i}");
    }
}
