// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end tests for the flow-filter network function.

#![cfg(test)]

use crate::context::{FlowFilterContext, FlowFilterContextWriter};
use crate::fuzz_gen::Probe;
use crate::test_utils::{
    build_icmp_packet, build_nonip_packet, build_tcp_packet, build_tcp_packet_v6, build_udp_packet,
    context, expose, expose_masquerade, expose_port_forwarding, expose_static, peering, v4, v6,
    vpcd,
};
use crate::{FlowFilter, LookupResult, NatRequirement};
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

// -------------------------------------------------------------------------------------------------
// The flow-invalidation decision table, as an executable spec. `should_invalidate_flow` is the
// subtlest policy in this NF (it decides which established sessions a config change kills); the
// property pins its complete truth table instead of sampling branches.

#[derive(Debug, Clone, Copy, bolero::TypeGenerator)]
enum GenidRel {
    Older,
    Same,
    Newer,
}

#[derive(Debug, Clone, Copy, bolero::TypeGenerator)]
struct InvalidationCase {
    meta_masquerade: bool,
    meta_port_forwarding: bool,
    has_flow: bool,
    genid: GenidRel,
    /// `Some(true)`: the flow's destination equals the route's; `Some(false)`: a different one;
    /// `None`: the flow records no destination.
    flow_dst_matches: Option<bool>,
    flow_masquerade: bool,
    flow_port_forwarding: bool,
}

// The specification: a flow is invalidated iff it comes from a DIFFERENT config generation
// (older or newer -- only an equal genid is trusted) AND the filter can prove it stale: the
// destination changed (or was never recorded), a stateful-NAT requirement appeared or
// disappeared, or the route no longer needs state at all. Anything else is deferred to the
// stateful NFs, which own the state's validity.
fn expected_invalidation(case: &InvalidationCase) -> bool {
    if !case.has_flow || matches!(case.genid, GenidRel::Same) {
        return false;
    }
    case.flow_dst_matches != Some(true)
        || case.meta_masquerade != case.flow_masquerade
        || case.meta_port_forwarding != case.flow_port_forwarding
        || (!case.meta_masquerade && !case.meta_port_forwarding)
}

#[test]
fn invalidation_decision_matches_spec() {
    use net::packet::PacketMeta;

    const GENID: i64 = 7;
    let route_dst = vpcd(200);

    bolero::check!()
        .with_type::<InvalidationCase>()
        .for_each(|case| {
            // Built inside the closure: neither the filter (classifier) nor FlowInfo (interior
            // mutability) is unwind-safe, so they cannot be captured across bolero's
            // catch_unwind boundary. Any FlowInfo serves: the decision reads only the summary
            // fields (the info itself is used for logging alone).
            let (flow_filter, _writer) = make_flow_filter(FlowFilterContext::default());
            let mut p = packet(
                Some(vpcd(100)),
                build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
            );
            let flow_info = attach_flow(&mut p, Some(route_dst), true, false, false);

            let mut meta = PacketMeta::default();
            meta.set_masquerade(case.meta_masquerade);
            meta.set_port_forwarding(case.meta_port_forwarding);

            let summary = case.has_flow.then(|| crate::FlowSummary {
                genid: match case.genid {
                    GenidRel::Older => GENID - 3,
                    GenidRel::Same => GENID,
                    GenidRel::Newer => GENID + 3,
                },
                dst_vpcd: match case.flow_dst_matches {
                    Some(true) => Some(route_dst),
                    Some(false) => Some(vpcd(300)),
                    None => None,
                },
                needs_masquerade: case.flow_masquerade,
                needs_port_forwarding: case.flow_port_forwarding,
                flow_info,
            });

            assert_eq!(
                flow_filter.should_invalidate_flow(&meta, route_dst, GENID, summary.as_ref()),
                expected_invalidation(case),
                "decision diverges from spec for {case:?}",
            );
        });
}

// -------------------------------------------------------------------------------------------------
// Burst-level structural invariants. The semantic correctness of individual routing decisions is
// covered by the context property tests; here the subject is the burst pipeline itself
// (classify / batched lookup / apply): nothing is lost or reordered, skipped packets are
// untouched, every processed packet is either resolved or done (never both, never neither), the
// flow bypass always short-circuits when it should, and a Filtered packet always cancels its
// flow pair.

#[derive(Debug, Clone, Copy, bolero::TypeGenerator)]
struct BurstFlowSpec {
    active: bool,
    /// `Some(true)`: the flow records vpc2 (the routable peer); `Some(false)`: an unrelated VPC;
    /// `None`: no destination recorded (a buggy flow).
    dst: Option<bool>,
    masq_state: bool,
    pf_state: bool,
}

#[derive(Debug, Clone, Copy, bolero::TypeGenerator)]
struct BurstPacketSpec {
    non_ip: bool,
    overlay: bool,
    preset_dst: bool,
    has_src_vpcd: bool,
    src_sel: u8,
    dst_sel: u8,
    flow: Option<BurstFlowSpec>,
}

impl BurstFlowSpec {
    fn dst_vpcd(&self) -> Option<VpcDiscriminant> {
        match self.dst {
            Some(true) => Some(vpcd(200)),
            Some(false) => Some(vpcd(300)),
            None => None,
        }
    }
}

#[test]
fn burst_processing_upholds_structural_invariants() {
    use net::headers::TryTransport;

    bolero::check!()
        .with_type::<(bool, [BurstPacketSpec; 40])>()
        .for_each(|&(bump_genid, ref specs)| {
            // Built inside the closure: the filter holds a classifier, which is not unwind-safe.
            let (mut flow_filter, _writer) = make_flow_filter(source_nat_context());
            if bump_genid {
                set_genid(&mut flow_filter, 5);
            }

            let mut packets = Vec::with_capacity(specs.len());
            let mut flows = Vec::with_capacity(specs.len());
            for (i, spec) in specs.iter().enumerate() {
                let sport = 1000 + u16::try_from(i).unwrap();
                let headers = if spec.non_ip {
                    build_nonip_packet()
                } else {
                    let src = match spec.src_sel % 3 {
                        0 => v4("1.0.0.5"), // plain source expose
                        1 => v4("3.0.0.5"), // masquerade source expose
                        _ => v4("9.9.9.9"), // no source expose (stage-2 miss)
                    };
                    let dst = match spec.dst_sel % 3 {
                        0 => v4("5.0.0.10"),  // the peer's expose (stage-1 hit)
                        1 => v4("30.0.0.10"), // our own masquerade public (stage-1 miss)
                        _ => v4("8.8.8.8"),   // nowhere (stage-1 miss)
                    };
                    build_tcp_packet(src, dst, sport, 5678)
                };
                let mut p = packet(spec.has_src_vpcd.then(|| vpcd(100)), headers);
                p.meta_mut().set_overlay(spec.overlay);
                if spec.preset_dst {
                    p.meta_mut().dst_vpcd = Some(vpcd(777));
                }
                // Flow attachment needs a FlowKey, which a non-IP packet cannot provide.
                let flow = spec
                    .flow
                    .filter(|_| !spec.non_ip)
                    .map(|f| attach_flow(&mut p, f.dst_vpcd(), f.active, f.masq_state, f.pf_state));
                flows.push(flow);
                packets.push(p);
            }

            let out: Vec<_> = flow_filter.process(packets.into_iter()).collect();
            assert_eq!(out.len(), specs.len(), "burst length must be preserved");

            for (i, (spec, pkt)) in specs.iter().zip(&out).enumerate() {
                // Order: each packet's source-port tag must sit at its original position.
                if !spec.non_ip {
                    let sport = pkt
                        .try_transport()
                        .and_then(|t| t.src_port())
                        .map(std::num::NonZero::get);
                    assert_eq!(
                        sport,
                        Some(1000 + u16::try_from(i).unwrap()),
                        "packet order not preserved at position {i}",
                    );
                }

                // Skipped packets (non-overlay, or destination already resolved upstream) are
                // untouched, and their flows are left alone.
                if !spec.overlay || spec.preset_dst {
                    assert!(!pkt.is_done(), "skipped packet must pass through: {spec:?}");
                    assert_eq!(pkt.meta().dst_vpcd, spec.preset_dst.then(|| vpcd(777)));
                    if let Some(flow) = &flows[i] {
                        assert_ne!(flow.status(), FlowStatus::Cancelled, "{spec:?}");
                    }
                    continue;
                }

                // Every processed packet is either resolved or done -- never both, never neither.
                assert_ne!(
                    pkt.is_done(),
                    pkt.meta().dst_vpcd.is_some(),
                    "processed packet must be resolved XOR done: {spec:?}",
                );

                // An active, current-generation flow with a recorded destination always
                // short-circuits the tables, whatever they would have said.
                if let Some(f) = spec.flow
                    && !spec.non_ip
                    && !bump_genid
                    && f.active
                    && f.dst.is_some()
                {
                    assert!(!pkt.is_done(), "bypass must win: {spec:?}");
                    assert_eq!(pkt.meta().dst_vpcd, f.dst_vpcd(), "{spec:?}");
                }

                // A Filtered packet always cancels its flow pair (Unroutable/NotIp do not).
                if pkt.get_done() == Some(DoneReason::Filtered)
                    && let Some(flow) = &flows[i]
                {
                    assert_eq!(flow.status(), FlowStatus::Cancelled, "{spec:?}");
                }
            }
        });
}

// -------------------------------------------------------------------------------------------------
// End-to-end config oracle: from a generated configuration all the way to a packet's metadata.
//
// The context property tests stop at a `LookupResult`. The step after it -- turning that result
// into the destination and NAT flags the downstream NFs act on -- was covered only by hand-written
// examples, so the mapping was never checked against a configuration nobody chose. This closes
// that last hop: the route is predicted by the *same* config oracle the context suite uses (see
// `context::fuzz::oracle_lookup`), and only the `LookupResult` -> metadata step is restated here.
//
// Scope: packets with no attached flow. Everything a flow contributes -- bypass, invalidation, and
// the reply paths that let an established flow overrule a miss -- is deliberately excluded, since
// that logic is not a function of the configuration and is covered by
// `invalidation_decision_matches_spec` and the flow tests above.

/// What the NF must leave on a flowless packet.
#[derive(Debug, PartialEq, Eq)]
enum NfOutcome {
    /// Dropped for this reason, with no destination stamped.
    Dropped(Option<DoneReason>),
    Routed {
        dst_vpcd: Option<VpcDiscriminant>,
        masquerade: bool,
        static_nat_src: bool,
        static_nat_dst: bool,
        port_forwarding: bool,
        /// Whether the pre-translation flow key was retained.
        flow_key: bool,
    },
}

/// The outcome the configuration predicts, given the route it resolves to.
///
/// Without a flow to vouch for it, every miss drops: a destination miss because no peering covers
/// the packet, a source miss because only an established port-forwarding flow could excuse one. A
/// masquerade destination drops for the same reason -- it cannot accept a new connection.
fn expected_outcome(result: LookupResult) -> NfOutcome {
    let (dst_vpcd, dst_nat, src_nat) = match result {
        LookupResult::Route(route) => route,
        LookupResult::SourceMiss(_) | LookupResult::DestinationMiss => {
            return NfOutcome::Dropped(Some(DoneReason::Filtered));
        }
    };
    if dst_nat == Some(NatRequirement::Masquerade) {
        return NfOutcome::Dropped(Some(DoneReason::Filtered));
    }

    let masquerade = src_nat == Some(NatRequirement::Masquerade);
    let static_nat_src = src_nat == Some(NatRequirement::Static);
    let static_nat_dst = dst_nat == Some(NatRequirement::Static);
    let port_forwarding = src_nat == Some(NatRequirement::PortForwarding)
        || dst_nat == Some(NatRequirement::PortForwarding);
    NfOutcome::Routed {
        dst_vpcd: Some(dst_vpcd),
        masquerade,
        static_nat_src,
        static_nat_dst,
        port_forwarding,
        // Stateful NAT combined with static NAT is the one case that needs the original addresses
        // kept, so the right flow-table entries can be built later.
        flow_key: (masquerade || port_forwarding) && (static_nat_src || static_nat_dst),
    }
}

/// The lookup key a packet presents, as a [`Probe`] the config oracle can answer.
///
/// Deliberately the same extraction `FlowFilter::classify` performs, through the same public
/// accessors: this is how a test asks "what did the NF see", not an independent re-derivation of
/// it. Returns `None` for a packet with no IP layer, which never reaches the tables at all.
fn probe_from_packet(pkt: &Packet<TestBuffer>, src_vpcd: VpcDiscriminant) -> Option<Probe> {
    use net::headers::{TryIp, TryTransport};
    use std::num::NonZero;

    let net = pkt.try_ip()?;
    Some(Probe {
        src_vpcd,
        src_ip: net.src_addr(),
        dst_ip: net.dst_addr(),
        proto: net.next_header(),
        ports: pkt.try_transport().and_then(|t| {
            t.src_port()
                .map(NonZero::get)
                .zip(t.dst_port().map(NonZero::get))
        }),
    })
}

fn observed_outcome(pkt: &Packet<TestBuffer>) -> NfOutcome {
    if pkt.is_done() {
        return NfOutcome::Dropped(pkt.get_done());
    }
    let meta = pkt.meta();
    NfOutcome::Routed {
        dst_vpcd: meta.dst_vpcd,
        masquerade: meta.requires_masquerade(),
        static_nat_src: meta.requires_static_nat_src(),
        static_nat_dst: meta.requires_static_nat_dst(),
        port_forwarding: meta.requires_port_forwarding(),
        flow_key: meta.flow_key.is_some(),
    }
}

/// Realize a probe as a real packet, together with the probe as that packet actually carries it.
///
/// Not every probe is a packet. Source and destination must agree on IP version (the lookup treats
/// a mismatch as a destination miss, but no such packet exists on the wire), ports on the wire are
/// non-zero (0 is the wildcard the lookup substitutes for a portless packet), and ICMP over v6 is a
/// different next header than over v4. Where the packet cannot carry the probe verbatim, the probe
/// is adjusted to match -- so the oracle is always asked about the packet that was really built.
fn probe_packet(probe: &Probe) -> Option<(Packet<TestBuffer>, Probe)> {
    use crate::test_utils::{build_icmp_packet_v6, build_udp_packet_v6};
    use net::ip::NextHeader;

    let mut probe = *probe;
    if let Some((sport, dport)) = probe.ports.as_mut() {
        *sport = (*sport).max(1);
        *dport = (*dport).max(1);
    }

    let headers = match (probe.src_ip, probe.dst_ip) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => match probe.ports {
            Some((sp, dp)) if probe.proto == NextHeader::TCP => build_tcp_packet(src, dst, sp, dp),
            Some((sp, dp)) if probe.proto == NextHeader::UDP => build_udp_packet(src, dst, sp, dp),
            _ => {
                probe.proto = NextHeader::ICMP;
                probe.ports = None;
                build_icmp_packet(src, dst)
            }
        },
        (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) => match probe.ports {
            Some((sp, dp)) if probe.proto == NextHeader::TCP => {
                build_tcp_packet_v6(src, dst, sp, dp)
            }
            Some((sp, dp)) if probe.proto == NextHeader::UDP => {
                build_udp_packet_v6(src, dst, sp, dp)
            }
            _ => {
                probe.proto = NextHeader::ICMP6;
                probe.ports = None;
                build_icmp_packet_v6(src, dst)
            }
        },
        _ => return None,
    };
    Some((packet(Some(probe.src_vpcd), headers), probe))
}

/// The metadata the NF stamps on a flowless packet is exactly what the configuration predicts, for
/// every probe of every generated overlay.
///
/// Coverage is asserted, not assumed: the counters fail the test if a time-boxed run never routed a
/// packet, never applied a NAT requirement, or never reached the flow-key case (which needs a route
/// requiring both stateful and static NAT, and so exists only on masquerade-opposite-static-NAT
/// peerings).
#[test]
fn nf_metadata_matches_config_oracle() {
    use crate::context::fuzz::oracle_lookup;
    use crate::fuzz_gen::{OverlaySpec, ProbeSpec};
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};

    // Lazily initialized so this compiles under the loom backend, whose AtomicU64::new is not const.
    static ROUTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
    static NATTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
    static FLOW_KEYED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
    static DROPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

    bolero::check!()
        .with_type::<(OverlaySpec, [ProbeSpec; 8])>()
        .for_each(|(overlay_spec, probe_specs)| {
            // Built inside the closure: the filter holds a classifier, which is not unwind-safe and
            // so cannot be captured across bolero's catch_unwind boundary.
            let built = overlay_spec.build();
            let (mut flow_filter, _writer) =
                make_flow_filter(FlowFilterContext::for_test(&built.overlay));

            // The overlay's own derived probes route by construction, which is where the NAT flags
            // actually get exercised; the generated probes supply the misses and the edges.
            let derived = built.routing_probes.iter().copied();
            let generated = probe_specs.iter().map(|spec| spec.resolve(built.blocks));
            for probe in derived.chain(generated) {
                let Some((pkt, probe)) = probe_packet(&probe) else {
                    continue;
                };
                let expected = expected_outcome(oracle_lookup(&built.overlay, &probe));
                assert_eq!(
                    observed_outcome(&run(&mut flow_filter, pkt)),
                    expected,
                    "stamped metadata diverges from the configuration for {probe:?}\n\
                     spec: {overlay_spec:?}",
                );

                match expected {
                    NfOutcome::Dropped(_) => {
                        DROPPED.fetch_add(1, Ordering::Relaxed);
                    }
                    NfOutcome::Routed {
                        masquerade,
                        static_nat_src,
                        static_nat_dst,
                        port_forwarding,
                        flow_key,
                        ..
                    } => {
                        ROUTED.fetch_add(1, Ordering::Relaxed);
                        if masquerade || static_nat_src || static_nat_dst || port_forwarding {
                            NATTED.fetch_add(1, Ordering::Relaxed);
                        }
                        if flow_key {
                            FLOW_KEYED.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        });

    let (routed, natted) = (
        ROUTED.load(Ordering::Relaxed),
        NATTED.load(Ordering::Relaxed),
    );
    let (flow_keyed, dropped) = (
        FLOW_KEYED.load(Ordering::Relaxed),
        DROPPED.load(Ordering::Relaxed),
    );
    eprintln!(
        "coverage: {routed} routed ({natted} with a NAT requirement, \
         {flow_keyed} retaining a flow key), {dropped} dropped"
    );
    assert!(routed >= 1, "no packet was ever routed");
    assert!(natted >= 1, "no route ever carried a NAT requirement");
    assert!(flow_keyed >= 1, "the flow-key case was never reached");
    assert!(dropped >= 1, "no packet was ever dropped");
}

// -------------------------------------------------------------------------------------------------
// Adversarial header stacks.
//
// `classify` is this NF's parser-facing edge -- it is the only place that reaches into a packet's
// headers -- and every test above it feeds exactly four hand-built shapes (v4 TCP/UDP/ICMP and a
// bare Ethernet frame). Nothing exercised a VLAN tag, an IPv6 extension-header chain, a fragment,
// an authentication header, or the fuzzed remainder of any header's fields.
//
// `net` already ships a bolero header-stack generator; this points it at the NF. What the test can
// honestly claim is bounded: `probe_from_packet` extracts the lookup key with the same public
// accessors `classify` uses, so this does not independently verify that extraction. Its value is
// that (a) no header stack the generator can build makes the NF panic, (b) the fail-closed and
// burst-structural invariants hold on stacks nobody hand-picked, and (c) the route -> metadata
// mapping still holds for keys that *only* exotic stacks produce -- an extension-header protocol
// number, a portless IP packet, a fragment. Those keys are unreachable from the four hand-built
// shapes, and they are what the coverage counters below insist on reaching.

mod adversarial_headers {
    use super::{
        NfOutcome, expected_outcome, make_flow_filter, observed_outcome, probe_from_packet,
    };
    use crate::context::FlowFilterContext;
    use crate::context::fuzz::oracle_lookup;
    use crate::test_utils::{expose, expose_masquerade, expose_static, overlay, peering, vpcd};
    use bolero::{Driver, ValueGenerator};
    use concurrency::sync::LazyLock;
    use concurrency::sync::atomic::{AtomicU64, Ordering};
    use config::external::overlay::ValidatedOverlay;
    use net::buffer::TestBuffer;
    use net::headers::Headers;
    use net::headers::builder::ChainBase;
    use net::ip::NextHeader;
    use net::ipv4::UnicastIpv4Addr;
    use net::ipv6::UnicastIpv6Addr;
    use net::packet::{DoneReason, Packet, VpcDiscriminant};
    use net::parse::DeParse;
    use pipeline::NetworkFunction;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The source VPC every generated packet claims.
    fn src_vpcd() -> VpcDiscriminant {
        vpcd(100)
    }

    /// A two-peering overlay whose prefixes the generated stacks aim at: a v4 peering carrying one
    /// expose of each source NAT mode, and a v6 peering so the v6 stacks have somewhere to land.
    /// Both manifests of a peering are single-version, as validation requires.
    fn wire_overlay() -> ValidatedOverlay {
        overlay(
            &[("vpc1", 100), ("vpc2", 200), ("vpc3", 300)],
            vec![
                peering(
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
                ),
                peering(
                    "vpc1-to-vpc3",
                    ("vpc1", vec![expose("2001:db8::/32")]),
                    ("vpc3", vec![expose("2001:db9::/32")]),
                ),
            ],
        )
    }

    // Address pinning. Every other field of every header stays fuzzed; only the addresses are
    // steered, because a uniformly random address never lands in a configured prefix and the whole
    // run would collapse into destination misses. The fuzzed low byte is kept, so host selection
    // (and with it the port-range and prefix-length edges) still comes from the driver.

    fn pin_v4(ip: &mut net::ipv4::Ipv4) {
        let src = ip.source().inner().octets();
        // 1/2/3 are the plain, static-NAT and masquerade source exposes; 4 is covered by none.
        let src_net = src[0] % 4 + 1;
        ip.set_source(
            UnicastIpv4Addr::new(Ipv4Addr::new(src_net, 0, 0, src[3]))
                .unwrap_or_else(|e| unreachable!("pinned v4 source is unicast: {e:?}")),
        );
        let dst = ip.destination().octets();
        // 5 is the peer's expose; 9 is nowhere.
        let dst_net = if dst[0].is_multiple_of(4) { 9 } else { 5 };
        ip.set_destination(Ipv4Addr::new(dst_net, 0, 0, dst[3]));
    }

    fn pin_v6(ip: &mut net::ipv6::Ipv6) {
        let src = ip.source().inner().octets();
        ip.set_source(
            UnicastIpv6Addr::new(Ipv6Addr::new(
                0x2001,
                0x0db8,
                0,
                0,
                0,
                0,
                0,
                u16::from(src[15]),
            ))
            .unwrap_or_else(|e| unreachable!("pinned v6 source is unicast: {e:?}")),
        );
        let dst = ip.destination().octets();
        // Half the destinations land in the peer's expose, half nowhere near it.
        let net = if dst[0].is_multiple_of(4) {
            0x0dbf
        } else {
            0x0db9
        };
        ip.set_destination(Ipv6Addr::new(
            0x2001,
            net,
            0,
            0,
            0,
            0,
            0,
            u16::from(dst[15]),
        ));
    }

    /// One header stack per shape. Each is its own concrete generator type (`ValueGenerator` has a
    /// generic method and so is not object-safe), which is why this dispatches through a `match`
    /// rather than a table of boxed generators.
    struct AnyStack;

    impl ValueGenerator for AnyStack {
        type Output = Headers;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Headers> {
            match driver.produce::<u8>()? % 10 {
                // No IP layer at all: the NotIp path.
                0 => ChainBase::new().eth(|_| {}).generate(driver),
                1 => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(pin_v4)
                    .tcp(|_| {})
                    .generate(driver),
                2 => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(pin_v4)
                    .udp(|_| {})
                    .generate(driver),
                3 => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(pin_v4)
                    .icmp4(|_| {})
                    .generate(driver),
                // A VLAN tag between the Ethernet and IP layers.
                4 => ChainBase::new()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(pin_v4)
                    .tcp(|_| {})
                    .generate(driver),
                // An IPv4 authentication header ahead of the transport.
                5 => ChainBase::new()
                    .eth(|_| {})
                    .ipv4(pin_v4)
                    .ipv4_auth(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                6 => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(pin_v6)
                    .tcp(|_| {})
                    .generate(driver),
                7 => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(pin_v6)
                    .udp(|_| {})
                    .generate(driver),
                // IPv6 extension-header chains, ahead of a transport header.
                8 => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(pin_v6)
                    .hop_by_hop(|_| {})
                    .tcp(|_| {})
                    .generate(driver),
                9 => ChainBase::new()
                    .eth(|_| {})
                    .ipv6(pin_v6)
                    .fragment(|_| {})
                    .udp(|_| {})
                    .generate(driver),
                _ => unreachable!("modulo 10"),
            }
        }
    }

    /// Serialize generated headers into a parseable overlay packet. Returns `None` when the stack
    /// cannot round-trip through a `TestBuffer` (too large, or not re-parseable) -- those are
    /// counted, so a run that silently discarded everything cannot pass.
    fn wire_packet(headers: &Headers) -> Option<Packet<TestBuffer>> {
        let mut buffer = TestBuffer::new();
        headers.deparse(buffer.as_mut()).ok()?;
        let mut packet = Packet::new(buffer).ok()?;
        packet.meta_mut().set_overlay(true);
        packet.meta_mut().src_vpcd = Some(src_vpcd());
        Some(packet)
    }

    /// However exotic the headers, a flowless packet leaves the NF with exactly the metadata the
    /// configuration predicts for the key that packet presents -- and a packet with no IP layer is
    /// dropped as `NotIp` without ever reaching the tables.
    #[test]
    fn arbitrary_header_stacks_uphold_the_config_contract() {
        // Lazily initialized so this compiles under the loom backend, whose AtomicU64::new is not
        // const.
        static UNPARSEABLE: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static NOT_IP: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static PORTLESS: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static EXOTIC_PROTO: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static ROUTED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));
        static DROPPED: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(0));

        let overlay = wire_overlay();

        bolero::check!()
            .with_generator(AnyStack)
            .for_each(|headers: &Headers| {
                // Built inside the closure: the filter holds a classifier, which is not unwind-safe
                // and so cannot be captured across bolero's catch_unwind boundary.
                let (mut flow_filter, _writer) =
                    make_flow_filter(FlowFilterContext::for_test(&overlay));

                let Some(packet) = wire_packet(headers) else {
                    UNPARSEABLE.fetch_add(1, Ordering::Relaxed);
                    return;
                };

                // Extract the key before the NF consumes the packet.
                let probe = probe_from_packet(&packet, src_vpcd());
                if let Some(probe) = probe.as_ref() {
                    if probe.ports.is_none() {
                        PORTLESS.fetch_add(1, Ordering::Relaxed);
                    }
                    if !matches!(
                        probe.proto,
                        NextHeader::TCP | NextHeader::UDP | NextHeader::ICMP | NextHeader::ICMP6
                    ) {
                        EXOTIC_PROTO.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    NOT_IP.fetch_add(1, Ordering::Relaxed);
                }

                let out = flow_filter
                    .process([packet].into_iter())
                    .next()
                    .unwrap_or_else(|| unreachable!("enforce keeps Filtered and NotIp packets"));

                let expected = match probe.as_ref() {
                    // No IP layer: dropped before any table is consulted.
                    None => NfOutcome::Dropped(Some(DoneReason::NotIp)),
                    Some(probe) => expected_outcome(oracle_lookup(&overlay, probe)),
                };
                assert_eq!(
                    observed_outcome(&out),
                    expected,
                    "NF diverged from the configuration on {headers:?}",
                );

                match expected {
                    NfOutcome::Routed { .. } => ROUTED.fetch_add(1, Ordering::Relaxed),
                    NfOutcome::Dropped(_) => DROPPED.fetch_add(1, Ordering::Relaxed),
                };
            });

        let counts = [
            ("unparseable", &UNPARSEABLE),
            ("not-IP", &NOT_IP),
            ("portless IP", &PORTLESS),
            ("non-transport proto", &EXOTIC_PROTO),
            ("routed", &ROUTED),
            ("dropped", &DROPPED),
        ]
        .map(|(label, counter)| (label, counter.load(Ordering::Relaxed)));
        eprintln!(
            "coverage: {}",
            counts
                .iter()
                .map(|(label, n)| format!("{n} {label}"))
                .collect::<Vec<_>>()
                .join(", ")
        );

        // The point of the suite is the keys the hand-built shapes cannot produce. If the generator
        // stops reaching them -- or starts failing to round-trip everything -- this must fail
        // rather than pass on a diet of ordinary v4 TCP.
        for (label, count) in counts {
            if label == "unparseable" {
                continue;
            }
            assert!(count >= 1, "no {label} packet was ever generated");
        }
    }
}

// -------------------------------------------------------------------------------------------------
// Documented behaviour: IPv6 extension headers hide the transport protocol.
//
// Found by the adversarial-header suite above, which reaches these keys in the thousands per run.
// Pinned here as its own test because a fuzz run that merely agrees with the config oracle does not
// say *what* the configuration means for these packets, and the answer is surprising enough that a
// future change to it should be deliberate.

/// `Net::next_header()` reports the IPv6 header's own next-header field. When any extension header
/// is present that field names the *extension*, not the transport -- while `try_transport()` still
/// walks the chain and finds the real ports.
///
/// So an IPv6 packet carrying TCP behind a hop-by-hop header presents the lookup key
/// `(proto = HOPOPT, ports = the TCP ports)`. A protocol-restricted expose lowers to an exact match
/// on the protocol byte, so it cannot match such a packet, and the traffic is dropped rather than
/// port-forwarded. That is fail-closed, but it is a functional gap: legitimate TCP over IPv6 with
/// extension headers does not reach a TCP-restricted port-forwarding destination.
#[test]
fn ipv6_extension_header_masks_the_transport_protocol() {
    use net::headers::builder::HeaderStack;
    use net::headers::{TryIp, TryTransport};
    use net::ipv6::UnicastIpv6Addr;
    use net::tcp::TcpPort;

    let with_hop_by_hop = || {
        HeaderStack::new()
            .eth(|_| {})
            .ipv6(|ip| {
                ip.set_source(UnicastIpv6Addr::new(v6("2001:db8::1")).unwrap());
                ip.set_destination(v6("2001:db9::5"));
            })
            .hop_by_hop(|_| {})
            .tcp(|tcp| {
                tcp.set_source(TcpPort::try_from(1234u16).unwrap());
                tcp.set_destination(TcpPort::try_from(80u16).unwrap());
            })
            .build_headers()
            .unwrap()
    };

    // The mechanism: the protocol byte names the extension header, but the ports are still found.
    let probe_packet = packet(Some(vpcd(100)), with_hop_by_hop());
    let net = probe_packet.try_ip().unwrap();
    assert_eq!(
        net.next_header(),
        net::ip::NextHeader::new(0),
        "an extension header should occupy the next-header field",
    );
    assert_eq!(
        probe_packet
            .try_transport()
            .and_then(|t| t.dst_port())
            .map(std::num::NonZero::get),
        Some(80),
        "the transport header is still reachable behind the extension header",
    );

    // The consequence: a TCP-restricted destination expose cannot match it.
    let tcp_only = context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("2001:db8::/32")]),
            (
                "vpc2",
                vec![expose_port_forwarding(
                    "2001:db9::5/128",
                    (22, 22),
                    "2001:db9::5/128",
                    (80, 80),
                    Some(L4Protocol::Tcp),
                )],
            ),
        )],
    );
    let (mut flow_filter, _writer) = make_flow_filter(tcp_only);
    let out = run(&mut flow_filter, packet(Some(vpcd(100)), with_hop_by_hop()));
    assert_eq!(
        out.get_done(),
        Some(DoneReason::Filtered),
        "a TCP-restricted expose does not see this packet as TCP, so nothing covers it",
    );

    // The same packet routes when the covering expose is not protocol-restricted, which confirms
    // the protocol byte -- not the address or the port -- is what excluded it above.
    let any_proto = context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("2001:db8::/32")]),
            ("vpc2", vec![expose("2001:db9::/32")]),
        )],
    );
    let (mut flow_filter, _writer) = make_flow_filter(any_proto);
    let out = run(&mut flow_filter, packet(Some(vpcd(100)), with_hop_by_hop()));
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
}
