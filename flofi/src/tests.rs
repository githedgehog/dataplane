// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! End-to-end tests for the `Flofi` network function.

#![cfg(test)]

use crate::Flofi;
use crate::context::FlofiContext;
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
    let flow_info = FlowInfo::new(flow_key, Instant::now() + Duration::from_secs(60));
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
    let flow_info = Arc::new(flow_info);
    packet.meta_mut().flow_info = Some(flow_info.clone());
    flow_info
}

fn make_flofi(ctx: FlofiContext) -> Flofi {
    Flofi::new("test-flofi".to_string(), ctx)
}

// Set the configuration generation id the filter compares flows against.
fn set_genid(flofi: &mut Flofi, genid: i64) {
    <Flofi as NetworkFunction<TestBuffer>>::set_data(flofi, Arc::new(PipelineData::new(genid)));
}

fn run(flofi: &mut Flofi, packet: Packet<TestBuffer>) -> Packet<TestBuffer> {
    flofi.process([packet].into_iter()).next().unwrap()
}

// vpc1 <-> vpc2: vpc1 (source side) exposes a plain prefix, a static-NAT prefix and a masquerade
// prefix; vpc2 (destination side) exposes a plain prefix.
fn source_nat_context() -> FlofiContext {
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
fn dst_port_forwarding_context() -> FlofiContext {
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
fn dst_static_context() -> FlofiContext {
    context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("10.0.0.0/24")]),
            ("vpc2", vec![expose_static("192.168.6.0/24", "60.0.0.0/24")]),
        )],
    )
}

// vpc1 <-> vpc2 over IPv6.
fn ipv6_context() -> FlofiContext {
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
    let mut flofi = make_flofi(source_nat_context());
    let out = run(
        &mut flofi,
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
    let mut flofi = make_flofi(source_nat_context());
    let out = run(
        &mut flofi,
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
    let mut flofi = make_flofi(source_nat_context());
    let out = run(
        &mut flofi,
        packet(
            None,
            build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ),
    );
    assert_eq!(out.get_done(), Some(DoneReason::Unroutable));
}

#[test]
fn non_overlay_packet_is_left_untouched() {
    let mut flofi = make_flofi(source_nat_context());
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    p.meta_mut().set_overlay(false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done());
    assert_eq!(out.meta().dst_vpcd, None);
}

#[test]
fn packet_with_destination_already_set_is_left_untouched() {
    let mut flofi = make_flofi(source_nat_context());
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    p.meta_mut().dst_vpcd = Some(vpcd(777));
    let out = run(&mut flofi, p);
    assert!(!out.is_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(777)));
}

#[test]
fn icmp_packet_is_allowed() {
    let mut flofi = make_flofi(source_nat_context());
    let out = run(
        &mut flofi,
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
    let mut flofi = make_flofi(source_nat_context());
    let out = run(
        &mut flofi,
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
    let mut flofi = make_flofi(source_nat_context());
    let out = run(
        &mut flofi,
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
    let mut flofi = make_flofi(dst_port_forwarding_context());

    // TCP packet into the port-forwarding range: allowed, flag set.
    let out = run(
        &mut flofi,
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
        &mut flofi,
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
    let mut flofi = make_flofi(source_nat_context());
    // Route itself requires no NAT, but the attached active flow carries masquerade state, so the
    // bypass path tags the packet for masquerade. Flow genid (0) matches the NF's default genid
    // (0), so the flow is considered up-to-date and is not invalidated.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, true, false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(out.meta().requires_masquerade());
    assert_eq!(flow.status(), FlowStatus::Active);
}

#[test]
fn outdated_flow_is_invalidated() {
    let mut flofi = make_flofi(source_nat_context());
    // Advance the configuration generation so the flow (genid 0) is outdated.
    set_genid(&mut flofi, 5);

    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    // The flow points at the wrong destination VPC for the current config.
    let flow = attach_flow(&mut p, Some(vpcd(300)), true, false, false);
    let out = run(&mut flofi, p);

    // The packet is re-evaluated from the tables (resolving to vpc2) and the stale flow is cancelled.
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

// -------------------------------------------------------------------------------------------------
// More NAT flags, protocols and batching

#[test]
fn static_nat_destination_sets_static_dst_flag() {
    let mut flofi = make_flofi(dst_static_context());
    let out = run(
        &mut flofi,
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
    let mut flofi = make_flofi(ipv6_context());
    let out = run(
        &mut flofi,
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
    let mut flofi = make_flofi(source_nat_context());
    let out = run(&mut flofi, packet(Some(vpcd(100)), build_nonip_packet()));
    assert_eq!(out.get_done(), Some(DoneReason::NotIp));
}

#[test]
fn batch_of_packets_is_processed_independently() {
    let mut flofi = make_flofi(source_nat_context());
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
    let out: Vec<_> = flofi.process(packets.into_iter()).collect();
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
    let mut flofi = make_flofi(source_nat_context());
    // No-NAT route, but the active flow carries port-forwarding state -> tagged for port forwarding.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, false, true);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(out.meta().requires_port_forwarding());
    assert_eq!(flow.status(), FlowStatus::Active);
}

#[test]
fn inactive_flow_state_is_not_honored() {
    let mut flofi = make_flofi(source_nat_context());
    // The flow carries masquerade state but is not active, so it must not be used to bypass the
    // filter: the packet is evaluated purely from the tables (no NAT) and the flow is left alone.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), false, true, false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert!(!out.meta().requires_masquerade());
    assert_ne!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn active_flow_without_destination_is_invalidated() {
    let mut flofi = make_flofi(source_nat_context());
    // An active, up-to-date flow that records no destination VPC is a bug: it is invalidated.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, None, true, false, false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(out.meta().dst_vpcd, Some(vpcd(200)));
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

// -------------------------------------------------------------------------------------------------
// Stateful flows: invalidation of outdated flows (each `should_invalidate_flow` branch)

#[test]
fn outdated_flow_that_no_longer_needs_state_is_invalidated() {
    // Outdated flow, correct destination, but the (no-NAT) route no longer requires any state.
    let mut flofi = make_flofi(source_nat_context());
    set_genid(&mut flofi, 5);
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, false, false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn outdated_flow_missing_masquerade_state_is_invalidated() {
    // Outdated flow, correct destination, route now requires masquerade, but the flow has no
    // masquerade state.
    let mut flofi = make_flofi(source_nat_context());
    set_genid(&mut flofi, 5);
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("3.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, false, false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_masquerade());
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn outdated_flow_missing_port_forwarding_state_is_invalidated() {
    // Outdated flow, correct destination, route now requires port forwarding, but the flow has no
    // port-forwarding state.
    let mut flofi = make_flofi(dst_port_forwarding_context());
    set_genid(&mut flofi, 5);
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, false, false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_port_forwarding());
    assert_eq!(flow.status(), FlowStatus::Cancelled);
}

#[test]
fn outdated_flow_with_consistent_state_is_kept() {
    // Outdated flow, correct destination, route requires masquerade and the flow already has
    // masquerade state: the filter cannot prove it stale, so it is left for the stateful NFs.
    let mut flofi = make_flofi(source_nat_context());
    set_genid(&mut flofi, 5);
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("3.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    let flow = attach_flow(&mut p, Some(vpcd(200)), true, true, false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_masquerade());
    assert_ne!(flow.status(), FlowStatus::Cancelled);
}

// -------------------------------------------------------------------------------------------------
// Stateful flows: flow-key attachment for the {masquerade|port-forwarding} + static-NAT combination

#[test]
fn flow_key_attached_for_stateful_plus_static_nat() {
    let mut flofi = make_flofi(source_nat_context());
    // Static-NAT source (from the route) combined with masquerade (from the up-to-date flow's
    // state) means the downstream NAT needs the original 5-tuple, so the flow key is attached.
    let mut p = packet(
        Some(vpcd(100)),
        build_tcp_packet(v4("2.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    attach_flow(&mut p, Some(vpcd(200)), true, true, false);
    let out = run(&mut flofi, p);
    assert!(!out.is_done(), "{:?}", out.get_done());
    assert!(out.meta().requires_static_nat());
    assert!(out.meta().requires_masquerade());
    assert!(out.meta().flow_key.is_some());
}
