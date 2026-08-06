// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tests for the routing context build and lookup.

#![cfg(test)]

use super::LookupResult;
use super::tables::RuleRow;
use crate::test_utils::*;
use crate::{FlowFilterContext, NatMode, NatRequirement};
use lpm::prefix::L4Protocol;
use net::headers::Headers;
use net::packet::VpcDiscriminant;
use std::num::NonZero;

// Wrapper for the result of a lookup
#[derive(Debug, PartialEq, Eq)]
struct Route {
    dst_vpcd: VpcDiscriminant,
    dst_nat: NatMode,
    src_nat: NatMode,
}

// Extract the 5-tuple from headers (as the pipeline does) and run the route lookup for a packet
// originating from a given source VPC.
fn route(
    context: &FlowFilterContext,
    src_vpcd: VpcDiscriminant,
    headers: &Headers,
) -> Option<Route> {
    route_revalidate(context, src_vpcd, None, headers)
}

// Extract the 5-tuple from headers (as the pipeline does) and run the route lookup for a packet
// originating from a given source VPC.
fn route_revalidate(
    context: &FlowFilterContext,
    src_vpcd: VpcDiscriminant,
    dst_vpcd: Option<VpcDiscriminant>,
    headers: &Headers,
) -> Option<Route> {
    let net = headers.net().unwrap();
    let src_ip = net.src_addr();
    let dst_ip = net.dst_addr();
    let proto = net.next_header();
    let ports = headers.transport().and_then(|t| {
        t.src_port()
            .map(NonZero::get)
            .zip(t.dst_port().map(NonZero::get))
    });
    match context.lookup(src_vpcd, dst_vpcd, src_ip, dst_ip, proto, ports) {
        LookupResult::Route((dst_vpcd, dst_nat, src_nat)) => Some(Route {
            dst_vpcd,
            dst_nat,
            src_nat,
        }),
        LookupResult::SourceMiss(_) | LookupResult::DestinationMiss => None,
    }
}

// -------------------------------------------------------------------------------------------------
// General-purpose overlay reused across various tests:
//
// - vpc1 <-> vpc2: vpc1 exposes 1.0.0.0/24; vpc2 exposes 5.0.0.0/24 + a default.
// - vpc1 <-> vpc3: vpc1 exposes 1.0.0.0/24 and 2.0.0.0/24; vpc3 exposes 6.0.0.0/24.
//
// Note the overlap on vpc1's source prefix 1.0.0.0/24, shared by both peerings but towards distinct
// destination VPCs.

fn routing_overlay() -> FlowFilterContext {
    context(
        &[("vpc1", 100), ("vpc2", 200), ("vpc3", 300)],
        vec![
            peering(
                "vpc1-to-vpc2",
                ("vpc1", vec![expose("1.0.0.0/24")]),
                ("vpc2", vec![expose("5.0.0.0/24"), expose_default()]),
            ),
            peering(
                "vpc1-to-vpc3",
                ("vpc1", vec![expose("1.0.0.0/24"), expose("2.0.0.0/24")]),
                ("vpc3", vec![expose("6.0.0.0/24")]),
            ),
        ],
    )
}

#[test]
fn build_context_smoke() {
    let ctx = routing_overlay();
    assert!(
        route(
            &ctx,
            vpcd(100),
            &build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678)
        )
        .is_some()
    );
}

#[test]
fn packet_allowed() {
    let ctx = routing_overlay();
    let r = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    )
    .expect("packet should be allowed");
    assert_eq!(r.dst_vpcd, vpcd(200));
    assert_eq!(r.dst_nat, None);
    assert_eq!(r.src_nat, None);
}

#[test]
fn packet_filtered_when_source_prefix_unmatched() {
    let ctx = routing_overlay();
    // Destination 5.0.0.10 resolves to vpc2, but 9.9.9.9 is not in any source prefix vpc1 exposes
    // towards vpc2 (which has no default on the local side).
    let r = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("9.9.9.9"), v4("5.0.0.10"), 1234, 5678),
    );
    assert_eq!(r, None);
}

#[test]
fn packet_filtered_for_unknown_source_vpc() {
    let ctx = routing_overlay();
    let r = route(
        &ctx,
        vpcd(999),
        &build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    );
    assert_eq!(r, None);
}

#[test]
fn default_remote_expose_is_catch_all() {
    let ctx = routing_overlay();
    // 99.0.0.10 matches no specific remote prefix; vpc2's default expose catches it
    let r = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("1.0.0.5"), v4("99.0.0.10"), 1234, 5678),
    )
    .expect("default expose should match");
    assert_eq!(r.dst_vpcd, vpcd(200));
    assert_eq!(r.dst_nat, None);
    assert_eq!(r.src_nat, None);
}

#[test]
fn overlapping_source_prefix_disambiguated_by_destination() {
    let ctx = routing_overlay();
    // Same source 1.0.0.5 is valid towards both vpc2 and vpc3; the destination prefix decides which
    // peering applies
    let to_vpc2 = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("1.0.0.5"), v4("5.0.0.10"), 1234, 5678),
    )
    .unwrap();
    assert_eq!(to_vpc2.dst_vpcd, vpcd(200));

    let to_vpc3 = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("1.0.0.5"), v4("6.0.0.10"), 1234, 5678),
    )
    .unwrap();
    assert_eq!(to_vpc3.dst_vpcd, vpcd(300));

    // 2.0.0.5 is only exposed towards vpc3, so it must not resolve towards vpc2
    let only_vpc3 = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("2.0.0.5"), v4("6.0.0.10"), 1234, 5678),
    )
    .unwrap();
    assert_eq!(only_vpc3.dst_vpcd, vpcd(300));
    assert_eq!(
        route(
            &ctx,
            vpcd(100),
            &build_tcp_packet(v4("2.0.0.5"), v4("5.0.0.10"), 1234, 5678),
        ),
        None,
    );
}

// -------------------------------------------------------------------------------------------------
// NAT modes.
//
// We pin down which NAT requirement is returned for each end of a lookup. The source (local) end
// carries private IPs; the destination (remote) end carries public IPs. Masquerade is only valid on
// the source side (a masquerade destination cannot receive connections) and port forwarding only on
// the destination side (a port-forwarding source cannot initiate connections); these constraints
// are tested in `dst_side_nat_modes`.

fn nat_modes_overlay() -> FlowFilterContext {
    context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            (
                "vpc1",
                vec![
                    expose("1.0.0.0/24"),                           // no NAT
                    expose_static("2.0.0.0/24", "20.0.0.0/24"),     // static NAT
                    expose_masquerade("3.0.0.0/24", "30.0.0.0/24"), // masquerade
                ],
            ),
            (
                "vpc2",
                vec![
                    expose("5.0.0.0/24"),                       // no NAT
                    expose_static("6.0.0.0/24", "60.0.0.0/24"), // static NAT
                    expose_default(),                           // default (no NAT)
                ],
            ),
        )],
    )
}

#[test]
fn nat_modes_source_and_destination() {
    let ctx = nat_modes_overlay();
    let lookup = |src: &str, dst: &str| {
        route(
            &ctx,
            vpcd(100),
            &build_tcp_packet(v4(src), v4(dst), 1234, 5678),
        )
        .unwrap()
    };

    // (src NAT, dst NAT) for valid combinations. Source carries private IPs, destination carries
    // public IPs.
    let none_none = lookup("1.0.0.5", "5.0.0.10");
    assert_eq!(none_none.src_nat, None);
    assert_eq!(none_none.dst_nat, None);

    let static_static = lookup("2.0.0.5", "60.0.0.10");
    assert_eq!(static_static.src_nat, Some(NatRequirement::Static));
    assert_eq!(static_static.dst_nat, Some(NatRequirement::Static));

    let masq_none = lookup("3.0.0.5", "5.0.0.10");
    assert_eq!(masq_none.src_nat, Some(NatRequirement::Masquerade));
    assert_eq!(masq_none.dst_nat, None);

    let none_static = lookup("1.0.0.5", "60.0.0.10");
    assert_eq!(none_static.src_nat, None);
    assert_eq!(none_static.dst_nat, Some(NatRequirement::Static));

    let static_none = lookup("2.0.0.5", "5.0.0.10");
    assert_eq!(static_none.src_nat, Some(NatRequirement::Static));
    assert_eq!(static_none.dst_nat, None);

    // Masquerade source towards the default (no-NAT) destination.
    let masq_default = lookup("3.0.0.5", "99.0.0.10");
    assert_eq!(masq_default.dst_vpcd, vpcd(200));
    assert_eq!(masq_default.src_nat, Some(NatRequirement::Masquerade));
    assert_eq!(masq_default.dst_nat, None);
}

// Destination-side NAT: a masquerade destination is filtered (cannot receive
// connections); a port-forwarding destination is returned. Source side is plain.
fn dst_side_overlay() -> FlowFilterContext {
    context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("10.0.0.0/24")]),
            (
                "vpc2",
                vec![
                    expose("90.0.0.0/24"),
                    expose_masquerade("192.168.70.0/24", "70.0.0.0/24"),
                    expose_port_forwarding(
                        "192.168.80.5/32",
                        (22, 22),
                        "80.0.0.5/32",
                        (2222, 2222),
                        Some(L4Protocol::Tcp),
                    ),
                ],
            ),
        )],
    )
}

#[test]
fn dst_side_nat_modes() {
    let ctx = dst_side_overlay();

    // Masquerade destination: resolves at table level as a marker (the NF only lets it through
    // for reply traffic on an established masquerade flow; see crate::tests)
    let masq = route_revalidate(
        &ctx,
        vpcd(100),
        Some(vpcd(200)),
        &build_tcp_packet(v4("10.0.0.5"), v4("70.0.0.10"), 1234, 5678),
    )
    .expect("masquerade destination resolves as a marker");
    assert_eq!(masq.dst_vpcd, vpcd(200));
    assert_eq!(masq.dst_nat, Some(NatRequirement::Masquerade));

    // Port-forwarding destination (matching proto + port): returned
    let pf = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
    )
    .expect("port forwarding destination should match");
    assert_eq!(pf.dst_vpcd, vpcd(200));
    assert_eq!(pf.dst_nat, Some(NatRequirement::PortForwarding));
    assert_eq!(pf.src_nat, None);

    // Port-forwarding destination, wrong port: no match.
    assert_eq!(
        route(
            &ctx,
            vpcd(100),
            &build_tcp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 9999),
        ),
        None,
    );
}

// -------------------------------------------------------------------------------------------------
// L4 protocols, including ICMP. Port-forwarding restricted to TCP must not match UDP or ICMP; plain
// (no-NAT) exposes match all protocols.

#[test]
fn protocol_awareness() {
    let ctx = dst_side_overlay();

    // Plain destination 90.0.0.10 is reachable over TCP, UDP and ICMP
    for headers in [
        build_tcp_packet(v4("10.0.0.5"), v4("90.0.0.10"), 1234, 5678),
        build_udp_packet(v4("10.0.0.5"), v4("90.0.0.10"), 1234, 5678),
        build_icmp_packet(v4("10.0.0.5"), v4("90.0.0.10")),
    ] {
        let r = route(&ctx, vpcd(100), &headers).expect("plain expose matches any protocol");
        assert_eq!(r.dst_vpcd, vpcd(200));
        assert_eq!(r.dst_nat, None);
    }

    // TCP packet matches the TCP-only port-forwarding destination
    let r = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
    )
    .expect("TCP port-forwarding destination should match");
    assert_eq!(r.dst_vpcd, vpcd(200));
    assert_eq!(r.src_nat, None);
    assert_eq!(r.dst_nat, Some(NatRequirement::PortForwarding));

    // TCP-only port forwarding: a UDP packet in the same range does not match
    assert_eq!(
        route(
            &ctx,
            vpcd(100),
            &build_udp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
        ),
        None,
    );

    // ICMP has no ports and cannot match a port-forwarding (port-keyed) entry
    assert_eq!(
        route(
            &ctx,
            vpcd(100),
            &build_icmp_packet(v4("10.0.0.5"), v4("80.0.0.5")),
        ),
        None,
    );
}

// -------------------------------------------------------------------------------------------------
// Source-side default expose

#[test]
fn source_default_expose_is_catch_all() {
    // vpc1 (source) has a default expose, so a source IP outside its specific prefix still resolves
    // (the destination must still match a remote prefix).
    let ctx = context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("1.0.0.0/24"), expose_default()]),
            ("vpc2", vec![expose("5.0.0.0/24")]),
        )],
    );
    let r = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("9.9.9.9"), v4("5.0.0.10"), 1234, 5678),
    )
    .expect("local default expose should match the source");
    assert_eq!(r.dst_vpcd, vpcd(200));
    assert_eq!(r.src_nat, None);
    assert_eq!(r.dst_nat, None);
}

// -------------------------------------------------------------------------------------------------
// Any-protocol port forwarding matches TCP and UDP alike

#[test]
fn port_forwarding_any_protocol_matches_tcp_and_udp() {
    let ctx = context(
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
                    None, // any protocol
                )],
            ),
        )],
    );
    for headers in [
        build_tcp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
        build_udp_packet(v4("10.0.0.5"), v4("80.0.0.5"), 1234, 2222),
    ] {
        let r = route(&ctx, vpcd(100), &headers).expect("any-protocol port forwarding matches");
        assert_eq!(r.dst_vpcd, vpcd(200));
        assert_eq!(r.dst_nat, Some(NatRequirement::PortForwarding));
    }
}

// -------------------------------------------------------------------------------------------------
// Port forwarding is excluded from the source side (it cannot initiate connections). With both a
// masquerade and a port-forwarding expose on the source manifest, a source in the port-forwarding
// range is matched by masquerade instead.

#[test]
fn source_port_forwarding_is_excluded_and_falls_back_to_masquerade() {
    let ctx = context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            (
                "vpc1",
                vec![
                    expose_masquerade("1.0.0.0/24", "100.0.0.0/24"),
                    expose_port_forwarding(
                        "1.0.0.27/32",
                        (2000, 2001),
                        "100.0.0.27/32",
                        (3000, 3001),
                        Some(L4Protocol::Tcp),
                    ),
                ],
            ),
            ("vpc2", vec![expose("5.0.0.0/24")]),
        )],
    );
    // Source 1.0.0.27:2000 is inside the port-forwarding private range, yet resolves to masquerade.
    let r = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("1.0.0.27"), v4("5.0.0.10"), 2000, 5678),
    )
    .expect("source resolves via the masquerade expose");
    assert_eq!(r.dst_vpcd, vpcd(200));
    assert_eq!(r.src_nat, Some(NatRequirement::Masquerade));
    assert_eq!(r.dst_nat, None);
}

// -------------------------------------------------------------------------------------------------
// IPv6

#[test]
fn ipv6_lookup() {
    let ctx = context(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("2001:db8::/32")]),
            ("vpc2", vec![expose("2001:db9::/32")]),
        )],
    );
    let r = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet_v6(v6("2001:db8::1"), v6("2001:db9::1"), 1234, 5678),
    )
    .expect("IPv6 packet should be allowed");
    assert_eq!(r.dst_vpcd, vpcd(200));

    // An address outside the exposed prefixes is filtered
    assert_eq!(
        route(
            &ctx,
            vpcd(100),
            &build_tcp_packet_v6(v6("2001:db8::1"), v6("2001:dba::1"), 1234, 5678),
        ),
        None,
    );
}

// -------------------------------------------------------------------------------------------------
// Non-regression test: a prior implementation of the flow-filter stage used to have a bug. For a
// setup with:
//
// - vpc2 and vpc3 exposing overlapping prefixes to vpc1, and
// - vpc3's exposed prefixes being contained within vpc2's exposed prefixes to vpc1, and
// - vpc2's exposed prefixes containing contiguous prefixes that could be merged into a single
//   parent prefix,
//
// then we would merge entries in the temporary list of overlapping prefixes used to compute table
// entries, resulting in a discrepency between (merged) prefixes for vpc2's context and (split)
// prefixes for vpc3's context. In our example here, the context table would contain, for source
// vpc1, among other entries, one entry for 10.0.2.0/31 (dst: vpc2), and additional entries for
// 10.0.2.2/32 plus 10.0.2.3/32 (dst: vpc3), instead of one single block for 10.0.2.2/31 and
// multiple destination matches. This would result in the flow-filter picking always the same
// incomplete entry and failing to find the destination VPC for some IPs with multiple matching
// entries (there should never have been multiple matching entries in the context table).
//
// The current implementation works differently and does not rely on splitting/merging prefixes, but
// we keep this test anyway to be sure this doesn't reproduce.
#[test]
fn discrepancy_overlapping_contiguous_prefixes() {
    let ctx = context(
        &[("vpc1", 100), ("vpc2", 200), ("vpc3", 300)],
        vec![
            peering(
                "vpc1-to-vpc2",
                ("vpc1", vec![expose("10.0.2.0/24")]),
                ("vpc2", vec![expose("20.0.0.0/24")]),
            ),
            peering(
                "vpc1-to-vpc3",
                (
                    "vpc1",
                    vec![expose_multi(&[
                        // Contiguous prefixes, which could also be expressed as a single parent
                        // prefix 10.0.2.2/31; and that are contained within 10.0.2.0/24 exposed
                        // to vpc1 by vpc2
                        "10.0.2.2/32",
                        "10.0.2.3/32",
                    ])],
                ),
                ("vpc3", vec![expose("30.0.0.0/24")]),
            ),
        ],
    );

    let r = route(
        &ctx,
        vpcd(100),
        &build_tcp_packet(v4("10.0.2.2"), v4("30.0.0.1"), 9999, 80),
    )
    .expect("request: single matching destination in table should be found based on src/dst IPs");
    assert_eq!(r.dst_vpcd, vpcd(300));
    assert_eq!(r.src_nat, None);
    assert_eq!(r.dst_nat, None);

    let r = route(
        &ctx,
        vpcd(300),
        &build_tcp_packet(v4("30.0.0.1"), v4("10.0.2.2"), 80, 9999),
    )
    .expect("reply: single matching destination in table should be found based on src/dst IPs");
    assert_eq!(r.dst_vpcd, vpcd(100));
    assert_eq!(r.src_nat, None);
    assert_eq!(r.dst_nat, None);

    // Check there are no /32 prefixes in the remote-side rules
    for RuleRow { rule, .. } in ctx.remote_v4.rules() {
        assert_ne!(rule.dst_ip.len, 32);
    }
    // Check there are no /32 prefixes in the local-side rules
    for RuleRow { rule, .. } in ctx.local_v4.rules() {
        assert_ne!(rule.src_ip.len, 32);
    }
}

// -------------------------------------------------------------------------------------------------
// Differential: the rte_acl (Dpdk) backend must agree with the reference oracle on every probe.
// This validates the wide-key encoding and the prefix-length priority scheme against real rte_acl.

#[test]
#[dpdk::with_eal]
fn reference_and_dpdk_backends_agree() {
    use super::tables::{Backend, FlowFilterContext};
    use net::ip::NextHeader;
    use std::net::IpAddr;

    // v4 peering (vpc1<->vpc2, with source static-NAT, a masquerade, a plain dst and a default
    // dst) and a v6 peering (vpc1<->vpc3) so all four tables are populated in both directions.
    // The masquerade expose additionally covers the stage-1 marker rules and the SourceMiss /
    // DestinationMiss distinction across backends.
    let ov = overlay(
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
                ("vpc2", vec![expose("5.0.0.0/24"), expose_default()]),
            ),
            peering(
                "vpc1-to-vpc3",
                ("vpc1", vec![expose("2001:db8::/32")]),
                ("vpc3", vec![expose("2001:db9::/32")]),
            ),
        ],
    );

    let reference = FlowFilterContext::build(&ov, Backend::Reference).expect("reference build");
    let dpdk = FlowFilterContext::build(&ov, Backend::Dpdk).expect("dpdk build");

    // (src vni, src ip, dst ip, protocol, optional (src, dst) ports)
    type Probe = (u32, IpAddr, IpAddr, NextHeader, Option<(u16, u16)>);
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let probes: &[Probe] = &[
        // v4 hits, NAT variants, protocol variants, default expose, and misses.
        (
            100,
            ip("1.0.0.5"),
            ip("5.0.0.10"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ),
        (
            100,
            ip("1.0.0.5"),
            ip("5.0.0.10"),
            NextHeader::UDP,
            Some((1234, 5678)),
        ),
        (100, ip("1.0.0.5"), ip("5.0.0.10"), NextHeader::ICMP, None),
        (
            100,
            ip("2.0.0.5"),
            ip("5.0.0.10"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ),
        (
            100,
            ip("1.0.0.5"),
            ip("99.0.0.10"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ), // default dst
        (
            100,
            ip("9.9.9.9"),
            ip("5.0.0.10"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ), // src miss
        (
            100,
            ip("1.0.0.5"),
            ip("6.6.6.6"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ), // caught by default
        (
            999,
            ip("1.0.0.5"),
            ip("5.0.0.10"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ), // unknown src vpc
        // masquerade: outbound from the masquerade source, and reply traffic toward the
        // masquerade public range (stage-1 marker rule).
        (
            100,
            ip("3.0.0.5"),
            ip("5.0.0.10"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ),
        (
            200,
            ip("5.0.0.10"),
            ip("30.0.0.5"),
            NextHeader::TCP,
            Some((5678, 1234)),
        ),
        (200, ip("5.0.0.10"), ip("30.0.0.5"), NextHeader::ICMP, None),
        // v6 hit + miss.
        (
            100,
            ip("2001:db8::1"),
            ip("2001:db9::1"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ),
        (
            100,
            ip("2001:db8::1"),
            ip("2001:dba::1"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ),
        // mixed IP version.
        (
            100,
            ip("1.0.0.5"),
            ip("2001:db9::1"),
            NextHeader::TCP,
            Some((1234, 5678)),
        ),
    ];

    for &(vni, src_ip, dst_ip, proto, ports) in probes {
        let src_vpcd = vpcd(vni);
        assert_eq!(
            reference.lookup(src_vpcd, None, src_ip, dst_ip, proto, ports),
            dpdk.lookup(src_vpcd, None, src_ip, dst_ip, proto, ports),
            "backends disagree on {src_ip} -> {dst_ip} ({proto:?}) from vni {vni}",
        );
    }

    // Batched lookup must agree with the single-lookup oracle AND across backends. Repeat the
    // probes past MAX_BATCH so the per-version chunking (32) runs multiple rte_acl calls.
    use super::tables::LookupInput;
    let inputs: Vec<LookupInput> = std::iter::repeat_n(probes, 5)
        .flatten()
        .map(|&(vni, src_ip, dst_ip, proto, ports)| LookupInput {
            src_vpcd: vpcd(vni),
            dst_vpcd: None,
            src_ip,
            dst_ip,
            proto,
            ports,
        })
        .collect();
    assert!(inputs.len() > 32, "want a multi-chunk batch");

    let mut ref_out = vec![LookupResult::DestinationMiss; inputs.len()];
    let mut dpdk_out = vec![LookupResult::DestinationMiss; inputs.len()];
    reference.lookup_batch(&inputs, &mut ref_out);
    dpdk.lookup_batch(&inputs, &mut dpdk_out);
    assert_eq!(ref_out, dpdk_out, "batched backends disagree");

    for (i, input) in inputs.iter().enumerate() {
        let single = reference.lookup(
            input.src_vpcd,
            input.dst_vpcd,
            input.src_ip,
            input.dst_ip,
            input.proto,
            input.ports,
        );
        assert_eq!(ref_out[i], single, "batched != single at index {i}");
    }
}

/// Retained typed rules must render identically across backends.
#[test]
#[dpdk::with_eal]
fn display_is_identical_across_backends() {
    use super::tables::{Backend, FlowFilterContext};

    let ov = overlay(
        &[("vpc1", 100), ("vpc2", 200)],
        vec![peering(
            "vpc1-to-vpc2",
            ("vpc1", vec![expose("10.0.0.0/24")]),
            (
                "vpc2",
                vec![
                    expose("90.0.0.0/24"),
                    expose_masquerade("192.168.70.0/24", "70.0.0.0/24"),
                    expose_port_forwarding(
                        "192.168.80.5/32",
                        (22, 22),
                        "80.0.0.5/32",
                        (2222, 2222),
                        Some(L4Protocol::Tcp),
                    ),
                ],
            ),
        )],
    );

    let reference = FlowFilterContext::build(&ov, Backend::Reference).expect("reference build");
    let dpdk = FlowFilterContext::build(&ov, Backend::Dpdk).expect("dpdk build");
    assert_eq!(reference.to_string(), dpdk.to_string());

    // Assert cell values without pinning widths, which depend on every value in the table.
    let dump = dpdk.to_string();

    // Every assertion below is scoped to one section. The four tables share column names and some
    // of their values, so a search over the whole dump answers with the first table's rows whatever
    // it was asked about, and the later tables go unchecked.
    //
    // A section heading is written at the left margin with its table indented under it, so a
    // section ends at the first line that is not indented. Finding the end that way means a test
    // that reads one section does not have to name the section that follows it.
    let section = |heading: &str| -> String {
        let mut lines = dump.lines().skip_while(|line| !line.starts_with(heading));
        let head = lines
            .next()
            .unwrap_or_else(|| panic!("no {heading:?} section in:\n{dump}"));
        std::iter::once(head)
            .chain(lines.take_while(|line| line.starts_with("  ")))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let cells = |section: &str, prefix: &str| -> Vec<String> {
        section
            .lines()
            .find(|line| line.trim_start().starts_with(prefix))
            .unwrap_or_else(|| panic!("no row starting {prefix:?} in:\n{section}"))
            .split_whitespace()
            .map(str::to_string)
            .collect()
    };
    let remote_v4 = section("Remote v4");
    let local_v4 = section("Local v4");

    assert_eq!(
        cells(&remote_v4, "rank"),
        [
            "rank",
            "proto",
            "src-vni",
            "dst-vni",
            "destination",
            "dst-port",
            "|",
            "to",
            "NAT"
        ],
        "unexpected heading row:\n{remote_v4}"
    );
    assert_eq!(
        cells(&remote_v4, "[0]"),
        [
            "[0]",
            "TCP",
            "100",
            "0",
            "80.0.0.5/32",
            "2222",
            "|",
            "VNI(200)",
            "port-forwarding"
        ],
        "unexpected rule rendering:\n{remote_v4}"
    );

    // The local table too: its key carries a second VNI and its action is a bare NAT mode, so it
    // exercises a different `ActionColumns` impl.
    assert_eq!(
        cells(&local_v4, "rank"),
        [
            "rank", "proto", "src-vni", "dst-vni", "source", "src-port", "|", "NAT"
        ],
        "unexpected local heading row:\n{local_v4}"
    );

    // The heading assertions above would still pass if a section ran past its own table, since they
    // read its first heading row and stop. The ordering assertion below would not: it compares
    // positions, so a section that swallowed the table after it could order two rules that are not
    // even in the same table and call the result precedence. Pin the boundary directly -- `source`
    // is a local-table column, and the local table is the one that follows.
    assert!(
        !remote_v4.contains("source"),
        "the remote v4 section ran past its own table:\n{remote_v4}"
    );

    // The index is the operator-facing precedence claim -- `[0]` is consulted first -- so the dump
    // must read in match order. Within one table that is longest-prefix-first: the port-forwarding
    // /32 outranks the /24s it is nested among.
    let rank = |needle: &str| {
        remote_v4
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} missing from the remote v4 table:\n{remote_v4}"))
    };
    assert!(
        rank("80.0.0.5/32") < rank("70.0.0.0/24") && rank("80.0.0.5/32") < rank("90.0.0.0/24"),
        "rules are not rendered in precedence order:\n{remote_v4}"
    );
}
