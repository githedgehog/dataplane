// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tests for the routing context build and lookup.

#![cfg(test)]

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
    let net = headers.net().unwrap();
    let src_ip = net.src_addr();
    let dst_ip = net.dst_addr();
    let proto = net.next_header();
    let ports = headers.transport().and_then(|t| {
        t.src_port()
            .map(NonZero::get)
            .zip(t.dst_port().map(NonZero::get))
    });
    context
        .lookup_route(src_vpcd, src_ip, dst_ip, proto, ports)
        .map(|(dst_vpcd, dst_nat, src_nat)| Route {
            dst_vpcd,
            dst_nat,
            src_nat,
        })
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

    // Masquerade destination: excluded from the remote end -> filtered
    assert_eq!(
        route(
            &ctx,
            vpcd(100),
            &build_tcp_packet(v4("10.0.0.5"), v4("70.0.0.10"), 1234, 5678),
        ),
        None,
    );

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
// Differential: the rte_acl (Dpdk) backend must agree with the reference oracle on every probe.
// This validates the wide-key encoding and the prefix-length priority scheme against real rte_acl.

#[test]
#[dpdk::with_eal]
fn reference_and_dpdk_backends_agree() {
    use super::tables::{Backend, PeeringTables};
    use net::ip::NextHeader;
    use std::net::IpAddr;

    // v4 peering (vpc1<->vpc2, with source static-NAT, a plain dst and a default dst) and a v6
    // peering (vpc1<->vpc3) so all four tables are populated in both directions.
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

    let reference = PeeringTables::build(&ov, Backend::Reference).expect("reference build");
    let dpdk = PeeringTables::build(&ov, Backend::Dpdk).expect("dpdk build");

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
            reference.lookup(src_vpcd, src_ip, dst_ip, proto, ports),
            dpdk.lookup(src_vpcd, src_ip, dst_ip, proto, ports),
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
            src_ip,
            dst_ip,
            proto,
            ports,
        })
        .collect();
    assert!(inputs.len() > 32, "want a multi-chunk batch");

    let mut ref_out = vec![None; inputs.len()];
    let mut dpdk_out = vec![None; inputs.len()];
    reference.lookup_batch(&inputs, &mut ref_out);
    dpdk.lookup_batch(&inputs, &mut dpdk_out);
    assert_eq!(ref_out, dpdk_out, "batched backends disagree");

    for (i, input) in inputs.iter().enumerate() {
        let single = reference.lookup(
            input.src_vpcd,
            input.src_ip,
            input.dst_ip,
            input.proto,
            input.ports,
        );
        assert_eq!(ref_out[i], single, "batched != single at index {i}");
    }
}
