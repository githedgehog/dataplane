// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tests for the DpdkAclClassifier facade.
//!
//! Verifies that the high-level API produces identical results to
//! the linear-scan reference classifier.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;

use acl::{
    AclRuleBuilder, AclTableBuilder, ActionSequence, Fate, FieldMatch,
    Ipv4Prefix, PortRange, Priority,
};
use dpdk::socket::SocketId;
use net::headers::builder::HeaderStack;
use net::tcp::port::TcpPort;
use net::udp::port::UdpPort;

use dataplane_acl_dpdk::classifier::DpdkAclClassifier;

mod common;

fn pri(n: u32) -> Priority {
    Priority::new(n).unwrap()
}

#[test]
fn facade_simple_permit_deny() {
    common::test_eal();

    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
                })
                .permit(pri(100)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
                })
                .deny(pri(50)),
        )
        .build();

    let dpdk = DpdkAclClassifier::compile(&table).unwrap();
    eprintln!("simple: sig={:?} cats={}", dpdk.signature(), dpdk.num_categories());

    // Also check via the raw path for comparison
    let groups = dataplane_acl_dpdk::compiler::compile(&table);
    eprintln!("raw groups: {} groups, field_count={}", groups.len(), groups.first().map(|g| g.field_count()).unwrap_or(0));

    let linear = table.compile();

    // 10.1.2.3:80 — matches both, pri 50 (deny) wins
    let pkt1 = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap());
        })
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    let dpdk_fate1 = dpdk.classify_fate(&pkt1);
    let linear_fate1 = linear.classify(&pkt1, &()).fate();
    eprintln!("pkt1: dpdk={dpdk_fate1:?} linear={linear_fate1:?} cats={}", dpdk.num_categories());
    assert_eq!(dpdk_fate1, Fate::Drop);
    assert_eq!(dpdk_fate1, linear_fate1);

    // 10.2.0.1:80 — matches /8 only → permit
    let pkt2 = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 2, 0, 1)).unwrap());
        })
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    assert_eq!(dpdk.classify_fate(&pkt2), Fate::Forward);
    assert_eq!(dpdk.classify_fate(&pkt2), linear.classify(&pkt2, &()).fate());

    // 192.168.1.1:80 — no match → default drop
    let pkt3 = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap());
        })
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    assert_eq!(dpdk.classify_fate(&pkt3), Fate::Drop);
    assert_eq!(dpdk.classify_fate(&pkt3), linear.classify(&pkt3, &()).fate());
}

#[test]
fn facade_mixed_signatures() {
    common::test_eal();

    // IPv4+TCP rule, IPv4-only rule, IPv4+UDP rule — three signatures.
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(PortRange::exact(80u16));
                })
                .permit(pri(2)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .permit(pri(1)), // highest priority — matches all 10.x traffic
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .udp(|udp| {
                    udp.dst = FieldMatch::Select(PortRange::exact(53u16));
                })
                .deny(pri(3)),
        )
        .build();

    let dpdk = DpdkAclClassifier::compile(&table).unwrap();
    let linear = table.compile();

    // TCP:80 from 10.x — matches IPv4-only (pri 1, Forward) and IPv4+TCP (pri 2, Forward).
    // Pri 1 wins → Forward.
    let tcp_pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap());
        })
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    assert_eq!(dpdk.classify_fate(&tcp_pkt), linear.classify(&tcp_pkt, &()).fate());

    // UDP:53 from 10.x — matches IPv4-only (pri 1, Forward) and IPv4+UDP (pri 3, Drop).
    // Pri 1 wins → Forward.
    let udp_pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap());
        })
        .udp(|udp| {
            udp.set_destination(UdpPort::new_checked(53).unwrap());
        })
        .build_headers()
        .unwrap();

    assert_eq!(dpdk.classify_fate(&udp_pkt), linear.classify(&udp_pkt, &()).fate());

    // 192.168.1.1 — no match → Drop.
    let no_match = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap());
        })
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    assert_eq!(dpdk.classify_fate(&no_match), Fate::Drop);
}
