// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Boundary and edge-case tests for the DPDK ACL backend.
//!
//! These tests exercise:
//! - Priority limits (near DPDK's MAX_PRIORITY boundary)
//! - Large rule counts
//! - Extreme match values (all-zeros, all-ones prefixes/ports)
//! - Single-rule tables
//! - Default-fate-only tables (no rules)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;

use acl::{
    AclRuleBuilder, AclTableBuilder, ActionSequence, Fate, FieldMatch,
    IpPrefix, Ipv4Prefix, Priority,
};
use dpdk::acl::config::{AclBuildConfig, AclCreateParams};
use dpdk::acl::context::{AclContext, Built};
use dpdk::acl::rule::{AclField, Rule};
use dpdk::socket::SocketId;
use net::headers::builder::HeaderStack;
use net::headers::Headers;
use net::tcp::port::TcpPort;

use dataplane_acl_dpdk::compiler;
use dataplane_acl_dpdk::input;

mod common;

fn pri(n: u32) -> Priority {
    Priority::new(n).unwrap()
}

fn make_tcp_packet(src_ip: Ipv4Addr, dst_port: u16) -> Headers {
    HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            if let Ok(uip) = net::ipv4::UnicastIpv4Addr::new(src_ip) {
                ip.set_source(uip);
            }
        })
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(dst_port).unwrap());
        })
        .build_headers()
        .unwrap()
}

/// Build a DPDK ACL context from a table, asserting single signature group
/// with 4 fields (proto, eth_type, ipv4_src, tcp_dst).
fn build_context(table: &acl::AclTable) -> Option<(AclContext<4, Built>, acl::FieldSignature)> {
    let groups = compiler::compile(table);
    if groups.is_empty() {
        return None;
    }
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.field_count(), 4);

    const N: usize = 4;
    let max_rules = group.rules().len().max(1);
    let params =
        AclCreateParams::new::<N>("boundary_test", SocketId::ANY, max_rules as u32)
            .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    let rules: Vec<Rule<N>> = group
        .rules()
        .iter()
        .map(|cr| {
            let mut fields = [AclField::wildcard(); N];
            for (i, f) in cr.fields.iter().enumerate() {
                fields[i] = *f;
            }
            Rule {
                data: cr.data,
                fields,
            }
        })
        .collect();

    ctx.add_rules(&rules).expect("add rules");

    let mut field_defs = [group.field_defs()[0]; N];
    for (i, fd) in group.field_defs().iter().enumerate() {
        field_defs[i] = *fd;
    }
    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).expect("build context");

    Some((ctx, group.signature()))
}

fn assert_agree(table: &acl::AclTable, packets: &[Headers]) {
    let classifier = table.compile();

    let Some((dpdk_ctx, sig)) = build_context(table) else {
        for pkt in packets {
            assert_eq!(
                classifier.classify(pkt, &()).fate(),
                table.default_fate(),
            );
        }
        return;
    };

    for pkt in packets {
        let linear_fate = classifier.classify(pkt, &()).fate();

        let acl_input = input::assemble_compact_input(pkt, sig);
        let data = [acl_input.as_ptr()];
        let mut results = [0u32; 1];
        dpdk_ctx
            .classify(&data, &mut results, 1)
            .expect("classify");
        let dpdk_fate = compiler::resolve_fate(table, results[0], table.default_fate());

        assert_eq!(
            linear_fate, dpdk_fate,
            "linear vs DPDK disagree: linear={linear_fate:?}, dpdk={dpdk_fate:?} \
             (userdata={})",
            results[0],
        );
    }
}

// ---- Priority boundary tests ----

#[test]
fn priority_one_is_highest_precedence() {
    common::test_eal();

    // Priority 1 (our highest) should beat priority 2.
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .permit(pri(1)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .deny(pri(2)),
        )
        .build();

    let pkt = make_tcp_packet(Ipv4Addr::new(10, 0, 0, 1), 80);
    assert_agree(&table, &[pkt]);
}

#[test]
fn priorities_near_dpdk_max() {
    common::test_eal();

    // Priorities near DPDK's MAX_PRIORITY (536870911).
    // Our priority 536870910 should map to DPDK priority 1 (lowest).
    // Our priority 536870909 should map to DPDK priority 2.
    // They should still maintain relative ordering.
    let high_pri = 536870909u32;
    let low_pri = 536870910u32;

    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .permit(pri(high_pri)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .deny(pri(low_pri)),
        )
        .build();

    let pkt = make_tcp_packet(Ipv4Addr::new(10, 0, 0, 1), 80);
    assert_agree(&table, &[pkt]);
}

#[test]
fn priority_beyond_dpdk_max_clamps() {
    common::test_eal();

    // Priority > DPDK's MAX_PRIORITY. Our compiler clamps to 1.
    // Two rules beyond the limit will both get DPDK priority 1,
    // making their relative ordering undefined in DPDK.
    // This test documents the behavior — it may not preserve
    // our priority ordering for values above 536870911.
    let beyond = 536870912u32; // MAX + 1

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
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .permit(pri(beyond)),
        )
        .build();

    // Single rule should still work — it just gets DPDK priority 1.
    let pkt = make_tcp_packet(Ipv4Addr::new(10, 0, 0, 1), 80);
    assert_agree(&table, &[pkt]);
}

// ---- Extreme match values ----

#[test]
fn all_zeros_prefix() {
    common::test_eal();

    // 0.0.0.0/0 matches everything.
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(1..=65535);
                })
                .permit(pri(100)),
        )
        .build();

    let packets: Vec<Headers> = [
        (Ipv4Addr::new(0, 0, 0, 1), 1u16),
        (Ipv4Addr::new(10, 0, 0, 1), 80),
        (Ipv4Addr::new(255, 255, 255, 254), 65535),
    ]
    .iter()
    .map(|(ip, port)| make_tcp_packet(*ip, *port))
    .collect();

    assert_agree(&table, &packets);
}

#[test]
fn full_port_range() {
    common::test_eal();

    // Port range 0-65535 (full range).
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::from(Ipv4Addr::new(10, 0, 0, 1)),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(0..=65535);
                })
                .permit(pri(100)),
        )
        .build();

    let packets: Vec<Headers> = [1u16, 80, 443, 8080, 65535]
        .iter()
        .map(|port| make_tcp_packet(Ipv4Addr::new(10, 0, 0, 1), *port))
        .collect();

    assert_agree(&table, &packets);
}

#[test]
fn single_port_zero() {
    common::test_eal();

    // Port 0 is protocol-unusual but valid in our raw u16 model.
    // DPDK ACL Range type should handle min=0, max=0.
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(0u16..=0u16);
                })
                .permit(pri(100)),
        )
        .build();

    // We can't easily build a packet with dst_port=0 via TcpPort
    // (it may reject 0), so just test that compilation succeeds
    // and non-matching packets get the default.
    let pkt = make_tcp_packet(Ipv4Addr::new(10, 0, 0, 1), 80);
    assert_agree(&table, &[pkt]);
}

// ---- Scale tests ----

#[test]
fn fifty_rules() {
    common::test_eal();

    let mut builder = AclTableBuilder::new(Fate::Drop);
    for i in 0..50u32 {
        let third = (i % 256) as u8;
        let fourth = ((i / 256) % 256) as u8;
        builder.push_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::from(Ipv4Addr::new(10, 0, third, fourth)),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .action(
                    ActionSequence::just(if i % 2 == 0 {
                        Fate::Accept
                    } else {
                        Fate::Drop
                    }),
                    pri(i + 1),
                ),
        );
    }
    let table = builder.build();

    let packets: Vec<Headers> = (0..50u32)
        .map(|i| {
            let third = (i % 256) as u8;
            let fourth = ((i / 256) % 256) as u8;
            make_tcp_packet(Ipv4Addr::new(10, 0, third, fourth), 80)
        })
        .collect();

    assert_agree(&table, &packets);
}

#[test]
fn two_hundred_rules() {
    common::test_eal();

    let mut builder = AclTableBuilder::new(Fate::Drop);
    for i in 0..200u32 {
        let b2 = (i % 256) as u8;
        let b3 = ((i / 256) % 256) as u8;
        builder.push_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::from(Ipv4Addr::new(10, b3, b2, 1)),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .action(
                    ActionSequence::just(if i % 3 == 0 {
                        Fate::Accept
                    } else {
                        Fate::Drop
                    }),
                    pri(i + 1),
                ),
        );
    }
    let table = builder.build();

    // Test a sample of packets — one per rule plus some non-matching.
    let mut packets: Vec<Headers> = (0..200u32)
        .step_by(10) // sample every 10th
        .map(|i| {
            let b2 = (i % 256) as u8;
            let b3 = ((i / 256) % 256) as u8;
            make_tcp_packet(Ipv4Addr::new(10, b3, b2, 1), 80)
        })
        .collect();
    // Add non-matching
    packets.push(make_tcp_packet(Ipv4Addr::new(192, 168, 1, 1), 80));
    packets.push(make_tcp_packet(Ipv4Addr::new(10, 0, 0, 1), 443));

    assert_agree(&table, &packets);
}

// ---- Edge cases ----

#[test]
fn empty_table_default_fate() {
    common::test_eal();

    // No rules — compiler should produce no groups.
    let table: acl::AclTable = AclTableBuilder::new(Fate::Accept).build();
    let groups = compiler::compile(&table);
    assert!(groups.is_empty(), "empty table should produce no DPDK groups");

    // Classification should return the default fate.
    let classifier = table.compile();
    let pkt = make_tcp_packet(Ipv4Addr::new(10, 0, 0, 1), 80);
    assert_eq!(classifier.classify(&pkt, &()).fate(), Fate::Accept);
}

#[test]
fn adjacent_non_overlapping_port_ranges() {
    common::test_eal();

    // Two rules with adjacent port ranges: 1-79 and 80-443.
    // No overlap — both should work independently.
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(1u16..=79u16);
                })
                .action(ActionSequence::just(Fate::Accept), pri(1)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(Ipv4Prefix::ROOT);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=443u16);
                })
                .action(ActionSequence::just(Fate::Accept), pri(2)),
        )
        .build();

    let packets: Vec<Headers> = [22u16, 79, 80, 443, 444, 8080]
        .iter()
        .map(|port| make_tcp_packet(Ipv4Addr::new(10, 0, 0, 1), *port))
        .collect();

    assert_agree(&table, &packets);
}

#[test]
fn nested_prefixes_priority_ordering() {
    common::test_eal();

    // Three nested prefixes: /8, /16, /24.
    // Most specific (/24) has highest precedence (pri 1).
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
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .action(ActionSequence::just(Fate::Accept), pri(3)),
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
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .action(ActionSequence::just(Fate::Drop), pri(2)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .action(ActionSequence::just(Fate::Accept), pri(1)),
        )
        .build();

    let packets: Vec<Headers> = [
        Ipv4Addr::new(10, 1, 2, 3),   // /24 match → Forward (pri 1)
        Ipv4Addr::new(10, 1, 3, 1),   // /16 match → Drop (pri 2)
        Ipv4Addr::new(10, 2, 0, 1),   // /8 match → Forward (pri 3)
        Ipv4Addr::new(192, 168, 1, 1), // no match → Drop (default)
    ]
    .iter()
    .map(|ip| make_tcp_packet(*ip, 80))
    .collect();

    assert_agree(&table, &packets);
}
