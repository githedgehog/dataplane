// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! E2E tests for signature grouping through the DPDK ACL backend.
//!
//! Verifies that rules with different field signatures are compiled
//! into separate DPDK ACL contexts, and that each context classifies
//! correctly for its subset of traffic.

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
use net::udp::port::UdpPort;

use dataplane_acl_dpdk::compiler::{self, CompiledGroup};
use dataplane_acl_dpdk::input;

mod common;

fn pri(n: u32) -> Priority {
    Priority::new(n).unwrap()
}

/// Classify a single packet against a compiled DPDK ACL group.
///
/// Dispatches on field count N (const generic).  Returns the raw
/// userdata from DPDK classification (0 = no match).
fn classify_with_group(
    group: &CompiledGroup,
    packet: &Headers,
) -> u32 {
    let sig = group.signature();
    let acl_input = input::assemble_compact_input(packet, sig);
    let data = [acl_input.as_ptr()];
    let mut results = [0u32; 1];

    // Dispatch on field count.
    // Each arm builds an AclContext<N> for that specific N.
    match group.field_count() {
        2 => classify_n::<2>(group, &data, &mut results),
        3 => classify_n::<3>(group, &data, &mut results),
        4 => classify_n::<4>(group, &data, &mut results),
        5 => classify_n::<5>(group, &data, &mut results),
        6 => classify_n::<6>(group, &data, &mut results),
        7 => classify_n::<7>(group, &data, &mut results),
        8 => classify_n::<8>(group, &data, &mut results),
        n => panic!("unsupported field count {n} in test"),
    }

    results[0]
}

fn classify_n<const N: usize>(
    group: &CompiledGroup,
    data: &[*const u8],
    results: &mut [u32],
) {
    let max_rules = group.rules().len().max(1);
    let params =
        AclCreateParams::new::<N>("sig_test", SocketId::ANY, max_rules as u32)
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

    ctx.classify(data, results, 1).expect("classify");
}

/// Classify a packet against ALL compiled groups, returning the
/// highest-priority match across all groups.
fn classify_all_groups(
    table: &acl::AclTable,
    groups: &[CompiledGroup],
    packet: &Headers,
) -> Fate {
    let mut best_userdata: u32 = 0;
    let mut best_priority: Option<acl::Priority> = None;

    for group in groups {
        let userdata = classify_with_group(group, packet);
        if userdata != 0 {
            let idx = (userdata - 1) as usize;
            if let Some(rule) = table.rules().get(idx) {
                let pri = rule.priority();
                if best_priority.is_none_or(|bp| pri < bp) {
                    best_priority = Some(pri);
                    best_userdata = userdata;
                }
            }
        }
    }

    compiler::resolve_fate(table, best_userdata, table.default_fate())
}

// ---- Tests ----

#[test]
fn two_signature_groups_ipv4_tcp_vs_ipv4_only() {
    common::test_eal();

    // Rule 1: IPv4 + TCP (has tcp.dst → signature includes TCP fields)
    // Rule 2: IPv4 only (no transport → different signature)
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
                .permit(pri(100)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
                    );
                })
                .permit(pri(200)),
        )
        .build();

    let groups = compiler::compile(&table);
    assert_eq!(
        groups.len(),
        2,
        "expected 2 signature groups (IPv4+TCP vs IPv4-only)"
    );

    // Debug: print group details
    for (i, g) in groups.iter().enumerate() {
        eprintln!("Group {i}: sig={:?} fields={} rules={}", g.signature(), g.field_count(), g.rules().len());
        for (j, fd) in g.field_defs().iter().enumerate() {
            eprintln!("  FieldDef[{j}]: type={:?} size={:?} fi={} ii={} offset={}",
                fd.field_type, fd.size, fd.field_index, fd.input_index, fd.offset);
        }
        for (j, cr) in g.rules().iter().enumerate() {
            eprintln!("  Rule[{j}]: pri={} userdata={}", cr.data.priority, cr.data.userdata);
            for (k, f) in cr.fields.iter().enumerate() {
                eprintln!("    Field[{k}]: {f}");
            }
        }
    }

    // Verify field counts differ.
    let mut field_counts: Vec<usize> = groups.iter().map(|g| g.field_count()).collect();
    field_counts.sort();
    assert!(
        field_counts[0] < field_counts[1],
        "groups should have different field counts: {field_counts:?}"
    );

    let classifier = table.compile();

    // Packet matching rule 1 (10.x.x.x:80 TCP)
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

    let linear_fate = classifier.classify(&tcp_pkt, &()).fate();
    let dpdk_fate = classify_all_groups(&table, &groups, &tcp_pkt);
    assert_eq!(linear_fate, Fate::Accept);
    assert_eq!(dpdk_fate, linear_fate, "TCP rule mismatch");

    // Packet matching rule 2 (172.16.x.x, any transport)
    // Use UDP to ensure it doesn't accidentally match the TCP rule.
    let udp_pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(
                net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(172, 16, 1, 1)).unwrap(),
            );
        })
        .udp(|udp| {
            udp.set_destination(UdpPort::new_checked(53).unwrap());
        })
        .build_headers()
        .unwrap();

    let linear_fate = classifier.classify(&udp_pkt, &()).fate();
    let dpdk_fate = classify_all_groups(&table, &groups, &udp_pkt);
    assert_eq!(linear_fate, Fate::Accept);
    assert_eq!(dpdk_fate, linear_fate, "IPv4-only rule mismatch");

    // Packet matching neither rule.
    let no_match_pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(
                net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap(),
            );
        })
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(443).unwrap());
        })
        .build_headers()
        .unwrap();

    let linear_fate = classifier.classify(&no_match_pkt, &()).fate();
    let dpdk_fate = classify_all_groups(&table, &groups, &no_match_pkt);
    assert_eq!(linear_fate, Fate::Drop);
    assert_eq!(dpdk_fate, linear_fate, "no-match mismatch");
}

#[test]
fn tcp_and_udp_separate_groups() {
    common::test_eal();

    // TCP rule with src port → signature includes TCP src+dst
    // UDP rule with dst port → different signature (UDP fields)
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|_| {})
                .tcp(|tcp| {
                    tcp.src = FieldMatch::Select(12345u16..=12345u16);
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .permit(pri(100)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|_| {})
                .udp(|udp| {
                    udp.dst = FieldMatch::Select(53u16..=53u16);
                })
                .permit(pri(200)),
        )
        .build();

    let groups = compiler::compile(&table);
    assert_eq!(
        groups.len(),
        2,
        "TCP and UDP rules should produce separate signature groups"
    );

    let classifier = table.compile();

    // TCP packet matching rule 1.
    let tcp_pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|_| {})
        .tcp(|tcp| {
            tcp.set_source(TcpPort::new_checked(12345).unwrap());
            tcp.set_destination(TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    let linear_fate = classifier.classify(&tcp_pkt, &()).fate();
    let dpdk_fate = classify_all_groups(&table, &groups, &tcp_pkt);
    assert_eq!(linear_fate, Fate::Accept);
    assert_eq!(dpdk_fate, linear_fate, "TCP packet mismatch");

    // UDP packet matching rule 2.
    let udp_pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|_| {})
        .udp(|udp| {
            udp.set_destination(UdpPort::new_checked(53).unwrap());
        })
        .build_headers()
        .unwrap();

    let linear_fate = classifier.classify(&udp_pkt, &()).fate();
    let dpdk_fate = classify_all_groups(&table, &groups, &udp_pkt);
    assert_eq!(linear_fate, Fate::Accept);
    assert_eq!(dpdk_fate, linear_fate, "UDP packet mismatch");

    // TCP packet NOT matching (wrong ports).
    let wrong_tcp = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|_| {})
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(443).unwrap());
        })
        .build_headers()
        .unwrap();

    let linear_fate = classifier.classify(&wrong_tcp, &()).fate();
    let dpdk_fate = classify_all_groups(&table, &groups, &wrong_tcp);
    assert_eq!(linear_fate, Fate::Drop);
    assert_eq!(dpdk_fate, linear_fate, "wrong TCP mismatch");
}

#[test]
fn three_groups_mixed() {
    common::test_eal();

    // Three distinct signatures:
    // 1. IPv4 + TCP dst (proto + ipv4_src + eth_type + tcp_dst = 4 fields)
    // 2. IPv4 + UDP dst (proto + ipv4_src + eth_type + udp_dst = 4 fields, but different signature bits)
    // 3. IPv4 src only (proto + ipv4_src + eth_type = 3 fields)
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
                .action(ActionSequence::just(Fate::Accept), pri(1)),
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
                    udp.dst = FieldMatch::Select(53u16..=53u16);
                })
                .action(ActionSequence::just(Fate::Accept), pri(2)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16).unwrap(),
                    );
                })
                .action(ActionSequence::just(Fate::Accept), pri(3)),
        )
        .build();

    let groups = compiler::compile(&table);
    assert!(
        groups.len() >= 2,
        "expected at least 2 signature groups, got {}",
        groups.len()
    );

    let classifier = table.compile();

    let test_cases: Vec<(Headers, Fate, &str)> = vec![
        (
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.set_source(
                        net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.set_destination(TcpPort::new_checked(80).unwrap());
                })
                .build_headers()
                .unwrap(),
            Fate::Accept,
            "10.x TCP:80 → Forward",
        ),
        (
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.set_source(
                        net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
                    );
                })
                .udp(|udp| {
                    udp.set_destination(UdpPort::new_checked(53).unwrap());
                })
                .build_headers()
                .unwrap(),
            Fate::Accept,
            "10.x UDP:53 → Forward",
        ),
        (
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.set_source(
                        net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.set_destination(TcpPort::new_checked(443).unwrap());
                })
                .build_headers()
                .unwrap(),
            Fate::Accept,
            "192.168.x any → Forward",
        ),
        (
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.set_source(
                        net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(8, 8, 8, 8)).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.set_destination(TcpPort::new_checked(80).unwrap());
                })
                .build_headers()
                .unwrap(),
            Fate::Drop,
            "8.8.8.8 → Drop (no match)",
        ),
    ];

    for (pkt, expected_fate, label) in &test_cases {
        let linear_fate = classifier.classify(pkt, &()).fate();
        let dpdk_fate = classify_all_groups(&table, &groups, pkt);

        assert_eq!(
            linear_fate, *expected_fate,
            "linear mismatch for {label}"
        );
        assert_eq!(
            dpdk_fate, linear_fate,
            "DPDK vs linear mismatch for {label}"
        );
    }
}

// ---- Category-aware tests ----

/// Helper: classify using the categorized compilation path.
fn classify_categorized(
    table: &acl::AclTable,
    comp: &compiler::CategorizedCompilation,
    packet: &Headers,
) -> Fate {
    let sig = comp.group.signature();
    let acl_input = input::assemble_compact_input(packet, sig);
    let data = [acl_input.as_ptr()];

    let n = comp.group.field_count();
    let cats = comp.num_categories;
    let mut results = vec![0u32; cats as usize];

    match n {
        2 => classify_cat_n::<2>(&comp.group, &data, &mut results, cats),
        3 => classify_cat_n::<3>(&comp.group, &data, &mut results, cats),
        4 => classify_cat_n::<4>(&comp.group, &data, &mut results, cats),
        5 => classify_cat_n::<5>(&comp.group, &data, &mut results, cats),
        6 => classify_cat_n::<6>(&comp.group, &data, &mut results, cats),
        7 => classify_cat_n::<7>(&comp.group, &data, &mut results, cats),
        8 => classify_cat_n::<8>(&comp.group, &data, &mut results, cats),
        _ => panic!("unsupported field count {n}"),
    }

    let best = compiler::resolve_categories(table, &results, cats);
    compiler::resolve_fate(table, best, table.default_fate())
}

fn classify_cat_n<const N: usize>(
    group: &CompiledGroup,
    data: &[*const u8],
    results: &mut [u32],
    categories: u32,
) {
    let max_rules = group.rules().len().max(1);
    let params =
        AclCreateParams::new::<N>("cat_test", SocketId::ANY, max_rules as u32)
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
    let build_cfg = AclBuildConfig::new(categories, field_defs, 0)
        .expect("build config with categories");
    let ctx = ctx.build(&build_cfg).expect("build context");

    ctx.classify(data, results, categories).expect("classify");
}

#[test]
fn categories_two_groups_ipv4_tcp_vs_ipv4_only() {
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
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .permit(pri(100)),
        )
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
                    );
                })
                .permit(pri(200)),
        )
        .build();

    let comp = compiler::compile_categories(&table).expect("should compile");
    eprintln!(
        "Categories: {} groups, {} categories, {} fields, {} rules",
        comp.num_groups,
        comp.num_categories,
        comp.group.field_count(),
        comp.group.rules().len(),
    );

    let classifier = table.compile();

    let test_cases: Vec<(Headers, &str)> = vec![
        (
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.set_source(
                        net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.set_destination(TcpPort::new_checked(80).unwrap());
                })
                .build_headers()
                .unwrap(),
            "10.x TCP:80",
        ),
        (
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.set_source(
                        net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(172, 16, 1, 1)).unwrap(),
                    );
                })
                .udp(|udp| {
                    udp.set_destination(UdpPort::new_checked(53).unwrap());
                })
                .build_headers()
                .unwrap(),
            "172.16.x UDP:53",
        ),
        (
            HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.set_source(
                        net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.set_destination(TcpPort::new_checked(443).unwrap());
                })
                .build_headers()
                .unwrap(),
            "192.168.x (no match)",
        ),
    ];

    for (pkt, label) in &test_cases {
        let linear_fate = classifier.classify(pkt, &()).fate();
        let cat_fate = classify_categorized(&table, &comp, pkt);

        assert_eq!(
            linear_fate, cat_fate,
            "linear vs categorized mismatch for {label}"
        );
    }
}

#[test]
fn categories_three_groups_priority_across_groups() {
    common::test_eal();

    // IPv4-only rule (pri 1, highest) — Forward
    // IPv4+TCP rule (pri 2) — Drop
    // IPv4+UDP rule (pri 3) — Drop
    // A TCP packet from 10.x should match both the IPv4-only (Forward)
    // and the IPv4+TCP (Drop) rules. Priority 1 wins → Forward.
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                    );
                })
                .permit(pri(1)),
        )
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
                .deny(pri(2)),
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
                    udp.dst = FieldMatch::Select(53u16..=53u16);
                })
                .deny(pri(3)),
        )
        .build();

    let comp = compiler::compile_categories(&table).expect("should compile");
    eprintln!(
        "3-group categories: {} groups, {} categories, {} field_defs, rules have {} fields each",
        comp.num_groups,
        comp.num_categories,
        comp.group.field_count(),
        comp.group.rules().first().map(|r| r.fields.len()).unwrap_or(0),
    );
    let classifier = table.compile();

    // TCP packet: matches IPv4-only (pri 1, Forward) AND IPv4+TCP (pri 2, Drop).
    // Priority 1 wins → Forward.
    let tcp_pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(
                net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
            );
        })
        .tcp(|tcp| {
            tcp.set_destination(TcpPort::new_checked(80).unwrap());
        })
        .build_headers()
        .unwrap();

    assert_eq!(
        classifier.classify(&tcp_pkt, &()).fate(),
        Fate::Accept,
        "linear should say Forward (pri 1 wins)"
    );
    assert_eq!(
        classify_categorized(&table, &comp, &tcp_pkt),
        Fate::Accept,
        "categorized should say Forward (pri 1 wins across categories)"
    );

    // UDP packet: matches IPv4-only (pri 1, Forward) AND IPv4+UDP (pri 3, Drop).
    // Priority 1 wins → Forward.
    let udp_pkt = HeaderStack::new()
        .eth(|_| {})
        .ipv4(|ip| {
            ip.set_source(
                net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(10, 1, 2, 3)).unwrap(),
            );
        })
        .udp(|udp| {
            udp.set_destination(UdpPort::new_checked(53).unwrap());
        })
        .build_headers()
        .unwrap();

    assert_eq!(
        classifier.classify(&udp_pkt, &()).fate(),
        Fate::Accept,
    );
    assert_eq!(
        classify_categorized(&table, &comp, &udp_pkt),
        Fate::Accept,
        "categorized should resolve cross-category priority correctly"
    );
}
