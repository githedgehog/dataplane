// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests: DPDK ACL classification vs linear-scan reference.
//!
//! Generates random rule sets and packets, compiles through both the
//! linear-scan classifier and the DPDK ACL backend, and asserts
//! identical classification results.
//!
//! These tests require EAL initialization and run under `nix-shell`.

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

/// Build probe packets covering interesting IPv4 src + TCP dst_port
/// combinations.
fn probe_packets() -> Vec<Headers> {
    let ips = [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 2, 3),
        Ipv4Addr::new(10, 255, 255, 255),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 100, 50),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(255, 255, 255, 255),
    ];
    let ports: &[u16] = &[1, 22, 53, 80, 443, 1024, 8080, 8443, 65535];

    let mut pkts = Vec::new();
    for ip in &ips {
        for port in ports {
            if let Ok(tp) = TcpPort::new_checked(*port) {
                if let Ok(h) = HeaderStack::new()
                    .eth(|_| {})
                    .ipv4(|h| {
                        if let Ok(uip) = net::ipv4::UnicastIpv4Addr::new(*ip) {
                            h.set_source(uip);
                        }
                    })
                    .tcp(|h| {
                        h.set_destination(tp);
                    })
                    .build_headers()
                {
                    pkts.push(h);
                }
            }
        }
    }
    pkts
}

/// Generate a random IPv4 prefix from raw bytes.
fn random_prefix(addr_bytes: [u8; 4], prefix_len_raw: u8) -> Ipv4Prefix {
    let prefix_len = prefix_len_raw % 33; // 0..=32
    let mask = if prefix_len == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix_len)
    };
    let addr_bits = u32::from(Ipv4Addr::from(addr_bytes)) & mask;
    let addr = Ipv4Addr::from(addr_bits);
    Ipv4Prefix::new(addr, prefix_len).unwrap()
}

/// Generate a random port range from two u16 values.
fn random_port_range(a: u16, b: u16) -> std::ops::RangeInclusive<u16> {
    let (min, max) = if a <= b { (a, b) } else { (b, a) };
    min..=max
}

/// A test rule spec: IPv4 src prefix + TCP dst port range + fate.
/// All rules share the same field signature (eth + ipv4.src + tcp.dst).
struct TestRuleSpec {
    src_prefix: Ipv4Prefix,
    dst_ports: std::ops::RangeInclusive<u16>,
    fate: Fate,
}

/// Build a table from test rule specs with unique priorities.
fn build_table(specs: &[TestRuleSpec], default_fate: Fate) -> acl::AclTable {
    let mut builder = AclTableBuilder::new(default_fate);
    for (i, spec) in specs.iter().enumerate() {
        let fate = spec.fate;
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(spec.src_prefix);
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(spec.dst_ports.clone());
            })
            .action(
                ActionSequence::just(fate),
                pri(u32::try_from(i + 1).unwrap()),
            );
        builder.push_rule(rule);
    }
    builder.build()
}

/// Compile a table to DPDK ACL and build a context.
/// Returns None if the table has no rules or no signature group.
fn build_dpdk_context(
    table: &acl::AclTable,
) -> Option<(AclContext<4, Built>, acl::FieldSignature)> {
    let groups = compiler::compile(table);
    if groups.is_empty() {
        return None;
    }

    // All our test rules have the same signature → one group with 4 fields
    assert_eq!(groups.len(), 1, "expected single signature group");
    let group = &groups[0];
    assert_eq!(group.field_count(), 4, "expected 4 fields");

    const N: usize = 4;
    let max_rules = group.rules().len().max(1);
    let params =
        AclCreateParams::new::<N>("prop_test", SocketId::ANY, max_rules as u32)
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

/// Core property test: for every packet, DPDK ACL and linear classifier
/// must agree on the classification result.
fn assert_dpdk_matches_linear(
    table: &acl::AclTable,
    packets: &[Headers],
) {
    let linear = table.compile();

    let Some((dpdk_ctx, sig)) = build_dpdk_context(table) else {
        // No rules → linear should return default for all packets.
        for pkt in packets {
            assert_eq!(
                linear.classify(pkt, &()).fate(),
                table.default_fate(),
                "linear matched a packet in an empty table"
            );
        }
        return;
    };

    for pkt in packets {
        let linear_fate = linear.classify(pkt, &()).fate();

        let acl_input = input::assemble_compact_input(pkt, sig);
        let data = [acl_input.as_ptr()];
        let mut results = [0u32; 1];
        dpdk_ctx
            .classify(&data, &mut results, 1)
            .expect("DPDK classify");
        let dpdk_fate = compiler::resolve_fate(table, results[0], table.default_fate());

        assert_eq!(
            linear_fate, dpdk_fate,
            "linear vs DPDK disagree: linear={linear_fate:?}, dpdk={dpdk_fate:?} \
             (userdata={}, {} rules)",
            results[0],
            table.rules().len()
        );
    }
}

// ---- Tests ----

#[test]
fn single_rule_all_packets() {
    common::test_eal();
    let packets = probe_packets();

    // Single permit rule: 10.0.0.0/8 TCP:80
    let table = build_table(
        &[TestRuleSpec {
            src_prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
            dst_ports: 80u16..=80u16,
            fate: Fate::Accept,
        }],
        Fate::Drop,
    );
    assert_dpdk_matches_linear(&table, &packets);
}

#[test]
fn overlapping_rules_priority() {
    common::test_eal();
    let packets = probe_packets();

    // Two overlapping rules: /8 permit (pri 2, lower precedence)
    // and /16 deny (pri 1, higher precedence).
    let table = build_table(
        &[
            TestRuleSpec {
                src_prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap(),
                dst_ports: 80u16..=80u16,
                fate: Fate::Drop,
            },
            TestRuleSpec {
                src_prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                dst_ports: 80u16..=80u16,
                fate: Fate::Accept,
            },
        ],
        Fate::Drop,
    );
    assert_dpdk_matches_linear(&table, &packets);
}

#[test]
fn port_range_rules() {
    common::test_eal();
    let packets = probe_packets();

    let table = build_table(
        &[
            TestRuleSpec {
                src_prefix: Ipv4Prefix::ROOT,
                dst_ports: random_port_range(80, 443),
                fate: Fate::Accept,
            },
            TestRuleSpec {
                src_prefix: Ipv4Prefix::ROOT,
                dst_ports: random_port_range(8000, 9000),
                fate: Fate::Accept,
            },
        ],
        Fate::Drop,
    );
    assert_dpdk_matches_linear(&table, &packets);
}

#[test]
fn many_rules_random() {
    common::test_eal();
    let packets = probe_packets();

    // 20 rules with deterministic "random" parameters.
    let specs: Vec<TestRuleSpec> = (0..20u8)
        .map(|i| {
            let a = i.wrapping_mul(37);
            let b = i.wrapping_mul(73);
            let c = i.wrapping_mul(11);
            let d = i.wrapping_mul(53);
            let prefix_len = (i % 25) + 8; // /8 to /32
            TestRuleSpec {
                src_prefix: random_prefix([a, b, c, d], prefix_len),
                dst_ports: random_port_range(
                    u16::from(i) * 100 + 1,
                    u16::from(i) * 100 + 200,
                ),
                fate: if i % 3 == 0 {
                    Fate::Drop
                } else {
                    Fate::Accept
                },
            }
        })
        .collect();

    let table = build_table(&specs, Fate::Drop);
    assert_dpdk_matches_linear(&table, &packets);
}

#[test]
fn wildcard_prefix_with_port_range() {
    common::test_eal();
    let packets = probe_packets();

    // /0 prefix (match all IPs) with specific port range.
    let table = build_table(
        &[TestRuleSpec {
            src_prefix: Ipv4Prefix::ROOT,
            dst_ports: random_port_range(1, 1024),
            fate: Fate::Accept,
        }],
        Fate::Drop,
    );
    assert_dpdk_matches_linear(&table, &packets);
}

#[test]
fn host_routes() {
    common::test_eal();
    let packets = probe_packets();

    // Several /32 host routes.
    let table = build_table(
        &[
            TestRuleSpec {
                src_prefix: Ipv4Prefix::from(Ipv4Addr::new(10, 0, 0, 1)),
                dst_ports: 80u16..=80u16,
                fate: Fate::Accept,
            },
            TestRuleSpec {
                src_prefix: Ipv4Prefix::from(Ipv4Addr::new(192, 168, 1, 1)),
                dst_ports: 443u16..=443u16,
                fate: Fate::Accept,
            },
            TestRuleSpec {
                src_prefix: Ipv4Prefix::from(Ipv4Addr::new(8, 8, 8, 8)),
                dst_ports: 1..=65535,
                fate: Fate::Drop,
            },
        ],
        Fate::Accept,
    );
    assert_dpdk_matches_linear(&table, &packets);
}
