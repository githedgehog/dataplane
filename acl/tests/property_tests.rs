// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Property tests for ACL classification and updates.
//!
//! Uses bolero to generate random rule sets and verify invariants:
//! - Classification is deterministic (same rules + same packet = same result)
//! - Two-tier update produces same results as fresh single-tier compile
//!
//! Short tests (1s default) run in normal `cargo test`.
//! Long tests (60s) are behind `#[ignore]` — run with `--ignored`.

#![allow(clippy::unwrap_used)]

use dataplane_acl::{
    AclRule, AclTableBuilder, Fate, GenerateAclTable, GenerateTablePair,
};
use net::headers::builder::HeaderStack;
use net::headers::Headers;
use net::ipv4::UnicastIpv4Addr;
use net::tcp::port::TcpPort;
use net::udp::port::UdpPort;
use std::net::Ipv4Addr;

/// Build a diverse set of probe packets covering common match dimensions.
fn generate_probe_packets(count: usize) -> Vec<Headers> {
    let ips = [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 2, 3),
        Ipv4Addr::new(10, 255, 0, 1),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(192, 168, 100, 50),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(1, 1, 1, 1),
    ];
    let tcp_ports: &[u16] = &[1, 22, 53, 80, 443, 1024, 8080, 8443, 65535];
    let udp_ports: &[u16] = &[53, 67, 68, 123, 500, 4500, 51820];

    let mut packets = Vec::new();

    // TCP packets
    for ip in &ips {
        for port in tcp_ports {
            if let (Ok(uip), Ok(tp)) = (UnicastIpv4Addr::new(*ip), TcpPort::new_checked(*port)) {
                if let Ok(h) = HeaderStack::new()
                    .eth(|_| {})
                    .ipv4(|h| { h.set_source(uip); })
                    .tcp(|h| { h.set_destination(tp); })
                    .build_headers()
                {
                    packets.push(h);
                }
            }
            if packets.len() >= count {
                return packets;
            }
        }
    }

    // UDP packets
    for ip in &ips {
        for port in udp_ports {
            if let (Ok(uip), Ok(up)) = (UnicastIpv4Addr::new(*ip), UdpPort::new_checked(*port)) {
                if let Ok(h) = HeaderStack::new()
                    .eth(|_| {})
                    .ipv4(|h| { h.set_source(uip); })
                    .udp(|h| { h.set_destination(up); })
                    .build_headers()
                {
                    packets.push(h);
                }
            }
            if packets.len() >= count {
                return packets;
            }
        }
    }

    packets
}

// ---- Short tests (1s, default) ----

#[test]
fn classify_deterministic_on_random_rules() {
    let packets = generate_probe_packets(50);

    bolero::check!()
        .with_type::<Vec<AclRule<()>>>()
        .for_each(|rules: &Vec<AclRule<()>>| {
            if rules.is_empty() {
                return;
            }

            let mut seen = std::collections::HashSet::new();
            let mut builder = AclTableBuilder::new(Fate::Drop);
            for rule in rules {
                if seen.insert(rule.priority()) {
                    builder.push_rule(rule.clone());
                }
            }
            let table = builder.build();

            let classifier = table.compile();

            // Classify twice — must be deterministic.
            for pkt in &packets {
                let first = classifier.classify(pkt, &()).fate();
                let second = classifier.classify(pkt, &()).fate();
                assert_eq!(
                    first, second,
                    "non-deterministic classification ({} rules)",
                    table.rules().len()
                );
            }
        });
}

#[test]
fn update_two_tier_matches_fresh_compile() {
    let packets = generate_probe_packets(100);

    bolero::check!()
        .with_generator(GenerateTablePair {
            base_rule_count: 20,
            add_count: 2,
            remove_count: 1,
            modify_count: 1,
        })
        .for_each(|(old_table, new_table)| {
            let old_classifier = old_table.compile();

            let plan = dataplane_acl::plan_update(old_table, &old_classifier, new_table);
            let fresh = new_table.compile();

            for pkt in &packets {
                let tiered_fate = plan.immediate.classify(pkt, &()).fate();
                let fresh_fate = fresh.classify(pkt, &()).fate();
                assert_eq!(
                    tiered_fate, fresh_fate,
                    "two-tier vs fresh mismatch after update ({} → {} rules)",
                    old_table.rules().len(),
                    new_table.rules().len()
                );
            }
        });
}

#[test]
fn large_table_classify_deterministic() {
    let packets = generate_probe_packets(200);

    bolero::check!()
        .with_generator(GenerateAclTable { rule_count: 100 })
        .for_each(|table| {
            let classifier = table.compile();

            for pkt in &packets {
                let first = classifier.classify(pkt, &()).fate();
                let second = classifier.classify(pkt, &()).fate();
                assert_eq!(
                    first, second,
                    "large table: non-deterministic classification ({} rules)",
                    table.rules().len()
                );
            }
        });
}

// ---- Long tests (60s, run with --ignored) ----

#[test]
#[ignore]
fn long_update_consistency() {
    let packets = generate_probe_packets(500);

    bolero::check!()
        .with_generator(GenerateTablePair {
            base_rule_count: 50,
            add_count: 5,
            remove_count: 3,
            modify_count: 3,
        })
        .with_iterations(1_000_000)
        .with_max_len(4096)
        .for_each(|(old_table, new_table)| {
            let old_classifier = old_table.compile();

            let plan = dataplane_acl::plan_update(old_table, &old_classifier, new_table);
            let fresh = new_table.compile();

            for pkt in &packets {
                let tiered_fate = plan.immediate.classify(pkt, &()).fate();
                let fresh_fate = fresh.classify(pkt, &()).fate();
                assert_eq!(
                    tiered_fate, fresh_fate,
                    "long test: two-tier vs fresh mismatch"
                );
            }
        });
}

#[test]
#[ignore]
fn long_large_table_deterministic() {
    let packets = generate_probe_packets(500);

    bolero::check!()
        .with_generator(GenerateAclTable { rule_count: 200 })
        .with_iterations(1_000_000)
        .with_max_len(8192)
        .for_each(|table| {
            let classifier = table.compile();

            for pkt in &packets {
                let first = classifier.classify(pkt, &()).fate();
                let second = classifier.classify(pkt, &()).fate();
                assert_eq!(
                    first, second,
                    "long test: non-deterministic classification ({} rules)",
                    table.rules().len()
                );
            }
        });
}
