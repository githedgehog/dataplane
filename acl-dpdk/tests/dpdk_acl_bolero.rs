// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bolero-driven fuzz tests: random rules through DPDK ACL vs linear classifier.
//!
//! Generates random rule sets constrained to the field types our DPDK ACL
//! pipeline currently supports (IPv4 + TCP/UDP), compiles through both
//! backends, and asserts identical classification on probe packets.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

use acl::{
    AclRuleBuilder, AclTableBuilder, ActionSequence, Fate, FieldMatch,
    Ipv4Prefix, Priority,
};
use bolero::TypeGenerator;
use dpdk::acl::config::{AclBuildConfig, AclCreateParams};
use dpdk::acl::context::AclContext;
use dpdk::acl::rule::{AclField, Rule};
use dpdk::socket::SocketId;
use net::headers::builder::HeaderStack;
use net::headers::Headers;
use net::tcp::port::TcpPort;
use net::udp::port::UdpPort;

use dataplane_acl_dpdk::compiler;
use dataplane_acl_dpdk::input;

mod common;

// ---- Constrained rule generator ----

/// Maximum priority value for DPDK ACL.  Priorities above this
/// clamp to DPDK priority 1, losing relative ordering.
const MAX_DPDK_PRIORITY: u32 = 536870911;

/// Generate a random port range from a bolero driver.
fn produce_port_range<D: bolero::Driver>(driver: &mut D) -> Option<RangeInclusive<u16>> {
    let a = driver.produce::<u16>()?;
    let b = driver.produce::<u16>()?;
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    Some(lo..=hi)
}

/// Generate a priority within DPDK's valid range.
fn dpdk_safe_priority<D: bolero::Driver>(driver: &mut D) -> Option<Priority> {
    let raw = driver.produce::<u32>()? % MAX_DPDK_PRIORITY + 1;
    Priority::new(raw).ok()
}

/// A rule spec that only produces IPv4+TCP rules with the same
/// field signature (eth + ipv4.src + tcp.dst).  This ensures all
/// rules land in a single DPDK ACL group with a fixed field count.
#[derive(Debug, Clone)]
struct Ipv4TcpRule {
    src_prefix: Ipv4Prefix,
    dst_port_range: RangeInclusive<u16>,
    fate: Fate,
    priority: Priority,
}

impl TypeGenerator for Ipv4TcpRule {
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let src_prefix = driver.produce::<Ipv4Prefix>()?;
        let dst_port_range = produce_port_range(driver)?;
        let fate = if driver.produce::<bool>()? {
            Fate::Accept
        } else {
            Fate::Drop
        };
        let priority = dpdk_safe_priority(driver)?;
        Some(Ipv4TcpRule {
            src_prefix,
            dst_port_range,
            fate,
            priority,
        })
    }
}

impl Ipv4TcpRule {
    fn to_acl_rule(&self) -> acl::AclRule {
        AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(self.src_prefix);
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(self.dst_port_range.clone());
            })
            .action(ActionSequence::just(self.fate), self.priority)
    }
}

/// Generate a table of IPv4+TCP rules with unique priorities.
struct Ipv4TcpTable {
    rule_count: usize,
}

impl bolero::ValueGenerator for Ipv4TcpTable {
    type Output = acl::AclTable;

    fn generate<D: bolero::Driver>(&self, driver: &mut D) -> Option<Self::Output> {
        let mut builder = AclTableBuilder::new(Fate::Drop);
        let mut seen_priorities = HashSet::new();

        for _ in 0..self.rule_count {
            let rule: Ipv4TcpRule = driver.produce()?;
            if seen_priorities.insert(rule.priority) {
                builder.push_rule(rule.to_acl_rule());
            }
        }
        Some(builder.build())
    }
}

// ---- Mixed signature generator ----

/// A rule that can be IPv4-only OR IPv4+TCP, producing multiple
/// signature groups.
#[derive(Debug, Clone)]
enum MixedRule {
    Ipv4Only {
        src_prefix: Ipv4Prefix,
        fate: Fate,
        priority: Priority,
    },
    Ipv4Tcp {
        src_prefix: Ipv4Prefix,
        dst_port_range: RangeInclusive<u16>,
        fate: Fate,
        priority: Priority,
    },
    Ipv4Udp {
        src_prefix: Ipv4Prefix,
        dst_port_range: RangeInclusive<u16>,
        fate: Fate,
        priority: Priority,
    },
}

impl TypeGenerator for MixedRule {
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let src_prefix = driver.produce::<Ipv4Prefix>()?;
        let fate = if driver.produce::<bool>()? {
            Fate::Accept
        } else {
            Fate::Drop
        };
        let priority = dpdk_safe_priority(driver)?;

        match driver.produce::<u8>()? % 3 {
            0 => Some(MixedRule::Ipv4Only {
                src_prefix,
                fate,
                priority,
            }),
            1 => {
                let dst_port_range = produce_port_range(driver)?;
                Some(MixedRule::Ipv4Tcp {
                    src_prefix,
                    dst_port_range,
                    fate,
                    priority,
                })
            }
            _ => {
                let dst_port_range = produce_port_range(driver)?;
                Some(MixedRule::Ipv4Udp {
                    src_prefix,
                    dst_port_range,
                    fate,
                    priority,
                })
            }
        }
    }
}

impl MixedRule {
    fn to_acl_rule(&self) -> acl::AclRule {
        match self {
            MixedRule::Ipv4Only {
                src_prefix,
                fate,
                priority,
            } => AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(*src_prefix);
                })
                .action(ActionSequence::just(*fate), *priority),
            MixedRule::Ipv4Tcp {
                src_prefix,
                dst_port_range,
                fate,
                priority,
            } => AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(*src_prefix);
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(dst_port_range.clone());
                })
                .action(ActionSequence::just(*fate), *priority),
            MixedRule::Ipv4Udp {
                src_prefix,
                dst_port_range,
                fate,
                priority,
            } => AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(*src_prefix);
                })
                .udp(|udp| {
                    udp.dst = FieldMatch::Select(dst_port_range.clone());
                })
                .action(ActionSequence::just(*fate), *priority),
        }
    }

    fn priority(&self) -> Priority {
        match self {
            MixedRule::Ipv4Only { priority, .. }
            | MixedRule::Ipv4Tcp { priority, .. }
            | MixedRule::Ipv4Udp { priority, .. } => *priority,
        }
    }
}

// ---- Probe packet generation ----

fn probe_packets() -> Vec<Headers> {
    let ips = [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 1, 2, 3),
        Ipv4Addr::new(10, 255, 255, 255),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(127, 0, 0, 1),
    ];
    let tcp_ports: &[u16] = &[1, 22, 80, 443, 8080, 65535];
    let udp_ports: &[u16] = &[53, 123, 500, 51820];

    let mut pkts = Vec::new();
    for ip in &ips {
        if let Ok(uip) = net::ipv4::UnicastIpv4Addr::new(*ip) {
            for port in tcp_ports {
                if let Ok(tp) = TcpPort::new_checked(*port) {
                    if let Ok(h) = HeaderStack::new()
                        .eth(|_| {})
                        .ipv4(|h| { h.set_source(uip); })
                        .tcp(|h| { h.set_destination(tp); })
                        .build_headers()
                    {
                        pkts.push(h);
                    }
                }
            }
            for port in udp_ports {
                if let Ok(up) = UdpPort::new_checked(*port) {
                    if let Ok(h) = HeaderStack::new()
                        .eth(|_| {})
                        .ipv4(|h| { h.set_source(uip); })
                        .udp(|h| { h.set_destination(up); })
                        .build_headers()
                    {
                        pkts.push(h);
                    }
                }
            }
        }
    }
    pkts
}

// ---- DPDK ACL classification helpers ----

/// Classify a packet through ALL compiled groups, returning the
/// highest-priority match across all groups.
///
/// Each group is an independent DPDK ACL context.  We classify the
/// packet against each, collect all matches, and return the one with
/// the lowest priority value (highest precedence).
fn classify_through_dpdk(
    table: &acl::AclTable,
    groups: &[compiler::CompiledGroup],
    packet: &Headers,
) -> Fate {
    let mut best_userdata: u32 = 0;
    let mut best_priority: Option<Priority> = None;

    for group in groups {
        let sig = group.signature();
        let acl_input = input::assemble_compact_input(packet, sig);
        let data = [acl_input.as_ptr()];
        let mut results = [0u32; 1];

        match group.field_count() {
            2 => classify_n::<2>(group, &data, &mut results),
            3 => classify_n::<3>(group, &data, &mut results),
            4 => classify_n::<4>(group, &data, &mut results),
            5 => classify_n::<5>(group, &data, &mut results),
            6 => classify_n::<6>(group, &data, &mut results),
            7 => classify_n::<7>(group, &data, &mut results),
            8 => classify_n::<8>(group, &data, &mut results),
            n => panic!("unsupported field count {n}"),
        }

        if results[0] != 0 {
            // Resolve the matched rule's priority.
            let idx = (results[0] - 1) as usize;
            if let Some(rule) = table.rules().get(idx) {
                let pri = rule.priority();
                // Lower priority value = higher precedence.
                if best_priority.is_none_or(|bp| pri < bp) {
                    best_priority = Some(pri);
                    best_userdata = results[0];
                }
            }
        }
    }

    compiler::resolve_fate(table, best_userdata, table.default_fate())
}

fn classify_n<const N: usize>(
    group: &compiler::CompiledGroup,
    data: &[*const u8],
    results: &mut [u32],
) {
    let max_rules = group.rules().len().max(1);
    let params =
        AclCreateParams::new::<N>("bolero_test", SocketId::ANY, max_rules as u32)
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

// ---- Tests ----

/// Bolero fuzz: generated IPv4+TCP rules, single signature group.
/// DPDK ACL must agree with linear classifier on all probe packets.
#[test]
fn bolero_ipv4_tcp_single_group() {
    common::test_eal();
    let packets = probe_packets();

    bolero::check!()
        .with_generator(Ipv4TcpTable { rule_count: 10 })
        .for_each(|table| {
            if table.rules().is_empty() {
                return;
            }

            let groups = compiler::compile(table);
            if groups.is_empty() {
                return;
            }

            let linear = table.compile();

            for pkt in &packets {
                let linear_fate = linear.classify(pkt, &()).fate();
                let dpdk_fate = classify_through_dpdk(table, &groups, pkt);

                assert_eq!(
                    linear_fate, dpdk_fate,
                    "linear vs DPDK disagree ({} rules, {} groups)",
                    table.rules().len(),
                    groups.len(),
                );
            }
        });
}

/// Bolero fuzz: mixed IPv4-only / IPv4+TCP / IPv4+UDP rules,
/// multiple signature groups.  This exercises the 2-byte field
/// promotion fix and cross-group classification.
#[test]
fn bolero_mixed_signatures() {
    common::test_eal();
    let packets = probe_packets();

    bolero::check!()
        .with_type::<Vec<MixedRule>>()
        .for_each(|rules: &Vec<MixedRule>| {
            if rules.is_empty() {
                return;
            }

            let mut builder = AclTableBuilder::new(Fate::Drop);
            let mut seen = HashSet::new();
            for rule in rules {
                if seen.insert(rule.priority()) {
                    builder.push_rule(rule.to_acl_rule());
                }
            }
            let table = builder.build();

            if table.rules().is_empty() {
                return;
            }

            let groups = compiler::compile(&table);
            if groups.is_empty() {
                return;
            }

            let linear = table.compile();

            for pkt in &packets {
                let linear_fate = linear.classify(pkt, &()).fate();
                let dpdk_fate = classify_through_dpdk(&table, &groups, pkt);

                if linear_fate != dpdk_fate {
                    // Diagnostic output for debugging
                    eprintln!("=== MISMATCH: linear={linear_fate:?} dpdk={dpdk_fate:?} ===");
                    eprintln!("Table: {} rules, {} groups", table.rules().len(), groups.len());
                    for (gi, group) in groups.iter().enumerate() {
                        let sig = group.signature();
                        let acl_input = input::assemble_compact_input(pkt, sig);
                        let d = [acl_input.as_ptr()];
                        let mut r = [0u32; 1];
                        match group.field_count() {
                            2 => classify_n::<2>(group, &d, &mut r),
                            3 => classify_n::<3>(group, &d, &mut r),
                            4 => classify_n::<4>(group, &d, &mut r),
                            5 => classify_n::<5>(group, &d, &mut r),
                            6 => classify_n::<6>(group, &d, &mut r),
                            7 => classify_n::<7>(group, &d, &mut r),
                            8 => classify_n::<8>(group, &d, &mut r),
                            _ => {}
                        }
                        let fate = compiler::resolve_fate(&table, r[0], table.default_fate());
                        let matched_pri = if r[0] != 0 {
                            table.rules().get((r[0] - 1) as usize)
                                .map(|ru| ru.priority().get())
                        } else {
                            None
                        };
                        eprintln!(
                            "  group[{gi}]: sig={:?} fields={} rules={} -> userdata={} pri={matched_pri:?} fate={fate:?}",
                            group.signature(), group.field_count(), group.rules().len(), r[0],
                        );
                    }
                    // Show ALL rules that match this packet, sorted by priority
                    let mut matching = Vec::new();
                    for (idx, rule) in table.rules().iter().enumerate() {
                        let single_table = AclTableBuilder::new(Fate::Drop)
                            .add_rule(rule.clone())
                            .build();
                        let single = single_table.compile();
                        if single.classify(pkt, &()).fate() != Fate::Drop {
                            matching.push((idx, rule.priority().get(), rule.actions().fate()));
                        }
                    }
                    matching.sort_by_key(|m| m.1);
                    for (idx, pri, fate) in &matching {
                        eprintln!("  matching rule: idx={idx} pri={pri} fate={fate:?}");
                    }
                }

                assert_eq!(
                    linear_fate, dpdk_fate,
                    "linear vs DPDK disagree ({} rules, {} groups)",
                    table.rules().len(),
                    groups.len(),
                );
            }
        });
}

/// Bolero fuzz: mixed signatures through the category-aware compilation
/// path.  Single DPDK ACL context with categories, single classify call.
#[test]
fn bolero_mixed_categories() {
    common::test_eal();
    let packets = probe_packets();

    bolero::check!()
        .with_type::<Vec<MixedRule>>()
        .for_each(|rules: &Vec<MixedRule>| {
            if rules.is_empty() {
                return;
            }

            let mut builder = AclTableBuilder::new(Fate::Drop);
            let mut seen = HashSet::new();
            for rule in rules {
                if seen.insert(rule.priority()) {
                    builder.push_rule(rule.to_acl_rule());
                }
            }
            let table = builder.build();

            if table.rules().is_empty() {
                return;
            }

            let Some(comp) = compiler::compile_categories(&table) else {
                return;
            };

            let linear = table.compile();
            let sig = comp.group.signature();
            let cats = comp.num_categories;
            let n = comp.group.field_count();

            match n {
                2 => classify_cat_packets::<2>(&table, &comp, &linear, &packets, cats, sig),
                3 => classify_cat_packets::<3>(&table, &comp, &linear, &packets, cats, sig),
                4 => classify_cat_packets::<4>(&table, &comp, &linear, &packets, cats, sig),
                5 => classify_cat_packets::<5>(&table, &comp, &linear, &packets, cats, sig),
                6 => classify_cat_packets::<6>(&table, &comp, &linear, &packets, cats, sig),
                7 => classify_cat_packets::<7>(&table, &comp, &linear, &packets, cats, sig),
                8 => classify_cat_packets::<8>(&table, &comp, &linear, &packets, cats, sig),
                _ => { /* skip unsupported field counts */ }
            }
        });
}

fn classify_cat_packets<const N: usize>(
    table: &acl::AclTable,
    comp: &compiler::CategorizedCompilation,
    linear: &acl::Classifier,
    packets: &[Headers],
    cats: u32,
    sig: acl::FieldSignature,
) {
    let max_rules = comp.group.rules().len().max(1);
    let params =
        AclCreateParams::new::<N>("bolero_cat", SocketId::ANY, max_rules as u32)
            .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    let rules: Vec<Rule<N>> = comp
        .group
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

    let mut field_defs = [comp.group.field_defs()[0]; N];
    for (i, fd) in comp.group.field_defs().iter().enumerate() {
        field_defs[i] = *fd;
    }
    let build_cfg = AclBuildConfig::new(cats, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).expect("build context");

    for pkt in packets {
        let linear_fate = linear.classify(pkt, &()).fate();

        let acl_input = input::assemble_compact_input(pkt, sig);
        let data = [acl_input.as_ptr()];
        let mut results = vec![0u32; cats as usize];
        ctx.classify(&data, &mut results, cats).expect("classify");

        let best = compiler::resolve_categories(table, &results, cats);
        let dpdk_fate = compiler::resolve_fate(table, best, table.default_fate());

        assert_eq!(
            linear_fate, dpdk_fate,
            "linear vs categorized DPDK disagree ({} rules, {} groups, {} categories)",
            table.rules().len(),
            comp.num_groups,
            cats,
        );
    }
}
