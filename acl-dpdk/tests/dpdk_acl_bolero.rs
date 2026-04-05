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

use acl::{
    AclRuleBuilder, AclTableBuilder, ActionSequence, Fate, FieldMatch,
    Ipv4Prefix, PortRange, Priority,
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

/// A rule spec that only produces IPv4+TCP rules with the same
/// field signature (eth + ipv4.src + tcp.dst).  This ensures all
/// rules land in a single DPDK ACL group with a fixed field count.
#[derive(Debug, Clone)]
struct Ipv4TcpRule {
    src_prefix: Ipv4Prefix,
    dst_port_range: PortRange<u16>,
    fate: Fate,
    priority: Priority,
}

impl TypeGenerator for Ipv4TcpRule {
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let src_prefix = driver.produce::<Ipv4Prefix>()?;
        let dst_port_range = driver.produce::<PortRange<u16>>()?;
        let fate = if driver.produce::<bool>()? {
            Fate::Forward
        } else {
            Fate::Drop
        };
        let priority = driver.produce::<Priority>()?;
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
                tcp.dst = FieldMatch::Select(self.dst_port_range);
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
        dst_port_range: PortRange<u16>,
        fate: Fate,
        priority: Priority,
    },
    Ipv4Udp {
        src_prefix: Ipv4Prefix,
        dst_port_range: PortRange<u16>,
        fate: Fate,
        priority: Priority,
    },
}

impl TypeGenerator for MixedRule {
    fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
        let src_prefix = driver.produce::<Ipv4Prefix>()?;
        let fate = if driver.produce::<bool>()? {
            Fate::Forward
        } else {
            Fate::Drop
        };
        let priority = driver.produce::<Priority>()?;

        match driver.produce::<u8>()? % 3 {
            0 => Some(MixedRule::Ipv4Only {
                src_prefix,
                fate,
                priority,
            }),
            1 => {
                let dst_port_range = driver.produce::<PortRange<u16>>()?;
                Some(MixedRule::Ipv4Tcp {
                    src_prefix,
                    dst_port_range,
                    fate,
                    priority,
                })
            }
            _ => {
                let dst_port_range = driver.produce::<PortRange<u16>>()?;
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
                    tcp.dst = FieldMatch::Select(*dst_port_range);
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
                    udp.dst = FieldMatch::Select(*dst_port_range);
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
/// first match (by rule index priority — lower userdata = earlier rule).
fn classify_through_dpdk(
    table: &acl::AclTable,
    groups: &[compiler::CompiledGroup],
    packet: &Headers,
) -> Fate {
    // Try each group; collect the match with lowest userdata (highest priority).
    let mut best_userdata: u32 = 0;

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
            // DPDK matched — check if this is a better (lower userdata = lower rule index) match.
            // We need to compare by the actual rule priority, not userdata directly.
            // For now, take the first match since groups contain non-overlapping signatures.
            if best_userdata == 0 {
                best_userdata = results[0];
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

/// Bolero fuzz: random IPv4+TCP rules, single signature group.
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

                assert_eq!(
                    linear_fate, dpdk_fate,
                    "linear vs DPDK disagree ({} rules, {} groups)",
                    table.rules().len(),
                    groups.len(),
                );
            }
        });
}
