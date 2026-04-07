// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Integration test: full DPDK ACL pipeline.
//!
//! Initializes a minimal DPDK EAL (no hugepages, in-memory only),
//! compiles ACL rules to a DPDK ACL context, classifies packets,
//! and verifies results match the linear-scan reference classifier.
//!
//! Run with: `cargo test -p dataplane-acl-dpdk --test dpdk_acl_classify`
//!
//! Requires: DPDK EAL environment (automatically set up with
//! `--no-huge --in-memory`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;

use acl::{IpPrefix, AclRuleBuilder, AclTableBuilder, Fate, FieldMatch, Ipv4Prefix, Priority};
use dpdk::acl::config::{AclBuildConfig, AclCreateParams};
use dpdk::acl::context::AclContext;
use dpdk::acl::rule::{AclField, Rule, RuleData};
use dpdk::socket::SocketId;
use net::headers::builder::HeaderStack;
use net::tcp::port::TcpPort;

use dataplane_acl_dpdk::compiler;
use dataplane_acl_dpdk::input;

mod common;

fn pri(n: u32) -> Priority {
    Priority::new(n).unwrap()
}

/// Build a 5-field DPDK ACL context from our compiled rules.
///
/// This is the "option 2" FFI bridge: assemble Rule<N> from
/// CompiledRule at a fixed N.  We use N=4 for the standard
/// eth_type + ipv4_proto + ipv4_src + tcp_dst layout.
#[test]
fn dpdk_acl_matches_linear_classifier() {
    common::test_eal();

    // Build the ACL table
    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src =
                        FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
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
                        Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 16).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.dst = FieldMatch::Select(80u16..=80u16);
                })
                .deny(pri(50)),
        )
        .build();

    // Compile to DPDK ACL format
    let groups = compiler::compile(&table);
    assert_eq!(groups.len(), 1, "expected single signature group");

    let group = &groups[0];
    let n = group.field_count();
    assert_eq!(
        n, 4,
        "expected 4 fields: proto, eth_type, ipv4_src, tcp_dst"
    );

    // Build the DPDK ACL context with N=4
    const N: usize = 4;
    let params = AclCreateParams::new::<N>("test_acl", SocketId::ANY, 16).expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    // Assemble Rule<4> from CompiledRule
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

    // Debug: print field defs and rules
    for (i, fd) in group.field_defs().iter().enumerate() {
        eprintln!(
            "FieldDef[{i}]: type={:?} size={:?} field_index={} input_index={} offset={}",
            fd.field_type, fd.size, fd.field_index, fd.input_index, fd.offset
        );
    }
    for (i, cr) in group.rules().iter().enumerate() {
        eprintln!(
            "Rule[{i}]: category_mask={} priority={} userdata={}",
            cr.data.category_mask, cr.data.priority, cr.data.userdata
        );
        for (j, f) in cr.fields.iter().enumerate() {
            eprintln!("  Field[{j}]: {f}");
        }
    }

    ctx.add_rules(&rules).expect("add rules");

    // Build with field defs
    let mut field_defs = [group.field_defs()[0]; N];
    for (i, fd) in group.field_defs().iter().enumerate() {
        field_defs[i] = *fd;
    }
    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).expect("build context");

    // Test packets
    let test_cases: Vec<(Ipv4Addr, u16, Fate)> = vec![
        // 10.1.2.3:80 — matches both rules, pri 50 (deny) wins
        (Ipv4Addr::new(10, 1, 2, 3), 80, Fate::Drop),
        // 10.2.0.1:80 — matches /8 rule only → permit
        (Ipv4Addr::new(10, 2, 0, 1), 80, Fate::Accept),
        // 192.168.1.1:80 — matches neither → default drop
        (Ipv4Addr::new(192, 168, 1, 1), 80, Fate::Drop),
        // 10.1.2.3:443 — matches neither (wrong port) → default drop
        (Ipv4Addr::new(10, 1, 2, 3), 443, Fate::Drop),
    ];

    let linear = table.compile();
    let sig = group.signature();

    for (src_ip, dst_port, expected_fate) in &test_cases {
        // Build headers
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(net::ipv4::UnicastIpv4Addr::new(*src_ip).unwrap());
            })
            .tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(*dst_port).unwrap());
            })
            .build_headers()
            .unwrap();

        // Linear classifier result
        let linear_fate = linear.classify(&headers, &()).fate();

        // DPDK ACL result — compact buffer
        let acl_input = input::assemble_compact_input(&headers, sig);
        // Dump first 12 bytes of compact buffer
        let p = acl_input.as_ptr();
        let slice = unsafe { std::slice::from_raw_parts(p, 12) };
        eprintln!("Compact buf for {src_ip}:{dst_port}: {:02x?}", slice);

        let data = [acl_input.as_ptr()];
        let mut results = [0u32; 1];
        ctx.classify(&data, &mut results, 1).expect("classify");
        eprintln!("  DPDK result: userdata={}", results[0]);
        let dpdk_fate = compiler::resolve_fate(&table, results[0], Fate::Drop);

        // Both must agree
        assert_eq!(
            linear_fate, *expected_fate,
            "linear classifier mismatch for {src_ip}:{dst_port}"
        );
        assert_eq!(
            dpdk_fate, *expected_fate,
            "DPDK ACL mismatch for {src_ip}:{dst_port} (userdata={})",
            results[0]
        );
        assert_eq!(
            linear_fate, dpdk_fate,
            "linear vs DPDK disagree for {src_ip}:{dst_port}"
        );
    }
}
