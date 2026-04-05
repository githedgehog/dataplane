// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Minimal reproduction of the 3-field DPDK ACL classification issue.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;

use acl::{
    AclRuleBuilder, AclTableBuilder, Fate, FieldMatch,
    Ipv4Prefix, Priority,
};
use dpdk::acl::config::{AclBuildConfig, AclCreateParams};
use dpdk::acl::context::AclContext;
use dpdk::acl::rule::{AclField, Rule};
use dpdk::socket::SocketId;
use net::headers::builder::HeaderStack;

use dataplane_acl_dpdk::compiler;
use dataplane_acl_dpdk::input;

mod common;

fn pri(n: u32) -> Priority {
    Priority::new(n).unwrap()
}

/// Hand-crafted 3-field test with 4-byte-aligned offsets.
/// Tests whether the issue is the offset alignment, not the field count.
#[test]
fn three_fields_aligned_offsets() {
    use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
    use dpdk::acl::rule::RuleData;

    common::test_eal();

    const N: usize = 3;

    // Layout: setup(1B) at offset 0, ipv4_src(4B) at offset 4,
    // eth_type(2B) at offset 8.  All on 4-byte boundaries.
    let field_defs: [FieldDef; N] = [
        FieldDef {
            field_type: FieldType::Bitmask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Two,
            field_index: 2,
            input_index: 2,
            offset: 8,
        },
    ];

    let params = AclCreateParams::new::<N>("align_test", SocketId::ANY, 1)
        .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    // Rule: wildcard setup + 172.16.0.0/12 + eth_type 0x0800/16
    let rule = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 1.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),            // wildcard setup
            AclField::from_u32(0xAC100000, 12),  // 172.16.0.0/12
            AclField::from_u16(0x0800, 16),      // IPv4 ether_type exact
        ],
    );
    ctx.add_rules(&[rule]).expect("add rules");

    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

    // Input buffer: [setup, pad, pad, pad, ip[0..4], ethtype[0..2], pad, pad]
    // 172.16.1.1 + 0x0800
    let mut buf = [0u8; 12];
    buf[4..8].copy_from_slice(&[172, 16, 1, 1]); // NBO
    buf[8..10].copy_from_slice(&[0x08, 0x00]);   // NBO

    let data = [buf.as_ptr()];
    let mut results = [0u32; 1];
    ctx.classify(&data, &mut results, 1).expect("classify");
    eprintln!("Aligned 3-field: userdata={}", results[0]);
    assert_eq!(results[0], 1, "should match 172.16.0.0/12 + 0x0800");

    // Non-matching: wrong IP
    let mut buf2 = [0u8; 12];
    buf2[4..8].copy_from_slice(&[192, 168, 1, 1]);
    buf2[8..10].copy_from_slice(&[0x08, 0x00]);

    let data2 = [buf2.as_ptr()];
    let mut results2 = [0u32; 1];
    ctx.classify(&data2, &mut results2, 1).expect("classify");
    eprintln!("Aligned 3-field non-match: userdata={}", results2[0]);
    assert_eq!(results2[0], 0, "should NOT match");
}

/// Test: 3 fields but the third is a 4-byte Mask (not 2-byte).
/// Isolates whether 2-byte Mask fields are the issue.
#[test]
fn three_fields_all_four_byte() {
    use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
    use dpdk::acl::rule::RuleData;

    common::test_eal();

    const N: usize = 3;

    // Layout: setup(1B)@0, ipv4_src(4B)@4, ipv4_dst(4B)@8
    let field_defs: [FieldDef; N] = [
        FieldDef {
            field_type: FieldType::Bitmask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 2,
            input_index: 2,
            offset: 8,
        },
    ];

    let params = AclCreateParams::new::<N>("3x4B_test", SocketId::ANY, 1)
        .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    let rule = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 1.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),            // wildcard setup
            AclField::from_u32(0xAC100000, 12),  // 172.16.0.0/12
            AclField::from_u32(0x0A000000, 8),   // 10.0.0.0/8
        ],
    );
    ctx.add_rules(&[rule]).expect("add rules");

    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

    // 172.16.1.1 → 10.0.0.1
    let mut buf = [0u8; 12];
    buf[4..8].copy_from_slice(&[172, 16, 1, 1]);
    buf[8..12].copy_from_slice(&[10, 0, 0, 1]);

    let data = [buf.as_ptr()];
    let mut results = [0u32; 1];
    ctx.classify(&data, &mut results, 1).expect("classify");
    eprintln!("3x4B: userdata={}", results[0]);
    assert_eq!(results[0], 1, "should match src=172.16/12 dst=10/8");
}

/// Test: 3 fields with a 2-byte Range field (like port) as the 3rd field.
#[test]
fn three_fields_with_range() {
    use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
    use dpdk::acl::rule::RuleData;

    common::test_eal();

    const N: usize = 3;

    // Layout: setup(1B)@0, ipv4_src(4B)@4, port(2B Range)@8
    let field_defs: [FieldDef; N] = [
        FieldDef {
            field_type: FieldType::Bitmask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
        FieldDef {
            field_type: FieldType::Range,
            size: FieldSize::Two,
            field_index: 2,
            input_index: 2,
            offset: 8,
        },
    ];

    let params = AclCreateParams::new::<N>("range_test", SocketId::ANY, 1)
        .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    let rule = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 1.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),            // wildcard setup
            AclField::from_u32(0xAC100000, 12),  // 172.16.0.0/12
            AclField::from_u16(80, 80),          // port 80 exact
        ],
    );
    ctx.add_rules(&[rule]).expect("add rules");

    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

    // 172.16.1.1, port 80 (NBO: 0x0050)
    let mut buf = [0u8; 12];
    buf[4..8].copy_from_slice(&[172, 16, 1, 1]);
    buf[8..10].copy_from_slice(&[0x00, 0x50]); // port 80 NBO

    let data = [buf.as_ptr()];
    let mut results = [0u32; 1];
    ctx.classify(&data, &mut results, 1).expect("classify");
    eprintln!("3-field with Range: userdata={}", results[0]);
    assert_eq!(results[0], 1, "should match src=172.16/12 port=80");
}

/// Test: 3 fields with a 2-byte Mask field as the 3rd field.
/// This is the specific case that fails.
#[test]
fn three_fields_with_2byte_mask() {
    use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
    use dpdk::acl::rule::RuleData;

    common::test_eal();

    const N: usize = 3;

    // Layout: setup(1B)@0, ipv4_src(4B)@4, ethtype(2B Mask)@8
    let field_defs: [FieldDef; N] = [
        FieldDef {
            field_type: FieldType::Bitmask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Two,
            field_index: 2,
            input_index: 2,
            offset: 8,
        },
    ];

    let params = AclCreateParams::new::<N>("mask2b_test", SocketId::ANY, 1)
        .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    // Try different value encodings for 0x0800 eth_type
    // Value 0x0800 with prefix 16 (exact match)
    let rule = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 1.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),
            AclField::from_u32(0xAC100000, 12),
            AclField::from_u16(0x0800, 16),  // 0x0800 exact (prefix=16)
        ],
    );
    ctx.add_rules(&[rule]).expect("add rules");

    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

    // Try NBO encoding: 0x0800 → [0x08, 0x00]
    let mut buf_nbo = [0u8; 12];
    buf_nbo[4..8].copy_from_slice(&[172, 16, 1, 1]);
    buf_nbo[8..10].copy_from_slice(&[0x08, 0x00]);

    let data = [buf_nbo.as_ptr()];
    let mut results = [0u32; 1];
    ctx.classify(&data, &mut results, 1).expect("classify");
    eprintln!("2B Mask NBO [08,00]: userdata={}", results[0]);

    // Try HBO encoding: 0x0800 → [0x00, 0x08] on LE
    let mut buf_hbo = [0u8; 12];
    buf_hbo[4..8].copy_from_slice(&[172, 16, 1, 1]);
    buf_hbo[8..10].copy_from_slice(&0x0800u16.to_le_bytes());

    let data2 = [buf_hbo.as_ptr()];
    let mut results2 = [0u32; 1];
    ctx.classify(&data2, &mut results2, 1).expect("classify");
    eprintln!("2B Mask HBO [00,08]: userdata={}", results2[0]);

    // At least one encoding should match
    assert!(
        results[0] == 1 || results2[0] == 1,
        "neither NBO nor HBO encoding matched for 2-byte Mask field"
    );
}

/// Test: what if 2-byte field shares input_index with the 4-byte field?
/// In l3fwd, src_port and dst_port share the same input_index.
/// Maybe a lone 2-byte field at its own input_index is the problem.
#[test]
fn two_byte_field_shared_input_index() {
    use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
    use dpdk::acl::rule::RuleData;

    common::test_eal();

    const N: usize = 3;

    // Put the 2-byte field right after the 4-byte field in the same
    // 4-byte word.  ipv4_src(4B)@4 with input_index=1,
    // ethtype(2B)@8 with input_index=2.
    //
    // Actually, try: put two 2-byte fields at the same input_index.
    // setup(1B)@0 ii=0, ipv4_src(4B)@4 ii=1, port_lo(2B)@8 ii=2, port_hi(2B)@10 ii=2
    // But that needs 4 fields...
    //
    // Instead: just use 4 fields like the working tests.
    // setup + ipv4_src + dummy_4B + eth_type_as_range
    // This tests whether padding the field count to >=4 matters.

    const N4: usize = 4;

    let field_defs: [FieldDef; N4] = [
        FieldDef {
            field_type: FieldType::Bitmask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
        // Dummy wildcard 4-byte field to pad to 4 fields
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 2,
            input_index: 2,
            offset: 8,
        },
        // eth_type as 2-byte at offset 12, sharing nothing
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Two,
            field_index: 3,
            input_index: 3,
            offset: 12,
        },
    ];

    let params = AclCreateParams::new::<N4>("pad_test", SocketId::ANY, 1)
        .expect("create params");
    let mut ctx = AclContext::<N4>::new(params).expect("create context");

    let rule = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 1.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),            // wildcard setup
            AclField::from_u32(0xAC100000, 12),  // 172.16.0.0/12
            AclField::from_u32(0, 0),            // wildcard dummy
            AclField::from_u16(0x0800, 16),      // eth_type exact
        ],
    );
    ctx.add_rules(&[rule]).expect("add rules");

    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

    let mut buf = [0u8; 16];
    buf[4..8].copy_from_slice(&[172, 16, 1, 1]);
    // dummy at 8..12 = 0
    buf[12..14].copy_from_slice(&[0x08, 0x00]);

    let data = [buf.as_ptr()];
    let mut results = [0u32; 1];
    ctx.classify(&data, &mut results, 1).expect("classify");
    eprintln!("Padded 4-field with 2B Mask: userdata={}", results[0]);

    // Try with byte-swapped value
    let params2 = AclCreateParams::new::<N4>("pad_test2", SocketId::ANY, 1)
        .expect("create params");
    let mut ctx2 = AclContext::<N4>::new(params2).expect("create context");

    let rule2 = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 2.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),
            AclField::from_u32(0xAC100000, 12),
            AclField::from_u32(0, 0),
            AclField::from_u16(0x0008, 16),  // byte-swapped 0x0800
        ],
    );
    ctx2.add_rules(&[rule2]).expect("add rules");

    let build_cfg2 = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx2 = ctx2.build(&build_cfg2).map_err(|f| f.error).expect("build");

    let data2 = [buf.as_ptr()];
    let mut results2 = [0u32; 1];
    ctx2.classify(&data2, &mut results2, 1).expect("classify");
    eprintln!("Padded 4-field with swapped value: userdata={}", results2[0]);

    assert!(
        results[0] == 1 || results2[0] == 2,
        "neither native nor swapped value matched for 2B Mask"
    );
}

/// Minimal: just setup + 2-byte Mask wildcard. Does classification work?
#[test]
fn two_fields_2byte_mask_wildcard() {
    use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
    use dpdk::acl::rule::RuleData;

    common::test_eal();

    const N: usize = 2;

    let field_defs: [FieldDef; N] = [
        FieldDef {
            field_type: FieldType::Bitmask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Two,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
    ];

    let params = AclCreateParams::new::<N>("2f_2b", SocketId::ANY, 1)
        .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    // Wildcard 2-byte mask — should match everything.
    let rule = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 1.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),   // wildcard setup
            AclField::from_u16(0, 0),  // wildcard 2B mask (value=0, prefix=0)
        ],
    );
    ctx.add_rules(&[rule]).expect("add rules");

    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

    let buf = [0u8; 8]; // all zeros
    let data = [buf.as_ptr()];
    let mut results = [0u32; 1];
    ctx.classify(&data, &mut results, 1).expect("classify");
    eprintln!("2-field 2B Mask wildcard: userdata={}", results[0]);
    assert_eq!(results[0], 1, "wildcard 2B Mask should match anything");
}

/// Test 2-byte Mask with actual value (0x0800, prefix=16).
#[test]
fn two_fields_2byte_mask_exact() {
    use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
    use dpdk::acl::rule::RuleData;

    common::test_eal();

    const N: usize = 2;

    let field_defs: [FieldDef; N] = [
        FieldDef {
            field_type: FieldType::Bitmask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Two,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
    ];

    let params = AclCreateParams::new::<N>("2f_exact", SocketId::ANY, 2)
        .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("create context");

    // Rule 1: 0x0800, prefix=16 (exact match in host byte order)
    let rule1 = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 1.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),
            AclField::from_u16(0x0800, 16),
        ],
    );
    // Rule 2: byte-swapped 0x0008, prefix=16
    let rule2 = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 2,
            userdata: 2.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),
            AclField::from_u16(0x0008, 16),
        ],
    );
    ctx.add_rules(&[rule1, rule2]).expect("add rules");

    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

    // Input: NBO 0x0800 → [0x08, 0x00]
    let mut buf = [0u8; 8];
    buf[4..6].copy_from_slice(&[0x08, 0x00]);

    let data = [buf.as_ptr()];
    let mut results = [0u32; 1];
    ctx.classify(&data, &mut results, 1).expect("classify");
    eprintln!(
        "2B Mask exact with NBO [08,00]: userdata={} (rule1=0x0800 → {}, rule2=0x0008 → {})",
        results[0],
        if results[0] == 1 { "MATCH" } else { "no" },
        if results[0] == 2 { "MATCH" } else { "no" },
    );

    assert!(
        results[0] == 1 || results[0] == 2,
        "at least one rule should match"
    );
}

/// Single IPv4-only rule (no transport), through DPDK ACL.
/// This is the minimal reproduction of the 3-field issue.
#[test]
#[ignore = "investigating 3-field DPDK ACL issue"]
fn single_ipv4_only_rule() {
    common::test_eal();

    let table = AclTableBuilder::new(Fate::Drop)
        .add_rule(
            AclRuleBuilder::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.src = FieldMatch::Select(
                        Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12).unwrap(),
                    );
                })
                .permit(pri(100)),
        )
        .build();

    let groups = compiler::compile(&table);
    assert_eq!(groups.len(), 1);
    let group = &groups[0];

    eprintln!("Field count: {}", group.field_count());
    for (i, fd) in group.field_defs().iter().enumerate() {
        eprintln!(
            "  FieldDef[{i}]: type={:?} size={:?} fi={} ii={} offset={}",
            fd.field_type, fd.size, fd.field_index, fd.input_index, fd.offset
        );
    }
    for (i, cr) in group.rules().iter().enumerate() {
        eprintln!(
            "  Rule[{i}]: pri={} userdata={}",
            cr.data.priority, cr.data.userdata
        );
        for (j, f) in cr.fields.iter().enumerate() {
            eprintln!("    Field[{j}]: {f}");
        }
    }

    let n = group.field_count();
    eprintln!("Building context with N={n}");

    // Build the context with the right N
    match n {
        3 => {
            const N: usize = 3;
            let params = AclCreateParams::new::<N>("debug3", SocketId::ANY, 1)
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
                    Rule { data: cr.data, fields }
                })
                .collect();

            ctx.add_rules(&rules).expect("add rules");

            let mut field_defs = [group.field_defs()[0]; N];
            for (i, fd) in group.field_defs().iter().enumerate() {
                field_defs[i] = *fd;
            }
            let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
            let ctx = ctx.build(&build_cfg).expect("build context");

            // Test packet: 172.16.1.1 (should match /12)
            let pkt = HeaderStack::new()
                .eth(|_| {})
                .ipv4(|ip| {
                    ip.set_source(
                        net::ipv4::UnicastIpv4Addr::new(Ipv4Addr::new(172, 16, 1, 1)).unwrap(),
                    );
                })
                .tcp(|tcp| {
                    tcp.set_destination(net::tcp::port::TcpPort::new_checked(80).unwrap());
                })
                .build_headers()
                .unwrap();

            let sig = group.signature();
            let acl_input = input::assemble_compact_input(&pkt, sig);
            let p = acl_input.as_ptr();
            let slice = unsafe { std::slice::from_raw_parts(p, 12) };
            eprintln!("Compact buffer: {:02x?}", slice);

            let data = [acl_input.as_ptr()];
            let mut results = [0u32; 1];
            ctx.classify(&data, &mut results, 1).expect("classify");
            eprintln!("Result: userdata={}", results[0]);

            let dpdk_fate = compiler::resolve_fate(&table, results[0], Fate::Drop);
            let linear = table.compile();
            let linear_fate = linear.classify(&pkt, &()).fate();

            eprintln!("Linear: {linear_fate:?}, DPDK: {dpdk_fate:?}");
            assert_eq!(linear_fate, Fate::Forward, "linear should match");
            assert_eq!(dpdk_fate, Fate::Forward, "DPDK should match");
        }
        other => panic!("unexpected field count {other}"),
    }
}
