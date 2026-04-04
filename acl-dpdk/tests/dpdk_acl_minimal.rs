// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Minimal DPDK ACL test following the exact pattern from the working
//! start_eal test in dpdk/src/acl/mod.rs.
//!
//! Uses a compact 2-field layout (wildcard byte + 4-byte IPv4 address)
//! to verify the basic pipeline works before adding complexity.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Once;

use dpdk::acl::config::{AclBuildConfig, AclCreateParams};
use dpdk::acl::context::AclContext;
use dpdk::acl::field::{FieldDef, FieldSize, FieldType};
use dpdk::acl::rule::{AclField, Rule, RuleData};
use dpdk::eal;
use dpdk::socket::SocketId;

static EAL_INIT: Once = Once::new();

fn init_eal() {
    EAL_INIT.call_once(|| {
        let _eal = eal::init(["test", "--no-huge", "--in-memory", "--no-pci"]);
        std::mem::forget(_eal);
    });
}

/// Minimal test: 2-field layout matching the working start_eal test pattern.
/// Tests /8 prefix matching on IPv4 addresses.
#[test]
fn minimal_ipv4_prefix_match() {
    init_eal();

    const N: usize = 2;

    let field_defs: [FieldDef; N] = [
        // Field 0: wildcard setup byte at offset 0
        FieldDef {
            field_type: FieldType::Bitmask,
            size: FieldSize::One,
            field_index: 0,
            input_index: 0,
            offset: 0,
        },
        // Field 1: IPv4 address at offset 4 (Mask with prefix length)
        FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 1,
            input_index: 1,
            offset: 4,
        },
    ];

    let params = AclCreateParams::new::<N>("minimal_test", SocketId::ANY, 16)
        .expect("create params");
    let mut ctx = AclContext::<N>::new(params).expect("new context");

    // Rule: match 10.0.0.0/8 (prefix length = 8)
    // Value 0x0A000000 = 10.0.0.0 in host byte order
    let rule = Rule::new(
        RuleData {
            category_mask: 1,
            priority: 1,
            userdata: 42.try_into().unwrap(),
        },
        [
            AclField::from_u8(0, 0),               // wildcard setup byte
            AclField::from_u32(0x0A000000, 8),      // 10.0.0.0/8
        ],
    );
    ctx.add_rules(&[rule]).expect("add rules");

    let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
    let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

    // Compact input buffer: [setup_byte, pad, pad, pad, ip[0], ip[1], ip[2], ip[3]]
    // IP address in network byte order (big-endian)

    // 10.1.2.3 — should match (10.x.x.x matches /8)
    let mut buf1 = [0u8; 8];
    buf1[4..8].copy_from_slice(&[10, 1, 2, 3]);

    // 192.168.1.1 — should NOT match
    let mut buf2 = [0u8; 8];
    buf2[4..8].copy_from_slice(&[192, 168, 1, 1]);

    // 10.255.0.1 — should match
    let mut buf3 = [0u8; 8];
    buf3[4..8].copy_from_slice(&[10, 255, 0, 1]);

    let data = [buf1.as_ptr(), buf2.as_ptr(), buf3.as_ptr()];
    let mut results = [0u32; 3];
    ctx.classify(&data, &mut results, 1).expect("classify");

    eprintln!("10.1.2.3   → userdata={}", results[0]);
    eprintln!("192.168.1.1 → userdata={}", results[1]);
    eprintln!("10.255.0.1  → userdata={}", results[2]);

    assert_eq!(results[0], 42, "10.1.2.3 should match 10.0.0.0/8");
    assert_eq!(results[1], 0, "192.168.1.1 should NOT match 10.0.0.0/8");
    assert_eq!(results[2], 42, "10.255.0.1 should match 10.0.0.0/8");
}

/// Test with 4 fields matching our compiler's layout:
/// [proto(Bitmask,1B), ethtype(Mask,2B), ipv4_src(Mask,4B), tcp_dst(Range,2B)]
#[test]
fn four_field_compact_layout() {
    init_eal();

    const N: usize = 4;

    // Minimal 4-field: same as 2-field test but with 2 extra wildcard fields.
    // This tests whether adding extra fields breaks the basic matching.
    const N2: usize = 4;

    let field_defs2: [FieldDef; N2] = [
        // Same as working 2-field test:
        FieldDef { field_type: FieldType::Bitmask, size: FieldSize::One,  field_index: 0, input_index: 0, offset: 0 },
        FieldDef { field_type: FieldType::Mask,    size: FieldSize::Four, field_index: 1, input_index: 1, offset: 4 },
        // Extra wildcard fields:
        FieldDef { field_type: FieldType::Mask,    size: FieldSize::Four, field_index: 2, input_index: 2, offset: 8 },
        FieldDef { field_type: FieldType::Range,   size: FieldSize::Two,  field_index: 3, input_index: 3, offset: 12 },
    ];

    let params2 = AclCreateParams::new::<N2>("four_field", SocketId::ANY, 16).expect("params");
    let mut ctx2 = AclContext::<N2>::new(params2).expect("context");

    // Rule: match 10.0.0.0/8 + port 80 (with byte-swapped range bounds)
    let rule2 = Rule::new(
        RuleData { category_mask: 1, priority: 1, userdata: 99.try_into().unwrap() },
        [
            AclField::from_u8(0, 0),              // wildcard proto
            AclField::from_u32(0x0A000000, 8),     // 10.0.0.0/8
            AclField::from_u32(0, 0),              // wildcard second IP
            // Range bounds must be in NBO-as-native representation
            // because DPDK reads the input bytes as native u16.
            // Port 80 in NBO bytes [0x00, 0x50] → LE u16 = 0x5000.
            AclField::from_u16(80, 80),  // host-order port 80
        ],
    );
    ctx2.add_rules(&[rule2]).expect("add rules");

    let build_cfg2 = AclBuildConfig::new(1, field_defs2, 0).expect("build config");
    let ctx2 = ctx2.build(&build_cfg2).map_err(|f| f.error).expect("build");

    // Buffer: 32 bytes (extra room)
    let mut buf2 = [0u8; 32];
    buf2[4..8].copy_from_slice(&0x0A010203u32.to_be_bytes()); // 10.1.2.3 NBO
    buf2[12..14].copy_from_slice(&80u16.to_be_bytes());       // port 80 NBO

    let data2 = [buf2.as_ptr()];
    let mut results2 = [0u32; 1];
    ctx2.classify(&data2, &mut results2, 1).expect("classify");

    eprintln!("4-field port test: result={}", results2[0]);
    assert_eq!(results2[0], 99, "should match 10.x.x.x port 80");
}
