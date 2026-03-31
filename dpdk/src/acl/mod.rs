// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Safe Rust abstraction over DPDK's ACL (Access Control List) library.
//!
//! This module provides a safe, idiomatic Rust interface to DPDK's packet classification engine.
//! The ACL library builds an optimised trie from a set of rules and uses SIMD-accelerated search
//! to classify input data buffers against those rules at high throughput.
//!
//! # Lifecycle
//!
//! The ACL context follows a **typestate** lifecycle enforced at compile time:
//!
//! ```text
//!                   add_rules(&mut)
//!                  ┌──────────────┐
//!                  │              │
//!                  ▼              │
//!   new() ──▶ Configuring ───build()───▶ Built ───classify(&)───▶ results
//!                  ▲                       │
//!                  │                       │
//!                  └────────reset()────────┘
//! ```
//!
//! - [`AclContext<N, Configuring>`][context::AclContext] — accepts rule mutations via `&mut self`.
//!   The Rust borrow checker enforces DPDK's documented constraint that rule addition and
//!   compilation are **not thread-safe**.
//!
//! - [`AclContext<N, Built>`][context::AclContext] — supports packet classification via `&self`.
//!   Because classification is documented by DPDK as **thread-safe**, the `Sync` implementation
//!   allows safe concurrent access from multiple threads (e.g. via `Arc`).
//!
//! # Type safety
//!
//! The const generic parameter `N` (number of fields per rule) is shared across
//! [`AclContext`][context::AclContext], [`Rule`][rule::Rule], and
//! [`AclBuildConfig`][config::AclBuildConfig].  A field-count mismatch between any of these types
//! is caught at compile time.
//!
//! # Byte order
//!
//! Rule field values must be in **host byte order** (LSB), while input data buffers passed to
//! [`classify`][context::AclContext::classify] must be in **network byte order** (MSB).  DPDK
//! handles the conversion internally during trie construction.
//!
//! # `mask_range` interpretation
//!
//! The meaning of [`AclField::mask_range`][rule::AclField] depends on the
//! [`FieldType`][field::FieldType]:
//!
//! | [`FieldType`][field::FieldType] | `mask_range` meaning |
//! |--------------------------------|----------------------|
//! | [`Mask`][field::FieldType::Mask]       | **prefix length** — number of most-significant bits to compare (e.g. `32` for exact match, `24` for `/24`) |
//! | [`Range`][field::FieldType::Range]     | **upper bound** of the range (`value` is the lower bound) |
//! | [`Bitmask`][field::FieldType::Bitmask] | **bitmask** applied to input before comparison |
//!
//! # Example
//!
//! ```ignore
//! use dpdk::acl::*;
//! use dpdk::socket::SocketId;
//!
//! // Define a simple 5-tuple IPv4 ACL layout (5 fields).
//! const NUM_FIELDS: usize = 5;
//!
//! let field_defs: [FieldDef; NUM_FIELDS] = [
//!     FieldDef { field_type: FieldType::Bitmask, size: FieldSize::One,  field_index: 0, input_index: 0, offset: 0  },
//!     FieldDef { field_type: FieldType::Mask,    size: FieldSize::Four, field_index: 1, input_index: 1, offset: 2  },
//!     FieldDef { field_type: FieldType::Mask,    size: FieldSize::Four, field_index: 2, input_index: 2, offset: 6  },
//!     FieldDef { field_type: FieldType::Range,   size: FieldSize::Two,  field_index: 3, input_index: 3, offset: 10 },
//!     FieldDef { field_type: FieldType::Range,   size: FieldSize::Two,  field_index: 4, input_index: 3, offset: 12 },
//! ];
//!
//! // 1. Create a context (Configuring state).
//! let params = AclCreateParams::new::<NUM_FIELDS>("my_acl", SocketId::ANY, 1024)?;
//! let mut ctx = AclContext::<NUM_FIELDS>::new(params)?;
//!
//! // 2. Add rules — Rule<5> is enforced by the type system.
//! let rule = Rule::new(
//!     RuleData { category_mask: 1, priority: 1, userdata: 42 },
//!     [
//!         AclField::from_u8(6, 0xFF),            // TCP protocol (bitmask)
//!         AclField::from_u32(0xC0A80100, 24),    // 192.168.1.0/24  (prefix length)
//!         AclField::from_u32(0x0A000100, 24),    // 10.0.1.0/24     (prefix length)
//!         AclField::from_u16(0, u16::MAX),       // any src port    (range)
//!         AclField::from_u16(80, 80),            // dst port 80     (range)
//!     ],
//! );
//! ctx.add_rules(&[rule])?;
//!
//! // 3. Build (transitions Configuring → Built).
//! let build_cfg = AclBuildConfig::new(1, field_defs, 0)?;
//! let ctx = ctx.build(&build_cfg).map_err(|f| f.error)?;
//!
//! // 4. Classify packets (hot path, &self, thread-safe).
//! let mut results = vec![0u32; packet_ptrs.len()];
//! ctx.classify(&packet_ptrs, &mut results, 1)?;
//!
//! // results[i] == 0  → no match
//! // results[i] == 42 → matched our rule
//! ```
//!
//! # Modules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`classify`] | [`ClassifyAlgorithm`] — SIMD backend selection |
//! | [`config`]   | [`AclCreateParams`], [`AclBuildConfig`] — validated configuration types |
//! | [`context`]  | [`AclContext`] — the typestate context (create, add, build, classify) |
//! | [`error`]    | Dedicated error types for each fallible operation |
//! | [`field`]    | [`FieldDef`], [`FieldType`], [`FieldSize`] — rule field layout |
//! | [`rule`]     | [`Rule`], [`RuleData`], [`AclField`] — rule value types |

#![deny(clippy::all)]

pub mod classify;
pub mod config;
pub mod context;
pub mod error;
pub mod field;
pub mod rule;

#[cfg(test)]
pub mod round3;

// ---------------------------------------------------------------------------
// Convenience re-exports
// ---------------------------------------------------------------------------

// Context & typestate markers
pub use context::{AclBuildFailure, AclContext, Built, Configuring};

// Configuration
pub use config::{AclBuildConfig, AclCreateParams, InvalidAclBuildConfig};
pub use config::{MAX_CATEGORIES, MAX_FIELDS, RESULTS_MULTIPLIER};

// Rules & fields
pub use field::{FieldDef, FieldSize, FieldType};
pub use rule::{AclField, Rule, RuleData};

// Classification algorithm
pub use classify::ClassifyAlgorithm;

// Errors
pub use error::{
    AclAddRulesError, AclBuildError, AclClassifyError, AclCreateError, AclSetAlgorithmError,
    InvalidAclName,
};

// Module-level utilities
pub use context::dump_all_contexts;

#[cfg(test)]
mod tests {
    use rstar::RTreeObject;

    #[derive(Debug)]
    struct Box {
        name: String,
        rect: [[i8; 2]; 2],
    }

    impl rstar::RTreeObject for Box {
        type Envelope = rstar::AABB<[i8; 2]>;

        fn envelope(&self) -> Self::Envelope {
            rstar::AABB::from_corners(self.rect[0], self.rect[1])
        }
    }

    #[test]
    fn yyy() {
        let box1 = Box {
            name: "Hello world".into(),
            rect: [[0, 0], [2, 2]],
        };
        let box2 = Box {
            name: "science world".into(),
            rect: [[1, 1], [3, 3]],
        };
        let box3 = Box {
            name: "science world".into(),
            rect: [[2, 3], [3, 4]],
        };
        let mut tree = rstar::RTree::new();
        tree.insert(box1);
        tree.insert(box2);
        for x in tree.locate_in_envelope_intersecting(&box3.envelope()) {
            println!("{x:?}", x = x);
        }
    }

    #[test]
    fn xxx() {
        let mut tree1 = rstar::RTree::new();
        let mut tree2 = rstar::RTree::new();
        tree1.insert([1, 2]);
        tree1.insert([2, 3]);
        tree2.insert([1, 2]);
        tree2.insert([9, 129]);
        // tree.insert([2i128,2,3]);
        // let space = rstar::AABB::from_corners([0, 0, 0], [9, 9, 9]);
        // for x in tree1.locate_in_envelope_intersecting(&space) {
        //     println!("{x}, {y}, {z}", x = x[0], y = x[1], z = x[2]);
        // }
    }

    #[test]
    fn start_eal() {
        let _eal =
            super::super::eal::init(["--no-huge", "--no-pci", "--in-memory", "--iova-mode=va"]);

        use crate::acl::*;
        use crate::socket::SocketId;
        const NUM_FIELDS: usize = 2;

        // DPDK ACL requires the first field in the rule definition to be one
        // byte long (it is consumed during trie setup).  All subsequent fields
        // must be grouped into sets of 4 consecutive bytes via `input_index`.
        let field_defs: [FieldDef; NUM_FIELDS] = [
            // Field 0: 1-byte entry at offset 0 (required by DPDK to be 1 byte).
            // Using Bitmask with value=0, mask=0 acts as a wildcard.
            FieldDef {
                field_type: FieldType::Bitmask,
                size: FieldSize::One,
                field_index: 0,
                input_index: 0,
                offset: 0,
            },
            // Field 1: 4-byte Mask field at offset 4, input_index 1.
            FieldDef {
                field_type: FieldType::Mask,
                size: FieldSize::Four,
                field_index: 1,
                input_index: 1,
                offset: 4,
            },
        ];

        // 1. Create a context in the Configuring state.
        let params = AclCreateParams::new::<NUM_FIELDS>("test_acl", SocketId::ANY, 16)
            .expect("create params");
        let mut ctx = AclContext::<NUM_FIELDS>::new(params).expect("new context");

        // 2. Add a single rule that exact-matches the value 0xDEADBEEF.
        //
        //    For FieldType::Mask the mask_range is a **prefix length** (number
        //    of most-significant bits to compare), NOT a bitmask.  Use 32 for
        //    an exact match on a 4-byte field.
        //
        //    Rule values are in **host byte order** as documented by DPDK.
        let rule = Rule::new(
            RuleData {
                category_mask: 1,
                priority: 1,
                userdata: 1.try_into().unwrap(),
            },
            [
                AclField::from_u8(0, 0),            // wildcard entry byte
                AclField::from_u32(0xDEADBEEF, 32), // exact match (prefix length = 32)
            ],
        );
        ctx.add_rules(&[rule]).expect("add rules");

        // 3. Build the context (Configuring → Built).
        let build_cfg = AclBuildConfig::new(1, field_defs, 0).expect("build config");
        let ctx = ctx.build(&build_cfg).map_err(|f| f.error).expect("build");

        // 4. Classify a matching and a non-matching input.
        //
        //    Input data must be in **network byte order** (MSB).
        //
        //    Buffer layout (8 bytes):
        //      [0]   : 1-byte entry (don't-care, matched by wildcard field 0)
        //      [1..4]: padding (not referenced by any field definition)
        //      [4..8]: 4-byte value in network byte order (matched by field 1)
        let mut matching = [0u8; 8];
        matching[4..8].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());

        let non_matching = [0u8; 8]; // value at offset 4 is 0x00000000

        let data_ptrs: Vec<*const u8> = vec![matching.as_ptr(), non_matching.as_ptr()];
        let mut results = vec![0u32; 2];
        ctx.classify(&data_ptrs, &mut results, 1).expect("classify");

        // The first input should match (userdata == 1), the second should not (0).
        assert_eq!(results[0], 1, "expected match for 0xDEADBEEF");
        assert_eq!(results[1], 0, "expected no match for 0x00000000");
    }
}
