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
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Configuring: new()
//!     Configuring --> Configuring: add_rules(&mut)
//!     Configuring --> Built: build()
//!     Built --> Configuring: reset()
//!     Built --> Built: classify(&) -> results
//! ```
//!
//! - [`AclContext<N, Configuring>`][context::AclContext] -- accepts rule mutations via `&mut self`.
//!   The Rust borrow checker enforces DPDK's documented constraint that rule addition and
//!   compilation are **not thread-safe**.
//!
//! - [`AclContext<N, Built>`][context::AclContext] -- supports packet classification via `&self`.
//!   Because classification is documented by DPDK as **thread-safe**, the `Sync` implementation
//!   allows safe concurrent access from multiple threads (e.g. via `Arc`).
//!
//! # Type safety
//!
//! The const generic parameter `N` (number of fields per rule) is shared across
//! [`AclContext`], [`Rule`], and [`AclBuildConfig`].  A field-count mismatch between any of
//! these types is caught at compile time.
//!
//! # Byte order
//!
//! Rule field values must be in **host byte order** (the native endianness of the build target),
//! while input data buffers passed to
//! [`classify`][context::AclContext::classify] must be in **network byte order** (MSB).  DPDK
//! handles the conversion internally during trie construction.
//!
//! The wrapper is developed and tested on little-endian targets (x86_64, aarch64).  Big-endian
//! targets are not currently exercised; see [`Rule::validate`][rule::Rule::validate] for the
//! soundness guards that catch the most common endian-related footgun.
//!
//! # `mask_range` interpretation
//!
//! The meaning of the `mask_range` value inside an [`AclField`] depends on the
//! [`FieldType`]:
//!
//! | [`FieldType`]                          | `mask_range` meaning |
//! |----------------------------------------|----------------------|
//! | [`FieldType::Mask`]                    | **prefix length** -- number of most-significant bits to compare (e.g. `32` for exact match, `24` for `/24`) |
//! | [`FieldType::Range`]                   | **upper bound** of the range (`value` is the lower bound) |
//! | [`FieldType::Bitmask`]                 | **bitmask** applied to input before comparison |
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use core::num::NonZero;
//!
//! use dataplane_dpdk::acl::*;
//! use dataplane_dpdk::socket::SocketId;
//!
//! // Define a simple 5-tuple IPv4 ACL layout (5 fields).
//! const NUM_FIELDS: usize = 5;
//!
//! let field_defs: [FieldDef; NUM_FIELDS] = [
//!     FieldDef::new(FieldType::Bitmask, FieldSize::One,  0, 0, 0),
//!     FieldDef::new(FieldType::Mask,    FieldSize::Four, 1, 1, 2),
//!     FieldDef::new(FieldType::Mask,    FieldSize::Four, 2, 2, 6),
//!     FieldDef::new(FieldType::Range,   FieldSize::Two,  3, 3, 10),
//!     FieldDef::new(FieldType::Range,   FieldSize::Two,  4, 3, 12),
//! ];
//!
//! // 1. Create a context (Configuring state).  The build config is
//! //    supplied up front so that add_rules can validate each rule's
//! //    field values against the layout.
//! let params = AclCreateParams::<NUM_FIELDS>::new(
//!     "my_acl",
//!     SocketId::ANY,
//!     NonZero::new(1024).unwrap(),
//! )?;
//! let build_cfg = AclBuildConfig::new(1, field_defs, 0)?;
//! let mut ctx = AclContext::new(params, build_cfg)?;
//!
//! // 2. Add rules -- Rule<5> is enforced by the type system.
//! let rule = Rule::new(
//!     RuleData {
//!         category_mask: CategoryMask::new(1)?,
//!         priority: Priority::new(1)?,
//!         userdata: NonZero::new(42).unwrap(),
//!     },
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
//! // 3. Build (transitions Configuring -> Built; uses the config from new()).
//! let ctx = ctx.build().map_err(|f| f.error)?;
//!
//! // 4. Classify packets (hot path, &self, thread-safe).
//! //    `classify` is `unsafe`: each pointer in `packet_ptrs` must reference
//! //    a buffer valid for at least `ctx.build_config().min_input_size()`
//! //    bytes -- DPDK loads 4 bytes per `input_index` group, so the safety
//! //    contract is wider than `max(offset + size)`.
//! let packet_ptrs: Vec<*const u8> = Vec::new(); // populated by caller
//! let mut results = vec![0u32; packet_ptrs.len()];
//! unsafe { ctx.classify(&packet_ptrs, &mut results, 1)?; }
//!
//! // results[i] == 0  -> no match
//! // results[i] == 42 -> matched our rule
//! # Ok(())
//! # }
//! ```
//!
//! # Modules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`classify`] | [`ClassifyAlgorithm`] -- SIMD backend selection |
//! | [`config`]   | [`AclCreateParams`], [`AclBuildConfig`] -- validated configuration types |
//! | [`context`]  | [`AclContext`] -- the typestate context (create, add, build, classify) |
//! | [`error`]    | Dedicated error types for each fallible operation |
//! | [`field`]    | [`FieldDef`], [`FieldType`], [`FieldSize`] -- rule field layout |
//! | [`rule`]     | [`Rule`], [`RuleData`], [`AclField`] -- rule value types |

pub mod classify;
pub mod config;
pub mod context;
pub mod error;
pub mod field;
pub mod rule;

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
pub use rule::{
    AclField, CategoryMask, InvalidCategoryMask, InvalidPriority, Priority, Rule, RuleData,
};

// Classification algorithm
pub use classify::{ClassifyAlgorithm, UnknownClassifyAlgorithm};

// Errors
pub use error::{
    AclAddRulesError, AclBuildError, AclClassifyError, AclCreateError, AclSetAlgorithmError,
    InvalidAclName, InvalidRule,
};

// Module-level utilities
pub use context::dump_all_contexts;

#[cfg(test)]
mod tests {
    use core::num::NonZero;

    use crate::acl::*;
    use crate::socket::SocketId;
    use crate::with_eal;

    const NUM_FIELDS: usize = 2;

    fn standard_field_defs() -> [FieldDef; NUM_FIELDS] {
        [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 1, 4),
        ]
    }

    fn exact_match_rule(value: u32, userdata: u32) -> Rule<NUM_FIELDS> {
        Rule::new(
            RuleData {
                category_mask: CategoryMask::new(1).unwrap(),
                priority: Priority::new(1).unwrap(),
                userdata: NonZero::new(userdata).expect("userdata must be non-zero"),
            },
            [AclField::from_u8(0, 0), AclField::from_u32(value, 32)],
        )
    }

    fn input_buffer(value: u32) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[4..8].copy_from_slice(&value.to_be_bytes());
        buf
    }

    fn standard_build_config() -> AclBuildConfig<NUM_FIELDS> {
        AclBuildConfig::new(1, standard_field_defs(), 0).expect("build config")
    }

    #[with_eal]
    #[test]
    fn classify_smoke() {
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "test_acl",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, standard_build_config()).expect("new context");

        ctx.add_rules(&[exact_match_rule(0xDEAD_BEEF, 1)])
            .expect("add rules");

        let ctx = ctx.build().map_err(|f| f.error).expect("build");

        let matching = input_buffer(0xDEAD_BEEF);
        let non_matching = input_buffer(0);

        let data_ptrs: Vec<*const u8> = vec![matching.as_ptr(), non_matching.as_ptr()];
        let mut results = vec![0u32; 2];
        // SAFETY: each buffer is 8 bytes; the field layout's max(offset + size)
        // is 8 (Mask field at offset 4 of size 4), so each pointer references
        // at least that many readable bytes.
        unsafe { ctx.classify(&data_ptrs, &mut results, 1) }.expect("classify");

        assert_eq!(results[0], 1, "expected match for 0xDEADBEEF");
        assert_eq!(results[1], 0, "expected no match for 0x00000000");
    }

    #[with_eal]
    #[test]
    fn reset_round_trip() {
        let original_cfg = standard_build_config();
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "reset_round_trip",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, original_cfg.clone()).expect("new context");

        ctx.add_rules(&[exact_match_rule(0xAAAA_AAAA, 1)])
            .expect("add rules (first)");
        let ctx = ctx.build().map_err(|f| f.error).expect("build (first)");
        assert_eq!(
            ctx.build_config(),
            &original_cfg,
            "Built context retains the config supplied to new()",
        );

        let first_input = input_buffer(0xAAAA_AAAA);
        let data_ptrs: Vec<*const u8> = vec![first_input.as_ptr()];
        let mut results = vec![0u32; 1];
        // SAFETY: see classify_smoke -- same 8-byte buffer / 8-byte layout.
        unsafe { ctx.classify(&data_ptrs, &mut results, 1) }.expect("classify (first)");
        assert_eq!(results[0], 1, "first build should match 0xAAAAAAAA");

        let mut ctx = ctx.reset();
        assert_eq!(
            ctx.build_config(),
            &original_cfg,
            "reset() preserves the build config across Built -> Configuring",
        );
        ctx.add_rules(&[exact_match_rule(0xBBBB_BBBB, 2)])
            .expect("add rules (second)");
        let ctx = ctx.build().map_err(|f| f.error).expect("build (second)");

        let second_input = input_buffer(0xBBBB_BBBB);
        let stale_input = input_buffer(0xAAAA_AAAA);
        let data_ptrs: Vec<*const u8> = vec![second_input.as_ptr(), stale_input.as_ptr()];
        let mut results = vec![0u32; 2];
        // SAFETY: see classify_smoke.
        unsafe { ctx.classify(&data_ptrs, &mut results, 1) }.expect("classify (second)");
        assert_eq!(
            results[0], 2,
            "second build should match 0xBBBBBBBB with userdata 2"
        );
        assert_eq!(results[1], 0, "second build must not retain the first rule");
    }

    #[with_eal]
    #[test]
    fn add_rules_rejects_out_of_range_prefix_length() {
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "prefix_len_validate",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, standard_build_config()).expect("new context");

        let bad_rule: Rule<NUM_FIELDS> = Rule::new(
            RuleData {
                category_mask: CategoryMask::new(1).unwrap(),
                priority: Priority::new(1).unwrap(),
                userdata: NonZero::new(1).unwrap(),
            },
            [
                AclField::from_u8(0, 0),
                AclField::from_u32(0, 33), // prefix_length = 33, max = 32
            ],
        );
        let err = ctx
            .add_rules(&[bad_rule])
            .expect_err("out-of-range prefix length must be rejected");
        assert!(
            matches!(
                err,
                AclAddRulesError::InvalidRule {
                    rule_index: 0,
                    source: error::InvalidRule::PrefixLengthOutOfRange {
                        prefix_length: 33,
                        max_bits: 32,
                        ..
                    },
                }
            ),
            "expected PrefixLengthOutOfRange, got {err:?}",
        );
    }

    #[with_eal]
    #[test]
    fn set_default_algorithm_then_classify() {
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "set_algo",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, standard_build_config()).expect("new context");
        ctx.add_rules(&[exact_match_rule(0xCAFE_BABE, 7)])
            .expect("add rules");
        let mut ctx = ctx.build().map_err(|f| f.error).expect("build");

        ctx.set_default_algorithm(ClassifyAlgorithm::Default)
            .expect("set_default_algorithm");

        let buf = input_buffer(0xCAFE_BABE);
        let data_ptrs: Vec<*const u8> = vec![buf.as_ptr()];
        let mut results = vec![0u32; 1];
        // SAFETY: see classify_smoke.
        unsafe { ctx.classify(&data_ptrs, &mut results, 1) }.expect("classify");
        assert_eq!(results[0], 7);
    }

    #[with_eal]
    #[test]
    fn classify_categories_validated_before_ffi() {
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "cat_validation",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, standard_build_config()).expect("new context");
        ctx.add_rules(&[exact_match_rule(0xAAAA_AAAA, 1)])
            .expect("add rules");
        let ctx = ctx.build().map_err(|f| f.error).expect("build");

        let buf = input_buffer(0xAAAA_AAAA);
        let data_ptrs: Vec<*const u8> = vec![buf.as_ptr()];

        let mut results = vec![0u32; 64];

        // SAFETY: see classify_smoke.
        let r = unsafe { ctx.classify(&data_ptrs, &mut results, 0) };
        assert!(matches!(r, Err(AclClassifyError::InvalidArgs)));

        // SAFETY: see classify_smoke.
        let r = unsafe { ctx.classify(&data_ptrs, &mut results, MAX_CATEGORIES + 1) };
        assert!(matches!(r, Err(AclClassifyError::InvalidArgs)));

        // SAFETY: see classify_smoke.
        let r = unsafe { ctx.classify(&data_ptrs, &mut results, 3) };
        assert!(matches!(r, Err(AclClassifyError::InvalidArgs)));
    }

    #[with_eal]
    #[test]
    fn duplicate_name_rejected() {
        let params_a = AclCreateParams::<NUM_FIELDS>::new(
            "dup_name",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let _ctx_a = AclContext::new(params_a, standard_build_config()).expect("first new");

        let params_b = AclCreateParams::<NUM_FIELDS>::new(
            "dup_name",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params (dup)");
        let err = AclContext::new(params_b, standard_build_config())
            .expect_err("second new with same name must fail");
        assert!(
            matches!(err, AclCreateError::AlreadyExists { ref name } if name == "dup_name"),
            "expected AlreadyExists, got {err:?}",
        );
    }

    #[with_eal]
    #[test]
    fn add_rules_after_overflow_failure() {
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "overflow_recover",
            SocketId::ANY,
            NonZero::new(1).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, standard_build_config()).expect("new context");

        ctx.add_rules(&[exact_match_rule(0x1111_1111, 1)])
            .expect("first add_rules should succeed");

        let extra = exact_match_rule(0x2222_2222, 2);
        let err = ctx
            .add_rules(&[extra])
            .expect_err("second add_rules should fail when over capacity");
        assert!(
            matches!(err, AclAddRulesError::OutOfMemory),
            "expected OutOfMemory from capacity exhaustion, got {err:?}",
        );

        let ctx = ctx
            .build()
            .map_err(|f| f.error)
            .expect("build after recoverable add_rules failure");

        let buf = input_buffer(0x1111_1111);
        let data_ptrs: Vec<*const u8> = vec![buf.as_ptr()];
        let mut results = vec![0u32; 1];
        // SAFETY: see classify_smoke.
        unsafe { ctx.classify(&data_ptrs, &mut results, 1) }.expect("classify");
        assert_eq!(results[0], 1);
    }

    #[with_eal]
    #[test]
    fn build_failure_returns_usable_context() {
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "build_failure_recovery",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let ctx = AclContext::new(params, standard_build_config()).expect("new context");

        let failure = ctx.build().expect_err("build() with no rules must fail");
        assert!(
            matches!(failure.error, AclBuildError::InvalidConfig),
            "expected InvalidConfig, got {:?}",
            failure.error,
        );

        let mut ctx = failure.context;
        ctx.add_rules(&[exact_match_rule(0xDEAD_BEEF, 1)])
            .expect("add rules after recovery");
        let ctx = ctx
            .build()
            .map_err(|f| f.error)
            .expect("second build succeeds");

        let buf = input_buffer(0xDEAD_BEEF);
        let data_ptrs: Vec<*const u8> = vec![buf.as_ptr()];
        let mut results = vec![0u32; 1];
        // SAFETY: see classify_smoke.
        unsafe { ctx.classify(&data_ptrs, &mut results, 1) }.expect("classify");
        assert_eq!(results[0], 1);
    }

    #[with_eal]
    #[test]
    fn add_rules_rejects_category_mask_beyond_num_categories() {
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "cat_mask_validate",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, standard_build_config()).expect("new context");

        let bad_rule: Rule<NUM_FIELDS> = Rule::new(
            RuleData {
                category_mask: CategoryMask::new(0b11).unwrap(),
                priority: Priority::new(1).unwrap(),
                userdata: NonZero::new(1).unwrap(),
            },
            [AclField::from_u8(0, 0), AclField::from_u32(0xAAAA_AAAA, 32)],
        );
        let err = ctx
            .add_rules(&[bad_rule])
            .expect_err("category_mask with bits beyond num_categories must be rejected");
        assert!(
            matches!(
                err,
                AclAddRulesError::InvalidRule {
                    rule_index: 0,
                    source: error::InvalidRule::CategoryMaskExceedsNumCategories {
                        category_mask: 0b11,
                        num_categories: 1,
                        extra_bits: 0b10,
                    },
                }
            ),
            "expected CategoryMaskExceedsNumCategories, got {err:?}",
        );
    }

    #[with_eal]
    #[test]
    fn classify_concurrent_arc_shared() {
        use concurrency::sync::Arc;
        use concurrency::thread;

        const WORKERS: usize = 4;
        const ITERS_PER_WORKER: usize = 1000;

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "classify_concurrent",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, standard_build_config()).expect("new context");
        ctx.add_rules(&[exact_match_rule(0xDEAD_BEEF, 1)])
            .expect("add rules");
        let ctx: Arc<AclContext<NUM_FIELDS, Built<NUM_FIELDS>>> =
            Arc::new(ctx.build().map_err(|f| f.error).expect("build"));

        let handles: Vec<_> = (0..WORKERS)
            .map(|worker| {
                let ctx = Arc::clone(&ctx);
                thread::spawn(move || {
                    let matching = input_buffer(0xDEAD_BEEF);
                    let non_matching = input_buffer(0);
                    for _ in 0..ITERS_PER_WORKER {
                        let data_ptrs: Vec<*const u8> =
                            vec![matching.as_ptr(), non_matching.as_ptr()];
                        let mut results = vec![0u32; 2];
                        // SAFETY: see classify_smoke.
                        unsafe { ctx.classify(&data_ptrs, &mut results, 1) }
                            .unwrap_or_else(|e| panic!("worker {worker}: classify failed: {e:?}"));
                        assert_eq!(
                            results[0], 1,
                            "worker {worker}: expected match for 0xDEADBEEF",
                        );
                        assert_eq!(results[1], 0, "worker {worker}: expected no match for 0",);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("worker thread panicked");
        }
    }

    #[with_eal]
    #[test]
    fn classify_with_algorithm_scalar() {
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "classify_alg_scalar",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx = AclContext::new(params, standard_build_config()).expect("new context");
        ctx.add_rules(&[exact_match_rule(0xFEED_FACE, 9)])
            .expect("add rules");
        let ctx = ctx.build().map_err(|f| f.error).expect("build");

        let buf = input_buffer(0xFEED_FACE);
        let data_ptrs: Vec<*const u8> = vec![buf.as_ptr()];
        let mut results = vec![0u32; 1];
        // SAFETY: see classify_smoke.
        unsafe {
            ctx.classify_with_algorithm(&data_ptrs, &mut results, 1, ClassifyAlgorithm::Scalar)
        }
        .expect("classify_with_algorithm(Scalar)");
        assert_eq!(results[0], 9);
    }
}
