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
//! let mut ctx = AclContext::<NUM_FIELDS>::new(params, build_cfg)?;
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

/// End-to-end integration tests for the ACL wrapper, exercising real
/// `rte_acl_*` calls against a live EAL.
///
/// # EAL configuration (shared by every test in this module)
///
/// All tests initialize EAL via [`start_eal`][self::tests::start_eal], which
/// passes a fixed set of flags plus two dynamic values:
///
/// - `--no-huge --in-memory` -- back EAL with anonymous memory instead of
///   hugetlbfs.  Keeps the tests runnable on any host without manual hugepage
///   configuration.
/// - `--lcores 0@({allowed_cpus})` -- a single logical lcore (the main),
///   floated across whatever physical CPUs `sched_getaffinity` reports as
///   available to the process.  No workers means
///   `rte_eal_mp_remote_launch` has no per-worker readiness flag to read, so
///   we sidestep a benign-but-flagged data race that ThreadSanitizer reports
///   against DPDK's lcore startup, and we also avoid spawning unused worker
///   threads.  Floating (instead of pinning to physical CPU 0) keeps the
///   tests honest about cgroups, taskset, and container CPU restrictions.
/// - `--file-prefix <unique-id>` -- a per-init unique identifier so that
///   concurrent forked test processes do not fight over the EAL runtime
///   configuration namespace.  Necessary alongside `--in-memory` because EAL
///   still creates per-process control state in the runtime dir.
/// - `--no-pci --no-telemetry --no-shconf --no-hpet` -- disable everything we
///   do not need so the tests start quickly and have no shared-config files
///   to clean up.
///
/// # Running once per process
///
/// `eal::init` may only be called once per process.  Every test in this
/// module funnels through the [`EAL`][self::tests::EAL] `OnceLock`, so
/// the init happens exactly once regardless of how the harness schedules
/// tests: nextest's per-test process fork (the workspace default) runs
/// the lazy init once per fork; a single-process runner (`cargo test
/// --test-threads=1` or an in-process parallel harness) runs it once for
/// the lifetime of the process.
///
/// # Running locally
///
/// ```text
/// just setup-roots             # rebuild DPDK + wrapper
/// # re-enter `nix-shell` so DATAPLANE_SYSROOT picks up the new sysroot
/// cargo nextest run -p dataplane-dpdk acl::tests
/// ```
#[cfg(test)]
mod tests {
    use core::num::NonZero;

    use concurrency::sync::OnceLock;

    use crate::acl::*;
    use crate::eal::Eal;
    use crate::socket::SocketId;

    /// Number of fields used by all lifecycle tests in this module.
    const NUM_FIELDS: usize = 2;

    /// Process-wide EAL initialized on first use, shared by every test.
    ///
    /// `eal::init` may only be called once per process.  Nextest's default
    /// per-test process forking makes a per-test `init` trivially safe
    /// (each forked process re-initializes EAL exactly once), but a
    /// single-process test runner -- `cargo test --test-threads=1`, an
    /// in-process parallel harness, or any future configuration that drops
    /// the fork -- would call init twice and fail.  Funneling every test
    /// through this lazy [`OnceLock`] makes the tests correct under both
    /// modes: per-process forking initializes once per fork (cheap),
    /// in-process initializes once for the lifetime of the process.
    ///
    /// The `Eal` value is intentionally leaked into the static for the
    /// lifetime of the process; DPDK has no clean teardown path, and the
    /// `Eal` Drop would (per [`crate::eal::init`]) be unable to free DPDK
    /// allocations through the system allocator after the allocator swap.
    static EAL: OnceLock<Eal> = OnceLock::new();

    /// Lazily initialize EAL on first call.
    ///
    /// Each test calls this in place of `eal::init`; subsequent calls
    /// return the shared `&'static Eal` without re-initializing DPDK.
    fn start_eal() -> &'static Eal {
        // DPDK pins lcores, but that is generally not what we actually want in a test environment.
        // Instead, we need to allocate just lcore 0 (main) and pin it to "everything we legally have access to."
        fn allowed_cpus() -> String {
            use nix::sched::{CpuSet, sched_getaffinity};
            use nix::unistd::Pid;
            let set = sched_getaffinity(Pid::from_raw(0)).expect("sched_getaffinity");
            (0..CpuSet::count())
                .filter(|&i| set.is_set(i).unwrap_or(false))
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        }
        // concurrent executions of DPDK EAL can fight over allocations and file resources.
        // You can prevent that with a unique prefix on the hugepage files it allocates (if any).
        let eal_id = format!("{}", id::Id::<Eal>::new());
        let core_pinning = format!("0@({})", allowed_cpus());
        // EAL arguments used the first time EAL is initialized in this process.
        let args: &[&str] = &[
            "--no-huge",
            "--no-pci",
            "--in-memory",
            "--no-telemetry",
            "--no-shconf",
            "--no-hpet",
            "--iova-mode=va",
            "--file-prefix",
            &eal_id,
            // Restrict EAL to a single lcore (the main).  Without workers,
            // rte_eal_mp_remote_launch has no readiness flags to read and there is
            // no DPDK-internal init race for ThreadSanitizer to flag.  Also avoids
            // spawning unused worker threads.
            //
            // The `0@(<cpu-list>)` form means "logical lcore 0, floated across
            // the listed physical CPUs": DPDK schedules lcore 0 onto any of
            // them rather than pinning to a single CPU.  Floating instead of
            // pinning keeps the tests honest about cgroups, taskset, and
            // container affinity restrictions.
            "--lcores",
            &core_pinning,
        ];

        EAL.get_or_init(|| super::super::eal::init(args.iter().copied()))
    }

    /// Standard field layout used by the lifecycle tests.
    ///
    /// DPDK ACL requires the first field in the rule definition to be one byte
    /// long (it is consumed during trie setup).  All subsequent fields must be
    /// grouped into sets of 4 consecutive bytes via `input_index`.
    fn standard_field_defs() -> [FieldDef; NUM_FIELDS] {
        [
            // Field 0: 1-byte entry at offset 0 (required by DPDK to be 1 byte).
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            // Field 1: 4-byte Mask field at offset 4, input_index 1.
            FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 1, 4),
        ]
    }

    /// Build a rule that exact-matches the given 32-bit value in field 1.
    ///
    /// `userdata` becomes the classify result for matching inputs.
    fn exact_match_rule(value: u32, userdata: u32) -> Rule<NUM_FIELDS> {
        Rule::new(
            RuleData {
                category_mask: CategoryMask::new(1).unwrap(),
                priority: Priority::new(1).unwrap(),
                userdata: NonZero::new(userdata).expect("userdata must be non-zero"),
            },
            [
                // Wildcard entry byte: field 0 is FieldType::Bitmask
                // (per standard_field_defs).  mask = 0 makes the
                // predicate `(input & 0) == 0`, which is trivially true
                // for any input -- so this field matches any byte at
                // offset 0.
                AclField::from_u8(0, 0),
                // Field 1 is FieldType::Mask; mask_range is interpreted
                // as a prefix length, so 32 means "compare all 32 bits".
                AclField::from_u32(value, 32),
            ],
        )
    }

    /// Build an 8-byte input buffer carrying `value` at offset 4 in network byte
    /// order, suitable for the field layout returned by [`standard_field_defs`].
    fn input_buffer(value: u32) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[4..8].copy_from_slice(&value.to_be_bytes());
        buf
    }

    /// Build the default `AclBuildConfig` used across the lifecycle tests
    /// (`num_categories = 1`, the standard 2-field layout, no max_size).
    fn standard_build_config() -> AclBuildConfig<NUM_FIELDS> {
        AclBuildConfig::new(1, standard_field_defs(), 0).expect("build config")
    }

    /// End-to-end classify smoke test: build a tiny ACL context, run a real
    /// `rte_acl_classify` call, and verify the match / no-match outcomes.
    /// See the [module-level docs](self) for the EAL setup that applies to
    /// every test here.
    #[test]
    fn classify_smoke() {
        let _eal = start_eal();

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "test_acl",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");

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

    /// Reset round-trip: build, classify, reset back to Configuring, swap
    /// in a new rule, rebuild (no config supplied -- it lives on the
    /// context), and verify the new rule's userdata wins.  Also asserts
    /// that the build config survives the reset.
    #[test]
    fn reset_round_trip() {
        let _eal = start_eal();

        let original_cfg = standard_build_config();
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "reset_round_trip",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, original_cfg.clone()).expect("new context");

        // First build cycle: match 0xAAAAAAAA -> userdata 1.
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

        // Reset back to Configuring (config carries through) and load a
        // different rule.
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

    /// `add_rules` rejects a rule whose [`FieldType::Mask`] field carries a
    /// prefix length larger than the field's bit width.  Without this
    /// wrapper-side check, DPDK's `RTE_ACL_MASKLEN_TO_BITMASK` would
    /// perform a C shift by an out-of-range amount (UB).
    #[test]
    fn add_rules_rejects_out_of_range_prefix_length() {
        let _eal = start_eal();

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "prefix_len_validate",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");

        // Field 1 in standard_field_defs is a 4-byte Mask field, so the
        // maximum legal prefix length is 32.  33 is out of range.
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

    /// `set_default_algorithm` happy path: build, switch to a specific
    /// algorithm, and classify.  Uses `Default` which is always supported.
    #[test]
    fn set_default_algorithm_then_classify() {
        let _eal = start_eal();

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "set_algo",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");
        ctx.add_rules(&[exact_match_rule(0xCAFE_BABE, 7)])
            .expect("add rules");
        let mut ctx = ctx.build().map_err(|f| f.error).expect("build");

        // `Default` is always available on any CPU DPDK runs on.
        ctx.set_default_algorithm(ClassifyAlgorithm::Default)
            .expect("set_default_algorithm");

        let buf = input_buffer(0xCAFE_BABE);
        let data_ptrs: Vec<*const u8> = vec![buf.as_ptr()];
        let mut results = vec![0u32; 1];
        // SAFETY: see classify_smoke.
        unsafe { ctx.classify(&data_ptrs, &mut results, 1) }.expect("classify");
        assert_eq!(results[0], 7);
    }

    /// `classify` must reject `categories` values that would overflow DPDK's
    /// per-thread runtime arrays sized to `RTE_ACL_MAX_CATEGORIES`, even when
    /// the user's `results` slice is generous enough to satisfy the
    /// per-element length check.
    #[test]
    fn classify_categories_validated_before_ffi() {
        let _eal = start_eal();

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "cat_validation",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");
        ctx.add_rules(&[exact_match_rule(0xAAAA_AAAA, 1)])
            .expect("add rules");
        let ctx = ctx.build().map_err(|f| f.error).expect("build");

        let buf = input_buffer(0xAAAA_AAAA);
        let data_ptrs: Vec<*const u8> = vec![buf.as_ptr()];

        // results slice large enough to pass the length check, but categories
        // out of range -- must still be rejected.
        let mut results = vec![0u32; 64];

        // categories = 0
        // SAFETY: see classify_smoke.
        let r = unsafe { ctx.classify(&data_ptrs, &mut results, 0) };
        assert!(matches!(r, Err(AclClassifyError::InvalidArgs)));

        // categories > MAX_CATEGORIES (= 16)
        // SAFETY: see classify_smoke.
        let r = unsafe { ctx.classify(&data_ptrs, &mut results, MAX_CATEGORIES + 1) };
        assert!(matches!(r, Err(AclClassifyError::InvalidArgs)));

        // categories > 1 but not a multiple of RESULTS_MULTIPLIER (= 4)
        // SAFETY: see classify_smoke.
        let r = unsafe { ctx.classify(&data_ptrs, &mut results, 3) };
        assert!(matches!(r, Err(AclClassifyError::InvalidArgs)));
    }

    /// Creating a second [`AclContext`] with a name already registered in
    /// DPDK's global ACL list must fail with [`AclCreateError::AlreadyExists`]
    /// rather than silently aliasing the first context (which would
    /// double-free on drop).
    #[test]
    fn duplicate_name_rejected() {
        let _eal = start_eal();

        let params_a = AclCreateParams::<NUM_FIELDS>::new(
            "dup_name",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let _ctx_a =
            AclContext::<NUM_FIELDS>::new(params_a, standard_build_config()).expect("first new");

        let params_b = AclCreateParams::<NUM_FIELDS>::new(
            "dup_name",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params (dup)");
        let err = AclContext::<NUM_FIELDS>::new(params_b, standard_build_config())
            .expect_err("second new with same name must fail");
        assert!(
            matches!(err, AclCreateError::AlreadyExists { ref name } if name == "dup_name"),
            "expected AlreadyExists, got {err:?}",
        );
    }

    /// Recovery after `add_rules` overflows `max_rule_num`: the context must
    /// remain usable.  We submit one rule successfully, then submit more rules
    /// than the remaining capacity allows, expect the error, and finally build
    /// and classify against the first rule.
    #[test]
    fn add_rules_after_overflow_failure() {
        let _eal = start_eal();

        // `max_rule_num` of 1: a second add_rules call with any rule will
        // overflow.
        let params = AclCreateParams::<NUM_FIELDS>::new(
            "overflow_recover",
            SocketId::ANY,
            NonZero::new(1).unwrap(),
        )
        .expect("create params");
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");

        ctx.add_rules(&[exact_match_rule(0x1111_1111, 1)])
            .expect("first add_rules should succeed");

        // Attempting to add another rule must fail: capacity is exhausted.
        // DPDK signals "no room left in the rule list" with -ENOMEM, which
        // the wrapper maps to AclAddRulesError::OutOfMemory.  Pin the variant
        // so a future change in mapping or DPDK's behaviour surfaces as a
        // test failure rather than silently passing through.
        let extra = exact_match_rule(0x2222_2222, 2);
        let err = ctx
            .add_rules(&[extra])
            .expect_err("second add_rules should fail when over capacity");
        assert!(
            matches!(err, AclAddRulesError::OutOfMemory),
            "expected OutOfMemory from capacity exhaustion, got {err:?}",
        );

        // Context must still be usable: build + classify against the first rule.
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

    /// Build failure recovery: when `build()` fails, the wrapper returns
    /// the original `Configuring` context inside `AclBuildFailure`.  The
    /// caller must be able to keep using it (add rules, retry).  We force
    /// the failure by calling `build()` with no rules added (DPDK rejects
    /// `num_rules == 0` with `-EINVAL`).
    #[test]
    fn build_failure_returns_usable_context() {
        let _eal = start_eal();

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "build_failure_recovery",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");

        // First build with zero rules must fail.
        let failure = ctx.build().expect_err("build() with no rules must fail");
        assert!(
            matches!(failure.error, AclBuildError::InvalidConfig),
            "expected InvalidConfig, got {:?}",
            failure.error,
        );

        // Recover the context, add a rule, build again -- must succeed.
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

    /// `add_rules` rejects a rule whose `category_mask` has bits set at
    /// positions `>= config.num_categories()`.  DPDK would silently mask
    /// off those bits at build time, narrowing the rule's intended
    /// category set; we surface this at `add_rules` time instead.
    #[test]
    fn add_rules_rejects_category_mask_beyond_num_categories() {
        let _eal = start_eal();

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "cat_mask_validate",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        // standard_build_config uses num_categories = 1, so only bit 0 is
        // legal.  Build a rule with bit 1 also set.
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");

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

    /// Concurrent classify under `Arc<AclContext<N, Built<N>>>`: spawns
    /// several worker threads, each calling
    /// [`AclContext::classify`][crate::acl::AclContext::classify] in a
    /// tight loop, and verifies every thread sees the correct match.
    /// Exercises the per-state `Sync` impl on [`Built<N>`] and ensures
    /// the wrapper's "share across classification threads" claim isn't
    /// vacuous.  Test runs with N=4 workers and M=1000 iterations each
    /// to give the OS scheduler a chance to interleave.
    #[test]
    fn classify_concurrent_arc_shared() {
        use concurrency::sync::Arc;
        use concurrency::thread;

        let _eal = start_eal();

        const WORKERS: usize = 4;
        const ITERS_PER_WORKER: usize = 1000;

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "classify_concurrent",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");
        ctx.add_rules(&[exact_match_rule(0xDEAD_BEEF, 1)])
            .expect("add rules");
        let ctx: Arc<AclContext<NUM_FIELDS, Built<NUM_FIELDS>>> =
            Arc::new(ctx.build().map_err(|f| f.error).expect("build"));

        let handles: Vec<_> = (0..WORKERS)
            .map(|worker| {
                let ctx = Arc::clone(&ctx);
                thread::spawn(move || {
                    // Each worker owns its own buffers; classify is the
                    // only place we share state across threads.
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

    /// `classify_with_algorithm` with a non-`Default` algorithm: locks in
    /// the special-casing in [`AclContext::classify_with_algorithm`] by
    /// dispatching through the `Scalar` variant (always available on every
    /// CPU DPDK runs on) and verifying classification still works.
    #[test]
    fn classify_with_algorithm_scalar() {
        let _eal = start_eal();

        let params = AclCreateParams::<NUM_FIELDS>::new(
            "classify_alg_scalar",
            SocketId::ANY,
            NonZero::new(16).unwrap(),
        )
        .expect("create params");
        let mut ctx =
            AclContext::<NUM_FIELDS>::new(params, standard_build_config()).expect("new context");
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
