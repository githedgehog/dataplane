// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Error types for ACL operations.
//!
//! Each fallible ACL operation has a dedicated error type following the project's error handling
//! guidelines.  Errors are strongly typed enums rather than strings or bare numeric codes.

use errno::Errno;

/// Ways in which an ACL context name can be invalid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
pub enum InvalidAclName {
    /// The name is not valid ASCII.
    #[error("ACL context name must be valid ASCII")]
    NotAscii,
    /// The name is too long (exceeds [`RTE_ACL_NAMESIZE`][dpdk_sys::RTE_ACL_NAMESIZE]).
    #[error("ACL context name is too long ({len} > {max} bytes)")]
    TooLong {
        /// The length of the name that was provided.
        len: usize,
        /// The maximum allowed length.
        max: usize,
    },
    /// The name is empty.
    #[error("ACL context name must not be empty")]
    Empty,
    /// The name contains interior null bytes.
    #[error("ACL context name must not contain null bytes")]
    ContainsNullBytes,
}

/// Errors that can occur when creating an ACL context via [`rte_acl_create`][dpdk_sys::rte_acl_create].
#[derive(Debug, thiserror::Error)]
pub enum AclCreateError {
    /// The context name failed validation.
    #[error("Invalid ACL context name: {0}")]
    InvalidName(#[from] InvalidAclName),
    /// A context with this name already exists in DPDK's global registry.
    ///
    /// DPDK's [`rte_acl_create`][dpdk_sys::rte_acl_create] silently returns the
    /// existing context for a duplicate name rather than failing.  Returning
    /// that pointer wrapped in a new [`AclContext`][super::context::AclContext]
    /// would create two owning wrappers for the same DPDK handle, leading to
    /// use-after-free when the first one is dropped.  We refuse the call
    /// instead.
    ///
    /// Detection is reliable against concurrent calls to
    /// [`AclContext::new`][super::context::AclContext::new] within the same
    /// process: a module-private mutex serializes the
    /// `rte_acl_find_existing` + `rte_acl_create` pair.  Concurrent calls to
    /// `rte_acl_create` from outside this wrapper (e.g. another C/C++
    /// library linked into the same process) can still race.
    ///
    /// As a workspace-level invariant, **nothing else in this process is
    /// permitted to call `rte_acl_create` / `rte_acl_free` directly**.  If
    /// a future DPDK PMD or third-party library is added that touches the
    /// global ACL registry, the wrapper's lock must be either lifted into
    /// a coordination primitive that the new caller honours, or replaced
    /// by a different scheme.  Touch
    /// [`ACL_CREATE_LOCK`][super::context] when revisiting.
    #[error("An ACL context named '{name}' already exists")]
    AlreadyExists {
        /// The name that collided.
        name: String,
    },
    /// DPDK returned `EINVAL` -- one or more parameters are invalid.
    #[error("Invalid ACL creation parameters")]
    InvalidParams,
    /// DPDK returned `ENOMEM` -- insufficient memory to allocate the context.
    #[error("Not enough memory to create ACL context")]
    OutOfMemory,
    /// DPDK set an `rte_errno` value that does not match any documented error for this call.
    #[error("Unknown error creating ACL context: {0:?}")]
    Unknown(Errno),
}

/// Errors that can occur when adding rules via [`rte_acl_add_rules`][dpdk_sys::rte_acl_add_rules].
#[derive(Debug, thiserror::Error)]
pub enum AclAddRulesError {
    /// The caller-supplied slice contains more than `u32::MAX` rules, which
    /// cannot be represented in the DPDK FFI's `num` argument.  Distinct
    /// from [`InvalidParams`][AclAddRulesError::InvalidParams] (which is
    /// DPDK's own validation failure), this is a pre-flight length check
    /// in the Rust wrapper.
    #[error("Rule slice length {len} exceeds u32::MAX")]
    TooManyRules {
        /// The offending slice length.
        len: usize,
    },
    /// A rule's [`AclField`] values are inconsistent with the
    /// [`AclBuildConfig`] in effect.  Caught in the Rust wrapper before the
    /// call would reach `rte_acl_add_rules`; see [`InvalidRule`] for the
    /// per-violation details.
    ///
    /// [`AclField`]: super::rule::AclField
    /// [`AclBuildConfig`]: super::config::AclBuildConfig
    #[error("rule {rule_index} is invalid for the configured field layout: {source}")]
    InvalidRule {
        /// Position of the offending rule within the caller's slice.
        rule_index: usize,
        /// The specific violation.
        #[source]
        source: InvalidRule,
    },
    /// DPDK returned `ENOMEM` -- not enough space in the context for the new rules.
    #[error("No space for additional rules in ACL context")]
    OutOfMemory,
    /// DPDK returned `EINVAL` -- one or more rule parameters are invalid.
    #[error("Invalid rule parameters")]
    InvalidParams,
    /// DPDK returned an undocumented error code.
    #[error("Unknown error adding rules: {0:?}")]
    Unknown(Errno),
}

/// Per-rule validation failure, reported as the cause of
/// [`AclAddRulesError::InvalidRule`].
///
/// Catching these in Rust (rather than relying on DPDK's later rejection at
/// build time) avoids reaching C code paths that would shift by an
/// out-of-range amount or otherwise invoke undefined behaviour on invalid
/// rule data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidRule {
    /// A [`FieldType::Mask`][super::field::FieldType::Mask] field's
    /// `mask_range` (interpreted as a prefix length) exceeds the field's
    /// bit width.  DPDK's `RTE_ACL_MASKLEN_TO_BITMASK` would perform a C
    /// shift by an amount `>= 8 * size`, which is undefined behaviour.
    #[error(
        "Mask field at field_index {field_index}: prefix length \
         {prefix_length} exceeds the field's bit width ({max_bits})"
    )]
    PrefixLengthOutOfRange {
        /// The `field_index` of the offending field.
        field_index: u8,
        /// The caller-supplied prefix length.
        prefix_length: u64,
        /// `8 * size_bytes`.
        max_bits: u32,
    },
    /// A [`FieldType::Range`][super::field::FieldType::Range] field has
    /// `value > mask_range`.  DPDK interprets `value` as the inclusive low
    /// bound and `mask_range` as the inclusive high bound, so the range
    /// would be empty.
    #[error(
        "Range field at field_index {field_index}: low bound {low} \
         exceeds high bound {high}"
    )]
    RangeReversed {
        /// The `field_index` of the offending field.
        field_index: u8,
        /// The low bound (`value`).
        low: u64,
        /// The high bound (`mask_range`).
        high: u64,
    },
    /// The rule's `category_mask` has bits set at positions
    /// `>= config.num_categories()`.  DPDK silently masks out those bits
    /// at build time, which would make the rule apply to fewer
    /// categories than the caller intended.  Surfacing this at
    /// `add_rules` time avoids the silent-narrowing footgun.
    #[error(
        "category_mask {category_mask:#010x} has bits set beyond \
         num_categories ({num_categories}); offending bits: {extra_bits:#010x}"
    )]
    CategoryMaskExceedsNumCategories {
        /// The rule's category mask.
        category_mask: u32,
        /// The build config's `num_categories`.
        num_categories: u32,
        /// `category_mask & !((1 << num_categories) - 1)`, the bits that
        /// DPDK would mask off.
        extra_bits: u32,
    },
}

/// Errors that can occur when building the ACL context via [`rte_acl_build`][dpdk_sys::rte_acl_build].
///
/// Recovery: any of these variants is reported through
/// [`AclBuildFailure`][super::context::AclBuildFailure], which carries the
/// original [`AclContext`][super::context::AclContext] back to the caller in
/// the [`Configuring`][super::context::Configuring] state.  The Rust typestate
/// is reset (we did not call `rte_acl_build`'s success path), but the
/// **DPDK-side rule list is left intact** -- previously-added rules remain
/// loaded.  Callers who want a clean slate must call
/// [`reset_rules`][super::context::AclContext::reset_rules] on the returned
/// context before retrying.
#[derive(Debug, thiserror::Error)]
pub enum AclBuildError {
    /// DPDK returned `ENOMEM` -- not enough memory to build the runtime structures.
    #[error("Not enough memory to build ACL context")]
    OutOfMemory,
    /// DPDK returned `EINVAL` -- the build configuration is invalid.
    #[error("Invalid ACL build configuration")]
    InvalidConfig,
    /// DPDK returned `ERANGE` -- the compiled runtime structures exceeded
    /// [`AclBuildConfig::max_size`][super::config::AclBuildConfig::max_size].
    /// Raise the limit or simplify the rule set, then retry on the
    /// recovered context (see [`AclBuildFailure`][super::context::AclBuildFailure]).
    #[error("ACL runtime structures exceeded the configured max_size")]
    ExceededMaxSize,
    /// DPDK returned an undocumented error code from `rte_acl_build`.
    #[error("ACL build failed: {0:?}")]
    Unknown(Errno),
}

/// Errors that can occur during classification via
/// [`rte_acl_classify`][dpdk_sys::rte_acl_classify].
#[derive(Debug, thiserror::Error)]
pub enum AclClassifyError {
    /// DPDK returned `EINVAL` -- the classify arguments are invalid.
    ///
    /// Common causes:
    /// - `categories` is zero, greater than [`RTE_ACL_MAX_CATEGORIES`][dpdk_sys::RTE_ACL_MAX_CATEGORIES],
    ///   or not a multiple of [`RTE_ACL_RESULTS_MULTIPLIER`][dpdk_sys::RTE_ACL_RESULTS_MULTIPLIER].
    /// - The `results` slice is too small for `num * categories` entries.
    #[error("Invalid classify arguments")]
    InvalidArgs,
    /// DPDK returned `ENOTSUP` -- the requested classification algorithm
    /// is not supported on this CPU.  Only reachable through
    /// [`classify_with_algorithm`][super::context::AclContext::classify_with_algorithm];
    /// the default-algorithm path returns the context's previously-set
    /// algorithm, which has already been vetted by
    /// [`set_default_algorithm`][super::context::AclContext::set_default_algorithm].
    #[error("Requested classification algorithm is not supported on this CPU")]
    NotSupported,
    /// DPDK returned an undocumented error code.
    #[error("Unknown error during classification: {0:?}")]
    Unknown(Errno),
}

/// Errors that can occur when setting the classification algorithm via
/// [`rte_acl_set_ctx_classify`][dpdk_sys::rte_acl_set_ctx_classify].
#[derive(Debug, thiserror::Error)]
pub enum AclSetAlgorithmError {
    /// DPDK returned `EINVAL` -- the parameters are invalid.
    #[error("Invalid algorithm or context")]
    InvalidParams,
    /// The requested algorithm is not supported on this CPU.
    #[error("Requested classification algorithm is not supported on this platform")]
    NotSupported,
    /// DPDK returned an undocumented error code.
    #[error("Unknown error setting classification algorithm: {0:?}")]
    Unknown(Errno),
}
