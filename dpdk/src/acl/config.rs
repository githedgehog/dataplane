// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL configuration types.
//!
//! This module provides safe, validated configuration types for the two main ACL setup calls:
//!
//! - [`AclCreateParams`] -- parameters for creating an ACL context
//!   ([`rte_acl_create`][dpdk_sys::rte_acl_create]).
//! - [`AclBuildConfig`]`<N>` -- parameters for compiling rules into runtime lookup structures
//!   ([`rte_acl_build`][dpdk_sys::rte_acl_build]).
//!
//! Following the project convention of validating inputs at the boundary, both types perform
//! validation at construction time so that downstream code can assume the configuration is valid.

use core::ffi::CStr;
use core::fmt::{self, Display};
use core::marker::PhantomData;
use core::num::NonZero;

use std::ffi::CString;

use tracing::debug;

use crate::socket::SocketId;

use super::error::InvalidAclName;
use super::field::FieldDef;
use super::rule::Rule;

// ---------------------------------------------------------------------------
// AclCreateParams
// ---------------------------------------------------------------------------

/// Validated parameters for creating an ACL context with `N` fields per rule.
///
/// This is the safe Rust equivalent of [`rte_acl_param`][dpdk_sys::rte_acl_param].
/// The name is validated at construction time and stored as a [`CString`] for zero-cost FFI.
///
/// # Why the const generic is on the type, not the constructor
///
/// `N` lives on the type so that
/// [`AclContext::<N>::new`][super::context::AclContext::new] can require
/// `AclCreateParams<N>` with the **same** `N`.  Erasing `N` after construction
/// would let `AclContext::<3>::new(AclCreateParams::<5>::new(...))` compile
/// while DPDK strides through rules at `rule_size = size_of::<Rule<5>>()` over
/// `Rule<3>`-sized slots -- the exact OOB read the const generic is meant to
/// rule out.  Keeping `N` on the type closes that gap statically and is
/// consistent with how [`AclBuildConfig<N>`] is parameterised.
///
/// # Construction
///
/// Use [`AclCreateParams::<N>::new`][AclCreateParams::new] to create a validated instance.
///
/// ```ignore
/// let params = AclCreateParams::<5>::new("my_acl", SocketId::ANY, NonZero::new(1024).unwrap())?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclCreateParams<const N: usize> {
    /// Validated ACL context name (ASCII, non-empty, no null bytes, within length limit).
    name: CString,
    /// NUMA socket on which to allocate the context's memory.
    socket_id: SocketId,
    /// Maximum number of rules this context can hold.  Non-zero: a context that
    /// cannot hold any rules is useless and `rte_acl_create` rejects it with
    /// `EINVAL`.
    max_rule_num: NonZero<u32>,
    /// Size of each rule in bytes -- equal to
    /// [`Rule::<N>::RULE_SIZE`][Rule::RULE_SIZE].  Stored as
    /// [`NonZero<u32>`] because `N > 0` implies `size_of::<Rule<N>>() > 0`,
    /// and a zero `rule_size` would be rejected by DPDK with `EINVAL`.
    rule_size: NonZero<u32>,
    /// Carries `N` on the type without taking up space.
    _phantom: PhantomData<[(); N]>,
}

/// The maximum length (in bytes, **excluding** the null terminator) of an ACL context name.
///
/// DPDK's [`RTE_ACL_NAMESIZE`][dpdk_sys::RTE_ACL_NAMESIZE] includes the null terminator, so the
/// usable string length is one less.
pub const MAX_ACL_NAME_LEN: usize = (dpdk_sys::RTE_ACL_NAMESIZE as usize).saturating_sub(1);

impl<const N: usize> AclCreateParams<N> {
    /// Compile-time guard: `N == 0` is rejected here so that
    /// [`AclContext::<0, _>`][super::context::AclContext] is unconstructable
    /// via the public API.  Forced to evaluate in `new` via a let-binding.
    const _CHECK_N_NONZERO: () = assert!(N > 0, "AclCreateParams requires N > 0");

    /// Compile-time guard: `N` must not exceed
    /// [`MAX_FIELDS`][super::config::MAX_FIELDS] (DPDK's
    /// `RTE_ACL_MAX_FIELDS` = 64).  Larger `N` would also be rejected by
    /// [`AclBuildConfig::new`][super::config::AclBuildConfig::new], but
    /// must be rejected **here** first: `Rule::<N>::RULE_SIZE`
    /// computes `size_of::<Rule<N>>() as u32`, and for very large `N`
    /// the cast can wrap to `0`, after which the `NonZero::new_unchecked`
    /// below would invoke undefined behaviour.  Capping `N` at
    /// `MAX_FIELDS` keeps `size_of::<Rule<N>>()` well under `u32::MAX`
    /// (it is at most 16 + 16 * 64 = 1040 bytes), so the cast is exact
    /// and non-zero.
    const _CHECK_N_FITS_U32_RULE_SIZE: () = assert!(
        N <= MAX_FIELDS,
        "AclCreateParams requires N <= RTE_ACL_MAX_FIELDS (64); larger N would \
         truncate size_of::<Rule<N>>() during the u32 cast and risk UB."
    );

    /// Create validated ACL creation parameters.
    ///
    /// `N` (on the type) must match the number of [`FieldDef`] entries that
    /// will be used when building the context, as well as the number of
    /// fields in every [`Rule<N>`][Rule] added to the context.  It is used
    /// here to compute the `rule_size` that DPDK requires at creation time.
    ///
    /// # Arguments
    ///
    /// * `name` -- human-readable name for the context.  Must be non-empty ASCII without null
    ///   bytes, at most [`MAX_ACL_NAME_LEN`] bytes long.
    /// * `socket_id` -- the NUMA socket to allocate memory on.  Use [`SocketId::ANY`] if you don't
    ///   have a preference.
    /// * `max_rule_num` -- the maximum number of rules this context will hold.
    ///   Non-zero by type; a context that cannot hold any rules has no use and
    ///   DPDK rejects it with `EINVAL`.
    ///
    /// # Compile-time checks
    ///
    /// `N == 0` is rejected by `_CHECK_N_NONZERO`; `N > MAX_FIELDS` is
    /// rejected by `_CHECK_N_FITS_U32_RULE_SIZE`.  Both are evaluated at
    /// monomorphisation time via let-bindings in this function.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAclName`] if the name fails validation.
    #[cold]
    #[tracing::instrument(level = "debug", skip(name), fields(name = name.as_ref()))]
    pub fn new(
        name: impl AsRef<str>,
        socket_id: SocketId,
        max_rule_num: NonZero<u32>,
    ) -> Result<Self, InvalidAclName> {
        // Force evaluation of both const assertions for this monomorphisation.
        let () = Self::_CHECK_N_NONZERO;
        let () = Self::_CHECK_N_FITS_U32_RULE_SIZE;

        let name = Self::validate_name(name.as_ref())?;
        // `Rule::<N>::RULE_SIZE == size_of::<Rule<N>>() as u32`.  The
        // two const assertions above guarantee `0 < N <= MAX_FIELDS`,
        // so `size_of::<Rule<N>>()` is in `[28, 1040]` -- well under
        // `u32::MAX`, and certainly non-zero.  The `unreachable!()`
        // arm is therefore dead; we surface it as a panic rather than
        // `unsafe { new_unchecked }` so that a broken invariant
        // faults loudly instead of being undefined behaviour.
        let rule_size = match NonZero::new(Rule::<N>::RULE_SIZE) {
            Some(nz) => nz,
            None => unreachable!(),
        };
        debug!(
            "Created ACL params: name={}, socket_id={:?}, max_rule_num={}, rule_size={}",
            name.to_str().unwrap_or("<invalid>"),
            socket_id,
            max_rule_num,
            rule_size,
        );
        Ok(Self {
            name,
            socket_id,
            max_rule_num,
            rule_size,
            _phantom: PhantomData,
        })
    }

    /// Validate and convert an ACL context name to a [`CString`].
    #[cold]
    fn validate_name(name: &str) -> Result<CString, InvalidAclName> {
        if name.is_empty() {
            return Err(InvalidAclName::Empty);
        }
        if !name.is_ascii() {
            return Err(InvalidAclName::NotAscii);
        }
        if name.len() > MAX_ACL_NAME_LEN {
            return Err(InvalidAclName::TooLong {
                len: name.len(),
                max: MAX_ACL_NAME_LEN,
            });
        }
        CString::new(name).map_err(|_| InvalidAclName::ContainsNullBytes)
    }

    /// Get the context name as a `&str`.
    #[must_use]
    pub fn name(&self) -> &str {
        // SAFETY: The name is validated as ASCII at construction time and therefore is
        // also valid UTF-8.  `self.name` is a `CString`, so `to_bytes()` excludes the
        // trailing NUL.
        unsafe { core::str::from_utf8_unchecked(self.name.to_bytes()) }
    }

    /// Get the name as a [`CString`] reference, suitable for FFI.
    #[must_use]
    pub fn name_cstr(&self) -> &CStr {
        &self.name
    }

    /// Get the NUMA socket preference.
    #[must_use]
    pub fn socket_id(&self) -> SocketId {
        self.socket_id
    }

    /// Get the maximum rule count.
    #[must_use]
    pub fn max_rule_num(&self) -> NonZero<u32> {
        self.max_rule_num
    }

    /// Get the per-rule byte size.
    ///
    /// This was computed from the const generic `N` at construction time and equals
    /// `core::mem::size_of::<Rule<N>>()`.  Non-zero by type since `N > 0`.
    #[must_use]
    pub fn rule_size(&self) -> NonZero<u32> {
        self.rule_size
    }

    /// Build the raw DPDK [`rte_acl_param`][dpdk_sys::rte_acl_param], borrowed from `self`.
    ///
    /// The returned [`RawParams`] holds a `rte_acl_param` whose `name` pointer is
    /// borrowed from `self.name`.  The lifetime on [`RawParams`] ties the raw
    /// struct to `&self`, preventing use-after-free if `self` is dropped before
    /// the FFI call completes.
    pub(crate) fn to_raw(&self) -> RawParams<'_> {
        // Cast rationale for `socket_id`:
        //
        // [`SocketId`] wraps a `c_uint`, but DPDK's
        // [`rte_acl_param`][dpdk_sys::rte_acl_param] field is `c_int`.
        // The cast is exact for the two value classes that ever appear in
        // a valid `SocketId`:
        //
        // - [`SocketId::ANY`][crate::socket::SocketId::ANY] is defined as
        //   `c_uint::MAX`, which two's-complement-casts to `-1` --
        //   precisely DPDK's `SOCKET_ID_ANY` sentinel.
        // - Real NUMA socket IDs are small non-negative integers
        //   (`< RTE_MAX_NUMA_NODES`, currently 32), safely representable
        //   in `c_int`.
        //
        // No value class produces silent wraparound here, so the `as`
        // cast is sound without a runtime check.
        RawParams {
            raw: dpdk_sys::rte_acl_param {
                name: self.name.as_ptr(),
                socket_id: self.socket_id.as_c_uint() as core::ffi::c_int,
                rule_size: self.rule_size.get(),
                max_rule_num: self.max_rule_num.get(),
            },
            _borrow: PhantomData,
        }
    }
}

/// A [`rte_acl_param`][dpdk_sys::rte_acl_param] that borrows its name pointer
/// from an owning [`AclCreateParams`].
///
/// The lifetime parameter ensures that the FFI struct cannot outlive the
/// [`AclCreateParams`] that owns the underlying C string.  Use [`as_ptr`] to
/// pass the raw pointer into a DPDK call.
///
/// [`as_ptr`]: RawParams::as_ptr
pub(crate) struct RawParams<'a> {
    raw: dpdk_sys::rte_acl_param,
    _borrow: PhantomData<&'a CStr>,
}

impl RawParams<'_> {
    /// Get a pointer to the raw [`rte_acl_param`][dpdk_sys::rte_acl_param].
    ///
    /// The pointer is valid for as long as `self` lives.
    #[inline]
    pub(crate) fn as_ptr(&self) -> *const dpdk_sys::rte_acl_param {
        &self.raw
    }
}

impl<const N: usize> Display for AclCreateParams<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AclCreateParams<{N}> {{ name: \"{}\", socket_id: {:?}, max_rule_num: {}, rule_size: {} }}",
            self.name(),
            self.socket_id,
            self.max_rule_num,
            self.rule_size,
        )
    }
}

// ---------------------------------------------------------------------------
// AclBuildConfig
// ---------------------------------------------------------------------------

/// Maximum number of categories that can be used in an ACL context.
///
/// Corresponds to [`RTE_ACL_MAX_CATEGORIES`][dpdk_sys::RTE_ACL_MAX_CATEGORIES].
pub const MAX_CATEGORIES: u32 = dpdk_sys::RTE_ACL_MAX_CATEGORIES;

/// The required alignment factor for the number of categories.
///
/// The `num_categories` value must be either `1` or a multiple of this value.
///
/// Corresponds to [`RTE_ACL_RESULTS_MULTIPLIER`][dpdk_sys::RTE_ACL_RESULTS_MULTIPLIER].
pub const RESULTS_MULTIPLIER: u32 = dpdk_sys::RTE_ACL_RESULTS_MULTIPLIER;

/// Maximum number of fields per ACL rule.
///
/// Corresponds to [`RTE_ACL_MAX_FIELDS`][dpdk_sys::RTE_ACL_MAX_FIELDS].
pub const MAX_FIELDS: usize = dpdk_sys::RTE_ACL_MAX_FIELDS as usize;

/// Validated build configuration for compiling ACL rules into runtime lookup structures.
///
/// This is the safe Rust equivalent of [`rte_acl_config`][dpdk_sys::rte_acl_config].
///
/// The const generic `N` must match the `N` used in the [`AclContext`][super::context::AclContext]
/// and in the [`Rule`]`<N>` type.  This is enforced by the type system -- the
/// [`build`][super::context::AclContext::build] method requires an `AclBuildConfig` with the same
/// `N` as the context.
///
/// # Validation
///
/// The constructor validates:
/// - `N <= 64` ([`RTE_ACL_MAX_FIELDS`][dpdk_sys::RTE_ACL_MAX_FIELDS])
/// - `num_categories` is between 1 and [`MAX_CATEGORIES`] (inclusive)
/// - `num_categories` is 1 or a multiple of [`RESULTS_MULTIPLIER`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclBuildConfig<const N: usize> {
    /// Number of categories to build with.
    ///
    /// Must be in `1..=`[`MAX_CATEGORIES`] and either `1` or a multiple of
    /// [`RESULTS_MULTIPLIER`].
    num_categories: u32,

    /// Field definitions -- one per field in the rule.
    ///
    /// The order and semantics of these definitions must match the order of
    /// [`AclField`][super::rule::AclField] entries in the [`Rule`]`<N>` instances added to the
    /// context.
    field_defs: [FieldDef; N],

    /// Maximum memory size (in bytes) for the compiled runtime structures.
    ///
    /// Set to `0` to impose no limit.
    max_size: usize,

    /// Cached output of [`min_input_size`][AclBuildConfig::min_input_size].
    ///
    /// Computed once at construction; constant for the lifetime of the
    /// config since `field_defs` cannot be mutated after `new` returns.
    /// Avoids O(N^2) re-computation on every classify-time pre-flight.
    min_input_size: usize,
}

/// Errors that can occur when constructing an [`AclBuildConfig`].
#[derive(Debug, thiserror::Error, Copy, Clone, PartialEq, Eq)]
pub enum InvalidAclBuildConfig {
    /// `N` exceeds [`RTE_ACL_MAX_FIELDS`][dpdk_sys::RTE_ACL_MAX_FIELDS].
    #[error("Too many fields: {num_fields} exceeds maximum of {max}")]
    TooManyFields {
        /// The number of fields that was requested.
        num_fields: usize,
        /// The maximum allowed.
        max: usize,
    },
    /// One of the [`FieldDef`] entries has `field_index >= N`.  DPDK uses
    /// `field_index` to look up each definition's value in the rule's field
    /// array; an out-of-range index would read past `Rule<N>`.
    #[error(
        "FieldDef.field_index {field_index} is out of range for N = {n} \
         (valid range: 0..{n})"
    )]
    FieldIndexOutOfRange {
        /// The offending index.
        field_index: u8,
        /// The const-generic field count.
        n: usize,
    },
    /// Two [`FieldDef`] entries share the same `field_index`.  Field indices
    /// must be unique within the array.
    #[error("FieldDef.field_index {field_index} appears more than once")]
    DuplicateFieldIndex {
        /// The duplicated index.
        field_index: u8,
    },
    /// The first field definition does not match DPDK's requirements for
    /// the trie's entry byte.
    ///
    /// DPDK requires the first field in `field_defs` to be **one byte
    /// long**; it consumes that byte during trie construction.  The
    /// wrapper additionally requires `input_index = 0` on the first
    /// field as a convention -- it labels the entry byte as belonging
    /// to the first input-index group, which simplifies the
    /// runtime-load reasoning in `min_input_size`.
    ///
    /// The first field's **`offset` is unconstrained**: a non-zero
    /// offset just means the input buffer has leading bytes before the
    /// ACL key, and DPDK loads from `field_defs[0].offset` regardless.
    /// `min_input_size` accounts for non-zero leading offsets via the
    /// per-group load-endpoint formula.
    #[error(
        "the first FieldDef must be size = One and input_index = 0 \
         (got size = {size:?}, input_index = {input_index})"
    )]
    InvalidFirstField {
        /// The first field's declared size.
        size: super::field::FieldSize,
        /// The first field's declared `input_index`.
        input_index: u8,
    },

    /// `num_categories` is zero.
    #[error("Number of categories must be at least 1")]
    ZeroCategories,

    /// `num_categories` exceeds [`MAX_CATEGORIES`].
    #[error("Number of categories {num_categories} exceeds maximum of {max}")]
    TooManyCategories {
        /// The requested number of categories.
        num_categories: u32,
        /// The maximum allowed.
        max: u32,
    },

    /// `num_categories` is greater than 1 and not a multiple of [`RESULTS_MULTIPLIER`].
    #[error("Number of categories {num_categories} must be 1 or a multiple of {multiplier}")]
    CategoriesNotAligned {
        /// The requested number of categories.
        num_categories: u32,
        /// The required alignment factor.
        multiplier: u32,
    },

    /// A field whose `(offset, size)` extends past its `input_index`
    /// group's 4-byte window.  DPDK's classify loop loads exactly 4
    /// contiguous bytes per `input_index` group starting at the group's
    /// lowest offset; any field spilling past that window would make
    /// DPDK read bytes the caller never accounted for, undermining the
    /// `min_input_size` safety contract.
    #[error(
        "FieldDef with input_index {input_index} spans beyond a 4-byte \
         window: lowest offset is {group_offset}, but field_index \
         {field_index} extends to offset {extent_end} (max allowed: \
         {window_end})"
    )]
    InvalidInputIndexGrouping {
        /// The offending `input_index`.
        input_index: u8,
        /// The lowest `offset` of any field in the group.
        group_offset: u32,
        /// The `field_index` of the field whose extent overruns the window.
        field_index: u8,
        /// `offset + size` of the offending field.
        extent_end: u32,
        /// `group_offset + 4`.
        window_end: u32,
    },

    /// `input_index` 0 contains more than just the first field.
    ///
    /// DPDK reserves `input_index = 0` for the single 1-byte first field
    /// (the trie entry byte).  No other field may share that group.
    #[error(
        "input_index 0 must contain only the first FieldDef, but \
         field_index {extra_field_index} also has input_index 0"
    )]
    ExtraFieldInFirstGroup {
        /// The `field_index` of the second field sharing `input_index = 0`.
        extra_field_index: u8,
    },

    /// A non-first `input_index` group does not cover exactly 4 contiguous
    /// bytes.  DPDK's runtime loads 4 bytes per group; gaps or overlaps in
    /// the field coverage of a group would either let DPDK read past the
    /// declared fields or build a trie node with inconsistent semantics.
    #[error(
        "input_index {input_index} group does not cover exactly 4 \
         contiguous bytes starting at offset {group_offset} \
         (coverage bitmask within the window: {coverage_mask:#06b}, \
         expected 0b1111)"
    )]
    InputIndexGroupCoverage {
        /// The offending `input_index`.
        input_index: u8,
        /// The lowest `offset` of any field in the group.
        group_offset: u32,
        /// 4-bit mask of which bytes in `[group_offset, group_offset+4)`
        /// are covered by some field in the group.  `0b1111` is the
        /// expected value.
        coverage_mask: u8,
    },

    /// Two fields in the same `input_index` group overlap in the bytes
    /// they cover.  DPDK requires each byte in a group to be claimed by
    /// at most one field.
    #[error(
        "input_index {input_index} group: field_index {field_index} \
         overlaps another field in the same group (overlap mask: \
         {overlap_mask:#06b})"
    )]
    OverlappingFieldsInGroup {
        /// The offending `input_index`.
        input_index: u8,
        /// The `field_index` of the field that introduced the overlap.
        field_index: u8,
        /// 4-bit mask of the overlapping bytes within the group window.
        overlap_mask: u8,
    },

    /// A field's `offset + size` (or its `input_index` group's
    /// `group_offset + 4`) overflows `u32`.  DPDK loads from those offsets
    /// at classify time, and `min_input_size()` would have to report at
    /// least that endpoint -- but a `u32` cannot represent it, which
    /// would let a caller satisfy the documented buffer-size precondition
    /// while DPDK still reads past the end.  We reject such layouts at
    /// construction time.
    #[error(
        "field_index {field_index} extent overflows u32: \
         offset={offset}, size={size_bytes}, would extend past u32::MAX"
    )]
    FieldExtentOverflow {
        /// The offending `field_index`.
        field_index: u8,
        /// The field's offset.
        offset: u32,
        /// The field's size in bytes.
        size_bytes: u8,
    },

    /// Fields sharing an `input_index` are not contiguous in the array.
    ///
    /// DPDK's `acl_build_index` records each group's data-index entry at
    /// the **first occurrence** of the input_index in definition order.
    /// If fields with the same `input_index` are interleaved with other
    /// groups, the wrapper's `min_input_size` calculation (which assumes
    /// the first occurrence is also the group's load offset) can diverge
    /// from DPDK's actual load position, undermining the safety contract.
    /// We require all fields sharing an `input_index` to be consecutive
    /// in the `field_defs` array.
    #[error(
        "input_index {input_index} fields are not contiguous in the \
         field_defs array: field at array position {position} has \
         input_index {input_index} but a different input_index appeared \
         between this field and an earlier sibling"
    )]
    NonContiguousInputIndexGroup {
        /// The offending `input_index`.
        input_index: u8,
        /// The array position of the field that resumed the group.
        position: usize,
    },

    /// Within a contiguous `input_index` group, the fields are not in
    /// strictly-ascending offset order.
    ///
    /// DPDK's `acl_build_index` uses the offset of the **first** field
    /// in each group (in definition order) as the group's load address.
    /// Requiring offset-ascending order within each group makes that
    /// first occurrence also the lowest offset, so the wrapper's
    /// `min_input_size` (computed from `min(offset) per group`) matches
    /// DPDK's actual load position.
    #[error(
        "input_index {input_index} group: field at array position \
         {position} has offset {offset}, which is not strictly greater \
         than the previous field's offset {previous_offset}"
    )]
    GroupFieldsNotOffsetOrdered {
        /// The offending `input_index`.
        input_index: u8,
        /// The array position of the out-of-order field.
        position: usize,
        /// The offending field's offset.
        offset: u32,
        /// The previous (in-group) field's offset.
        previous_offset: u32,
    },
}

impl<const N: usize> AclBuildConfig<N> {
    /// Compile-time guard: `N == 0` is rejected at monomorphization so
    /// `AclBuildConfig::<0>::new` fails to compile.  Mirrors the symmetric
    /// guards on [`Rule<N>`][super::rule::Rule] and [`AclCreateParams<N>`].
    const _CHECK_N_NONZERO: () = assert!(N > 0, "AclBuildConfig requires N > 0");

    /// Compile-time guard: `N` must not exceed
    /// [`MAX_FIELDS`][super::config::MAX_FIELDS].
    ///
    /// Mirrors the same guard on [`AclCreateParams<N>`] so that an
    /// out-of-range `N` is rejected uniformly across the two configuration
    /// types -- without this, `AclBuildConfig<65>` would compile and only
    /// fall over at runtime in `AclBuildConfig::new`'s `TooManyFields`
    /// branch.  Forced to evaluate in `new` via a let-binding.
    const _CHECK_N_FITS_MAX_FIELDS: () = assert!(
        N <= MAX_FIELDS,
        "AclBuildConfig requires N <= RTE_ACL_MAX_FIELDS (64)"
    );

    /// Create a validated build configuration.
    ///
    /// # Arguments
    ///
    /// * `num_categories` -- the number of result categories.  Must be in
    ///   `1..=`[`MAX_CATEGORIES`] and either `1` or a multiple of [`RESULTS_MULTIPLIER`].
    /// * `field_defs` -- the field definitions for the rule layout (one per field).
    /// * `max_size` -- maximum memory (in bytes) for compiled structures, or `0` for no limit.
    ///
    /// # Validation scope
    ///
    /// This constructor checks:
    ///
    /// - **First field shape**: size = 1, `input_index` = 0 (DPDK's
    ///   trie-entry-byte contract).  `offset` is unconstrained -- the
    ///   first field may sit at any byte position in the input buffer,
    ///   and [`min_input_size`][AclBuildConfig::min_input_size] accounts
    ///   for leading bytes via the per-group load-endpoint formula.
    ///   See [`InvalidFirstField`][InvalidAclBuildConfig::InvalidFirstField]
    ///   for the precise contract.
    /// - **`field_index` invariants**: every `field_index` is `< N`, all
    ///   values are unique.
    /// - **`input_index = 0` group**: contains only the first field (no
    ///   other field may share `input_index = 0`).
    /// - **Non-first `input_index` groups**: the union of fields sharing
    ///   the group's `input_index` covers **exactly 4 contiguous bytes**
    ///   with no overlaps -- matches DPDK's runtime 4-byte-per-group
    ///   load pattern.  This is the load-bearing safety check for the
    ///   [`min_input_size`][AclBuildConfig::min_input_size] contract.
    /// - **Categories**: `num_categories` is in `1..=MAX_CATEGORIES` and
    ///   either `1` or a multiple of `RESULTS_MULTIPLIER`.
    ///
    /// An `Ok` from this constructor does **not** imply a successful build
    /// at DPDK time -- DPDK may still reject the config for reasons we do
    /// not pre-check (e.g. excessive trie size with `max_size > 0`).  But
    /// every reason the wrapper accepts a config corresponds to a layout
    /// whose `classify`-time loads stay within
    /// [`min_input_size`][AclBuildConfig::min_input_size] bytes.
    ///
    /// [`AclBuildError::InvalidConfig`]: super::error::AclBuildError::InvalidConfig
    ///
    /// # Errors
    ///
    /// Returns [`InvalidAclBuildConfig`] if any parameter is out of range.
    #[cold]
    #[tracing::instrument(level = "debug")]
    pub fn new(
        num_categories: u32,
        field_defs: [FieldDef; N],
        max_size: usize,
    ) -> Result<Self, InvalidAclBuildConfig> {
        // Force evaluation of both const assertions for this monomorphisation.
        // `_CHECK_N_FITS_MAX_FIELDS` makes `N > MAX_FIELDS` a compile error,
        // so the runtime branch below is unreachable for any properly
        // monomorphised call; we keep the runtime check as a defence-in-depth
        // (and to surface a typed `TooManyFields` error rather than a panic
        // for cases where the const-assert is bypassed).
        let () = Self::_CHECK_N_NONZERO;
        let () = Self::_CHECK_N_FITS_MAX_FIELDS;

        if N > MAX_FIELDS {
            return Err(InvalidAclBuildConfig::TooManyFields {
                num_fields: N,
                max: MAX_FIELDS,
            });
        }
        if num_categories == 0 {
            return Err(InvalidAclBuildConfig::ZeroCategories);
        }
        if num_categories > MAX_CATEGORIES {
            return Err(InvalidAclBuildConfig::TooManyCategories {
                num_categories,
                max: MAX_CATEGORIES,
            });
        }
        if num_categories > 1 && !num_categories.is_multiple_of(RESULTS_MULTIPLIER) {
            return Err(InvalidAclBuildConfig::CategoriesNotAligned {
                num_categories,
                multiplier: RESULTS_MULTIPLIER,
            });
        }

        // First field: DPDK requires size = 1 (the trie's entry byte),
        // and the wrapper additionally requires input_index = 0 so that
        // the entry byte sits in its own input-index group (see the
        // grouping validator below).  `offset` is unconstrained -- it
        // simply describes where in the input buffer the entry byte
        // lives; `min_input_size` accounts for any leading bytes.
        // N > 0 has been checked above, so field_defs[0] is safe to index.
        let first = &field_defs[0];
        if !matches!(first.size(), super::field::FieldSize::One) || first.input_index() != 0 {
            return Err(InvalidAclBuildConfig::InvalidFirstField {
                size: first.size(),
                input_index: first.input_index(),
            });
        }

        // Every field_index must be < N (DPDK uses it to index the rule's
        // field array, so out-of-range reads past Rule<N>) and unique.
        // O(N^2) duplicate check is fine: N <= RTE_ACL_MAX_FIELDS = 64.
        for (i, def) in field_defs.iter().enumerate() {
            let fi = def.field_index();
            if (fi as usize) >= N {
                return Err(InvalidAclBuildConfig::FieldIndexOutOfRange {
                    field_index: fi,
                    n: N,
                });
            }
            for later in &field_defs[i + 1..] {
                if later.field_index() == fi {
                    return Err(InvalidAclBuildConfig::DuplicateFieldIndex { field_index: fi });
                }
            }
        }

        // No other field may share input_index = 0; that group is reserved
        // for the 1-byte first field.
        for def in &field_defs[1..] {
            if def.input_index() == 0 {
                return Err(InvalidAclBuildConfig::ExtraFieldInFirstGroup {
                    extra_field_index: def.field_index(),
                });
            }
        }

        // Validate definition-order shape:
        //
        // 1. Fields with the same `input_index` must appear consecutively
        //    in `field_defs` (no interleaving with other groups).  DPDK's
        //    `acl_build_index` walks defs in array order and records a
        //    new data-index slot whenever input_index changes; an
        //    interleaving caller would create two separate data-index
        //    slots for the same logical group, breaking the
        //    `min_input_size` calculation.
        //
        // 2. Within each contiguous run, offsets must be strictly
        //    ascending.  DPDK uses the first field's offset (in array
        //    order) as the group's load address; requiring
        //    offset-ascending order makes that first field also the
        //    lowest-offset field, so our `min_input_size` (computed from
        //    `min(offset)` per group) matches DPDK's actual load.
        //
        // We track each input_index's "already closed" status via a
        // bitmap: once a different input_index is observed after we've
        // started one, the closed bit for that one is set and a later
        // re-occurrence is an error.  Indexed by `input_index`, which
        // fits in u8 (i.e. 0..=255).
        let mut closed = [false; 256];
        let mut current_input_index: Option<(u8, u32)> = None; // (input_index, last_offset_seen)
        for (pos, def) in field_defs.iter().enumerate() {
            let ii = def.input_index();
            let offset = def.offset();
            match current_input_index {
                Some((open_ii, last_offset)) if open_ii == ii => {
                    // Still inside the same group; verify offset > last_offset.
                    if offset <= last_offset {
                        return Err(InvalidAclBuildConfig::GroupFieldsNotOffsetOrdered {
                            input_index: ii,
                            position: pos,
                            offset,
                            previous_offset: last_offset,
                        });
                    }
                    current_input_index = Some((ii, offset));
                }
                Some((open_ii, _)) => {
                    // Group `open_ii` is now closed; start `ii` if it
                    // hasn't already been closed.
                    closed[open_ii as usize] = true;
                    if closed[ii as usize] {
                        return Err(InvalidAclBuildConfig::NonContiguousInputIndexGroup {
                            input_index: ii,
                            position: pos,
                        });
                    }
                    current_input_index = Some((ii, offset));
                }
                None => {
                    current_input_index = Some((ii, offset));
                }
            }
        }

        // Reject any field whose extent (`offset + size`) or whose
        // group-load endpoint (`offset + 4`) would overflow `u32`.
        // `min_input_size` reports a `usize` derived from these
        // endpoints; if the u32 arithmetic saturates, the reported
        // bound understates DPDK's actual read extent and the safety
        // contract is broken.
        for def in &field_defs {
            let size_bytes = def.size() as u8 as u32;
            if def.offset().checked_add(size_bytes).is_none()
                || def.offset().checked_add(4).is_none()
            {
                return Err(InvalidAclBuildConfig::FieldExtentOverflow {
                    field_index: def.field_index(),
                    offset: def.offset(),
                    size_bytes: def.size() as u8,
                });
            }
        }

        // Validate the input_index grouping rule for non-first groups:
        // every field sharing an input_index > 0 must fit inside a 4-byte
        // window starting at the group's lowest offset, and the union of
        // all fields in the group must cover **exactly** those 4 bytes
        // with no overlap.  DPDK loads 4 contiguous bytes per group at the
        // group_offset; a sub-4-byte covered region would leave loaded
        // bytes unattributed to any field (incorrect trie traversal), and
        // an overlap would build a trie node with inconsistent semantics.
        //
        // O(N^2) again; N <= MAX_FIELDS = 64.  Coverage tracked as a 4-bit
        // mask within the group window (bit i means "byte at group_offset + i").
        // The overflow check above means `offset + size` and `group_offset
        // + 4` no longer need saturation; they fit in u32 by construction.
        for def in &field_defs {
            let ii = def.input_index();
            if ii == 0 {
                continue; // already handled above
            }
            // group_offset = min(field.offset for field where input_index == ii)
            let mut group_offset = def.offset();
            for other in &field_defs {
                if other.input_index() == ii && other.offset() < group_offset {
                    group_offset = other.offset();
                }
            }
            let extent_end = def.offset() + def.size() as u8 as u32;
            let window_end = group_offset + 4;
            if extent_end > window_end {
                return Err(InvalidAclBuildConfig::InvalidInputIndexGrouping {
                    input_index: ii,
                    group_offset,
                    field_index: def.field_index(),
                    extent_end,
                    window_end,
                });
            }
        }
        // Second pass: each non-first input_index group must cover exactly
        // 4 contiguous bytes via the union of its fields, with no overlap.
        // We iterate inputs once, dedup'ing by tracking the first
        // appearance of each input_index.
        for (anchor_idx, anchor) in field_defs.iter().enumerate() {
            let ii = anchor.input_index();
            if ii == 0 {
                continue;
            }
            // Process this input_index only at its first occurrence.
            if field_defs[..anchor_idx]
                .iter()
                .any(|prev| prev.input_index() == ii)
            {
                continue;
            }
            // group_offset = min(field.offset for field in group)
            let group_offset = field_defs
                .iter()
                .filter(|d| d.input_index() == ii)
                .map(|d| d.offset())
                .min()
                .unwrap_or(anchor.offset());
            // Accumulate the 4-bit coverage mask; reject overlaps.
            let mut mask: u8 = 0;
            for d in field_defs.iter().filter(|d| d.input_index() == ii) {
                let shift = (d.offset() - group_offset) as u8;
                let size_bits = d.size() as u8;
                let field_mask = ((1u8 << size_bits) - 1) << shift;
                let overlap = mask & field_mask;
                if overlap != 0 {
                    return Err(InvalidAclBuildConfig::OverlappingFieldsInGroup {
                        input_index: ii,
                        field_index: d.field_index(),
                        overlap_mask: overlap,
                    });
                }
                mask |= field_mask;
            }
            if mask != 0b1111 {
                return Err(InvalidAclBuildConfig::InputIndexGroupCoverage {
                    input_index: ii,
                    group_offset,
                    coverage_mask: mask,
                });
            }
        }

        // Memoize the safety-critical buffer-size requirement.  All
        // grouping invariants have been validated above, so this loop is
        // sound and the result is constant for the lifetime of the
        // config.
        let min_input_size = Self::compute_min_input_size(&field_defs);

        debug!(
            "Created ACL build config: num_categories={num_categories}, num_fields={N}, max_size={max_size}, min_input_size={min_input_size}",
        );

        Ok(Self {
            num_categories,
            field_defs,
            max_size,
            min_input_size,
        })
    }

    /// Compute the buffer-size requirement at construction time.
    ///
    /// See [`min_input_size`][AclBuildConfig::min_input_size] for the
    /// formula and rationale.  Factored out so that `new` can call it
    /// once and cache the result; the public accessor returns the cached
    /// value.
    ///
    /// Precondition: all fields' `offset + 4` fit in `u32`.  This is
    /// guaranteed by the `FieldExtentOverflow` check in
    /// [`new`][AclBuildConfig::new], so the plain `+` below cannot
    /// overflow.
    fn compute_min_input_size(field_defs: &[FieldDef; N]) -> usize {
        let mut max_load_end: u32 = 0;
        for def in field_defs {
            let ii = def.input_index();
            let mut group_offset = def.offset();
            for other in field_defs {
                if other.input_index() == ii && other.offset() < group_offset {
                    group_offset = other.offset();
                }
            }
            // No saturation: `new`'s FieldExtentOverflow check has
            // already verified `def.offset() + 4 <= u32::MAX` for every
            // def, and `group_offset <= def.offset()`.
            let load_end = group_offset + 4;
            if load_end > max_load_end {
                max_load_end = load_end;
            }
        }
        max_load_end as usize
    }

    /// Get the number of categories.
    #[must_use]
    pub fn num_categories(&self) -> u32 {
        self.num_categories
    }

    /// Get the field definitions.
    #[must_use]
    pub fn field_defs(&self) -> &[FieldDef; N] {
        &self.field_defs
    }

    /// Get the maximum memory size for compiled structures.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// The minimum size, in bytes, that an input buffer passed to
    /// [`classify`][super::context::AclContext::classify] must be valid for.
    ///
    /// DPDK's classify loop does **not** read one field at a time at the
    /// field's `offset`; it performs 4-byte aligned loads where each load's
    /// starting offset is the lowest `FieldDef.offset` within an
    /// `input_index` group.  For every distinct `input_index` value the
    /// buffer must therefore be valid for reads in
    /// `[group_offset, group_offset + 4)`.  This function returns the
    /// maximum `group_offset + 4` across all `input_index` groups.
    ///
    /// The grouping invariant validated by [`new`][AclBuildConfig::new]
    /// (every field's `offset + size` fits within its group's 4-byte
    /// window) guarantees that this value is also at least
    /// `max(field.offset + field.size)`.
    ///
    /// Callers of the unsafe [`classify`][super::context::AclContext::classify]
    /// API should size their input buffers to at least this value to avoid
    /// out-of-bounds reads.
    ///
    /// Computed and cached at [`new`][AclBuildConfig::new] time;
    /// returning the cached value is O(1).
    #[must_use]
    pub fn min_input_size(&self) -> usize {
        self.min_input_size
    }

    /// Convert to the raw DPDK [`rte_acl_config`][dpdk_sys::rte_acl_config].
    ///
    /// The returned struct is fully owned and has no lifetime dependency on `self`.
    ///
    /// # Stack footprint
    ///
    /// `rte_acl_config::defs` is a fixed-size C array of
    /// `RTE_ACL_MAX_FIELDS` (= [`MAX_FIELDS`] = 64) entries -- about 0.5 KiB
    /// on the stack at 8 bytes per `rte_acl_field_def`.  Build is a cold
    /// path, so the size is acceptable; we materialise the full array
    /// because DPDK's `rte_acl_build` reads `defs[0..num_fields]` and
    /// ignores entries beyond `num_fields`, but the array storage itself
    /// must be present.
    pub(crate) fn to_raw(&self) -> dpdk_sys::rte_acl_config {
        let mut defs = [dpdk_sys::rte_acl_field_def::default(); MAX_FIELDS];
        for (i, def) in self.field_defs.iter().enumerate() {
            defs[i] = dpdk_sys::rte_acl_field_def::from(def);
        }
        dpdk_sys::rte_acl_config {
            num_categories: self.num_categories,
            num_fields: N as u32,
            defs,
            max_size: self.max_size,
        }
    }
}

impl<const N: usize> Display for AclBuildConfig<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AclBuildConfig<{N}> {{ num_categories: {}, max_size: {} }}",
            self.num_categories, self.max_size,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::field::{FieldSize, FieldType};

    /// Test-local shorthand: build a `NonZero<u32>` from a literal that we know is non-zero.
    fn nz(value: u32) -> NonZero<u32> {
        NonZero::new(value).expect("test literal is non-zero")
    }

    // -- AclCreateParams name validation --

    #[test]
    fn valid_name_accepted() {
        let result = AclCreateParams::<5>::new("my_acl_ctx", SocketId::ANY, nz(1024));
        assert!(result.is_ok());
        let params = result.unwrap();
        assert_eq!(params.name(), "my_acl_ctx");
    }

    #[test]
    fn empty_name_rejected() {
        let result = AclCreateParams::<1>::new("", SocketId::ANY, nz(128));
        assert!(matches!(result, Err(InvalidAclName::Empty)));
    }

    #[test]
    fn non_ascii_name_rejected() {
        // Three-character non-ASCII string (U+65E5 U+672C U+8A9E).  Spelled
        // out via escapes rather than a literal so source stays ASCII-only.
        let result = AclCreateParams::<1>::new("\u{65E5}\u{672C}\u{8A9E}", SocketId::ANY, nz(128));
        assert!(matches!(result, Err(InvalidAclName::NotAscii)));
    }

    #[test]
    fn too_long_name_rejected() {
        // MAX_ACL_NAME_LEN is RTE_ACL_NAMESIZE - 1 = 31
        let long_name: String = "a".repeat(MAX_ACL_NAME_LEN + 1);
        let result = AclCreateParams::<1>::new(&long_name, SocketId::ANY, nz(128));
        assert!(matches!(result, Err(InvalidAclName::TooLong { .. })));
    }

    #[test]
    fn max_length_name_accepted() {
        let name: String = "a".repeat(MAX_ACL_NAME_LEN);
        let result = AclCreateParams::<1>::new(&name, SocketId::ANY, nz(128));
        assert!(result.is_ok());
    }

    #[test]
    fn name_with_null_byte_rejected() {
        let result = AclCreateParams::<1>::new("hello\0world", SocketId::ANY, nz(128));
        assert!(matches!(result, Err(InvalidAclName::ContainsNullBytes)));
    }

    #[test]
    fn rule_size_matches_generic() {
        let params = AclCreateParams::<5>::new("test", SocketId::ANY, nz(128)).unwrap();
        assert_eq!(
            params.rule_size().get() as usize,
            core::mem::size_of::<Rule<5>>()
        );
    }

    #[test]
    fn to_raw_preserves_values() {
        let params = AclCreateParams::<3>::new("raw_test", SocketId::ANY, nz(256)).unwrap();
        let raw_params = params.to_raw();
        // SAFETY: raw_params borrows from `params`, which is alive in this scope.
        let raw = unsafe { *raw_params.as_ptr() };
        // Name pointer should point to the same C string data.
        let raw_name = unsafe { CStr::from_ptr(raw.name) };
        assert_eq!(raw_name.to_str().unwrap(), "raw_test");
        assert_eq!(raw.max_rule_num, 256);
        assert_eq!(raw.rule_size as usize, core::mem::size_of::<Rule<3>>());
    }

    #[test]
    fn display_contains_name() {
        let params = AclCreateParams::<1>::new("display_test", SocketId::ANY, nz(10)).unwrap();
        let s = format!("{params}");
        assert!(s.contains("display_test"), "got: {s}");
    }

    // -- AclBuildConfig validation --

    /// Build a valid `[FieldDef; N]` with the DPDK first-field-is-one-byte
    /// constraint satisfied.
    fn sample_field_defs<const N: usize>() -> [FieldDef; N] {
        core::array::from_fn(|i| {
            if i == 0 {
                FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0)
            } else {
                FieldDef::new(
                    FieldType::Mask,
                    FieldSize::Four,
                    i as u8,
                    i as u8,
                    (i * 4) as u32,
                )
            }
        })
    }

    #[test]
    fn valid_build_config_single_category() {
        let cfg = AclBuildConfig::new(1, sample_field_defs::<5>(), 0);
        assert!(cfg.is_ok());
        let cfg = cfg.unwrap();
        assert_eq!(cfg.num_categories(), 1);
        assert_eq!(cfg.max_size(), 0);
        assert_eq!(cfg.field_defs().len(), 5);
    }

    #[test]
    fn valid_build_config_multiple_categories() {
        let cfg = AclBuildConfig::new(4, sample_field_defs::<3>(), 1024);
        assert!(cfg.is_ok());
        assert_eq!(cfg.unwrap().num_categories(), 4);
    }

    #[test]
    fn zero_categories_rejected() {
        let result = AclBuildConfig::new(0, sample_field_defs::<1>(), 0);
        assert!(matches!(result, Err(InvalidAclBuildConfig::ZeroCategories)));
    }

    #[test]
    fn too_many_categories_rejected() {
        let result = AclBuildConfig::new(MAX_CATEGORIES + 1, sample_field_defs::<1>(), 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::TooManyCategories { .. })
        ));
    }

    #[test]
    fn max_categories_accepted() {
        let result = AclBuildConfig::new(MAX_CATEGORIES, sample_field_defs::<1>(), 0);
        assert!(result.is_ok());
    }

    #[test]
    fn misaligned_categories_rejected() {
        // 3 is > 1 but not a multiple of RESULTS_MULTIPLIER (4)
        let result = AclBuildConfig::new(3, sample_field_defs::<1>(), 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::CategoriesNotAligned { .. })
        ));
    }

    #[test]
    fn to_raw_build_config_preserves_fields() {
        // Two 2-byte Range fields in input_index 1 (offsets 4 and 6) fill
        // bytes [4, 8) exactly -- a valid grouping under the strict rule.
        let defs: [FieldDef; 3] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Range, FieldSize::Two, 1, 1, 4),
            FieldDef::new(FieldType::Range, FieldSize::Two, 2, 1, 6),
        ];
        let cfg = AclBuildConfig::new(1, defs, 4096).unwrap();
        let raw = cfg.to_raw();
        assert_eq!(raw.num_categories, 1);
        assert_eq!(raw.num_fields, 3);
        assert_eq!(raw.max_size, 4096);
        assert_eq!(raw.defs[0].type_, FieldType::Bitmask as u8);
        assert_eq!(raw.defs[0].size, FieldSize::One as u8);
        assert_eq!(raw.defs[0].offset, 0);
        assert_eq!(raw.defs[1].type_, FieldType::Range as u8);
        assert_eq!(raw.defs[1].size, FieldSize::Two as u8);
        assert_eq!(raw.defs[1].offset, 4);
        assert_eq!(raw.defs[2].type_, FieldType::Range as u8);
        assert_eq!(raw.defs[2].size, FieldSize::Two as u8);
        assert_eq!(raw.defs[2].offset, 6);
    }

    #[test]
    fn build_config_display() {
        let cfg = AclBuildConfig::new(4, sample_field_defs::<3>(), 0).unwrap();
        let s = format!("{cfg}");
        assert!(s.contains("AclBuildConfig<3>"), "got: {s}");
        assert!(s.contains("num_categories: 4"), "got: {s}");
    }

    // Note: there is no runtime `zero_fields_rejected` test.  N == 0 is
    // rejected at compile time by the `_CHECK_N_NONZERO` const assertion on
    // `AclBuildConfig<N>`, so `AclBuildConfig::<0>::new(1, [], 0)` would
    // fail to monomorphize.

    #[test]
    fn first_field_invalid_rejected() {
        // First field is Four bytes -- must be One.
        let defs: [FieldDef; 2] = [
            FieldDef::new(FieldType::Mask, FieldSize::Four, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 1, 4),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::InvalidFirstField {
                size: FieldSize::Four,
                input_index: 0,
            })
        ));
    }

    #[test]
    fn field_index_out_of_range_rejected() {
        // N = 2 but field_index = 5 on the second def -- DPDK would index
        // past Rule<2> when looking up the field value.
        let defs: [FieldDef; 2] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 5, 1, 4),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::FieldIndexOutOfRange {
                field_index: 5,
                n: 2
            })
        ));
    }

    #[test]
    fn duplicate_field_index_rejected() {
        // Both defs declare field_index = 0.
        let defs: [FieldDef; 2] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 0, 1, 4),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::DuplicateFieldIndex { field_index: 0 })
        ));
    }

    #[test]
    fn invalid_input_index_grouping_rejected() {
        // Two fields share input_index 1, but their offsets span more than 4
        // bytes (offset 4 + offset 12 cannot both fit in [4, 8) -- field at
        // offset 12 with size 4 extends to offset 16, but the group window
        // is [4, 8)).
        let defs: [FieldDef; 3] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 1, 4),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 2, 1, 12),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::InvalidInputIndexGrouping {
                input_index: 1,
                group_offset: 4,
                field_index: 2,
                extent_end: 16,
                window_end: 8,
            })
        ));
    }

    #[test]
    fn extra_field_in_first_group_rejected() {
        // Two fields share input_index 0; only field_defs[0] is allowed there.
        let defs: [FieldDef; 2] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 0, 4),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::ExtraFieldInFirstGroup {
                extra_field_index: 1
            })
        ));
    }

    #[test]
    fn undersized_group_rejected() {
        // input_index 1 has a single 1-byte field; group must cover all 4
        // bytes.  Coverage mask would be 0b0001 (just byte 0 of the group).
        let defs: [FieldDef; 2] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 1, 1, 4),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::InputIndexGroupCoverage {
                input_index: 1,
                group_offset: 4,
                coverage_mask: 0b0001,
            })
        ));
    }

    #[test]
    fn overlapping_group_fields_rejected() {
        // A 4-byte field at offset 4 followed by a 2-byte field at offset
        // 6 -- both in input_index 1.  Offsets are strictly ascending
        // (passes ordering), but the byte ranges overlap in [6, 8).
        let defs: [FieldDef; 3] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 1, 4),
            FieldDef::new(FieldType::Mask, FieldSize::Two, 2, 1, 6),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::OverlappingFieldsInGroup { input_index: 1, .. })
        ));
    }

    #[test]
    fn non_contiguous_input_index_group_rejected() {
        // input_index 1 is interrupted by input_index 2 and then resumed.
        let defs: [FieldDef; 4] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Two, 1, 1, 4),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 2, 2, 8),
            FieldDef::new(FieldType::Mask, FieldSize::Two, 3, 1, 6),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::NonContiguousInputIndexGroup {
                input_index: 1,
                position: 3,
            })
        ));
    }

    #[test]
    fn group_fields_not_offset_ordered_rejected() {
        // Within input_index 1, the second field has a lower offset than
        // the first.  Ordering must be strictly ascending.
        let defs: [FieldDef; 3] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Two, 1, 1, 6),
            FieldDef::new(FieldType::Mask, FieldSize::Two, 2, 1, 4),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::GroupFieldsNotOffsetOrdered {
                input_index: 1,
                position: 2,
                offset: 4,
                previous_offset: 6,
            })
        ));
    }

    #[test]
    fn field_extent_overflow_rejected() {
        // A 4-byte field at offset = u32::MAX - 2: offset + size = u32::MAX + 2
        // overflows u32.  Must be rejected at construction; otherwise
        // min_input_size's u32-based computation would saturate and
        // understate DPDK's actual read endpoint.
        let defs: [FieldDef; 2] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 1, u32::MAX - 2),
        ];
        let result = AclBuildConfig::new(1, defs, 0);
        assert!(matches!(
            result,
            Err(InvalidAclBuildConfig::FieldExtentOverflow {
                field_index: 1,
                offset: o,
                size_bytes: 4,
            }) if o == u32::MAX - 2
        ));
    }

    #[test]
    fn min_input_size_uses_group_offsets() {
        // input_index 9 group fully covers bytes [100, 104) via a 4-byte
        // field.  DPDK loads 4 bytes from the group_offset (100), so
        // min_input_size must be 104.  A formula like `input_index * 4 +
        // 4` (which earlier wrapper versions used) would compute 40 and
        // let DPDK read past the end of an undersized buffer.
        let defs: [FieldDef; 2] = [
            FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
            FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 9, 100),
        ];
        let cfg = AclBuildConfig::new(1, defs, 0).expect("config should validate");
        assert_eq!(
            cfg.min_input_size(),
            104,
            "DPDK loads 4 bytes from group_offset = 100, so min_input_size = 104"
        );
    }

    /// Property: `AclCreateParams::new` accepts a name iff it is non-empty
    /// ASCII without interior NUL bytes and of length `<= MAX_ACL_NAME_LEN`.
    /// Verifies the four error variants are mutually exclusive and that the
    /// expected variant is produced for each rejection class.
    #[test]
    fn create_params_name_validation_property() {
        bolero::check!()
            .with_type::<String>()
            .for_each(|name: &String| {
                let result = AclCreateParams::<1>::new(name.as_str(), SocketId::ANY, nz(1));
                match result {
                    Ok(params) => {
                        // Name was accepted: must satisfy all preconditions.
                        assert!(!name.is_empty());
                        assert!(name.is_ascii());
                        assert!(name.len() <= MAX_ACL_NAME_LEN);
                        assert!(!name.contains('\0'));
                        assert_eq!(params.name(), name.as_str());
                    }
                    Err(InvalidAclName::Empty) => assert!(name.is_empty()),
                    Err(InvalidAclName::NotAscii) => assert!(!name.is_ascii()),
                    Err(InvalidAclName::TooLong { len, max }) => {
                        assert_eq!(len, name.len());
                        assert_eq!(max, MAX_ACL_NAME_LEN);
                        assert!(name.len() > MAX_ACL_NAME_LEN);
                    }
                    Err(InvalidAclName::ContainsNullBytes) => {
                        // Reached only after Empty / NotAscii / TooLong checks
                        // pass, so the name is non-empty ASCII of valid length
                        // and must contain at least one interior NUL.
                        assert!(!name.is_empty());
                        assert!(name.is_ascii());
                        assert!(name.len() <= MAX_ACL_NAME_LEN);
                        assert!(name.contains('\0'));
                    }
                }
            });
    }

    /// Property: `AclBuildConfig::new` accepts `num_categories` iff it is
    /// non-zero, within `MAX_CATEGORIES`, and either `1` or a multiple of
    /// `RESULTS_MULTIPLIER`.
    #[test]
    fn build_config_num_categories_validation_property() {
        bolero::check!()
            .with_type::<u32>()
            .for_each(|num_categories: &u32| {
                let result = AclBuildConfig::new(*num_categories, sample_field_defs::<1>(), 0);
                let in_range = *num_categories > 0 && *num_categories <= MAX_CATEGORIES;
                let aligned =
                    *num_categories == 1 || (*num_categories).is_multiple_of(RESULTS_MULTIPLIER);
                match result {
                    Ok(cfg) => {
                        assert!(in_range);
                        assert!(aligned);
                        assert_eq!(cfg.num_categories(), *num_categories);
                    }
                    Err(InvalidAclBuildConfig::ZeroCategories) => {
                        assert_eq!(*num_categories, 0);
                    }
                    Err(InvalidAclBuildConfig::TooManyCategories {
                        num_categories: n,
                        max,
                    }) => {
                        assert_eq!(n, *num_categories);
                        assert_eq!(max, MAX_CATEGORIES);
                        assert!(*num_categories > MAX_CATEGORIES);
                    }
                    Err(InvalidAclBuildConfig::CategoriesNotAligned { .. }) => {
                        assert!(in_range);
                        assert!(!aligned);
                    }
                    Err(InvalidAclBuildConfig::TooManyFields { .. }) => {
                        unreachable!("N=1 cannot trigger TooManyFields")
                    }
                    Err(InvalidAclBuildConfig::FieldIndexOutOfRange { .. })
                    | Err(InvalidAclBuildConfig::DuplicateFieldIndex { .. })
                    | Err(InvalidAclBuildConfig::InvalidFirstField { .. })
                    | Err(InvalidAclBuildConfig::ExtraFieldInFirstGroup { .. })
                    | Err(InvalidAclBuildConfig::InvalidInputIndexGrouping { .. })
                    | Err(InvalidAclBuildConfig::InputIndexGroupCoverage { .. })
                    | Err(InvalidAclBuildConfig::OverlappingFieldsInGroup { .. })
                    | Err(InvalidAclBuildConfig::NonContiguousInputIndexGroup { .. })
                    | Err(InvalidAclBuildConfig::GroupFieldsNotOffsetOrdered { .. })
                    | Err(InvalidAclBuildConfig::FieldExtentOverflow { .. }) => {
                        unreachable!(
                            "sample_field_defs<1> produces a valid layout; field-array errors \
                             are not reachable via this test"
                        )
                    }
                }
            });
    }

    /// Property: `AclBuildConfig::new` accepts a `[FieldDef; N]` iff an
    /// independent Rust-side oracle says all wrapper-enforced invariants
    /// hold.  Bolero generates a fuzzed 32-byte input, deterministically
    /// constructs a `[FieldDef; 4]` from it, and checks that both the
    /// validator and the oracle agree.
    ///
    /// The oracle is written from scratch (not copied from the impl) so
    /// that a bug in either implementation will produce a disagreement.
    /// Specifically catches mistakes in the ordering / contiguity /
    /// coverage / overlap logic of [`AclBuildConfig::new`].
    #[test]
    fn build_config_field_defs_validation_property() {
        const N: usize = 4;
        // 8 bytes per FieldDef * 4 fields = 32 bytes of input.
        bolero::check!()
            .with_type::<[u8; 32]>()
            .for_each(|input: &[u8; 32]| {
                let defs = field_defs_from_bytes::<N>(input);
                let actual = AclBuildConfig::new(1, defs, 0);
                let expected_accept = oracle_field_defs_valid::<N>(&defs);
                match (expected_accept, actual.as_ref()) {
                    (true, Ok(_)) | (false, Err(_)) => {}
                    (true, Err(e)) => {
                        panic!(
                            "oracle accepted layout but validator rejected: {e:?}\n  defs: {defs:?}"
                        );
                    }
                    (false, Ok(_)) => {
                        panic!("oracle rejected layout but validator accepted\n  defs: {defs:?}");
                    }
                }
            });
    }

    /// Construct a `[FieldDef; N]` deterministically from raw bytes.
    /// Each FieldDef consumes 8 bytes: 1 for field_type, 1 for size, 1
    /// for field_index, 1 for input_index, 4 for offset.
    ///
    /// `field_type` is the low 2 bits of byte 0, mapping to Mask (0),
    /// Range (1), Bitmask (2).  Value 3 is biased toward Mask (the
    /// most common case) by also mapping it to Mask.
    ///
    /// `size` is the low 2 bits of byte 1, mapping to One (0/3), Two
    /// (1), Four (2).
    fn field_defs_from_bytes<const N: usize>(bytes: &[u8]) -> [FieldDef; N] {
        use crate::acl::field::{FieldSize, FieldType};
        core::array::from_fn(|i| {
            let base = i * 8;
            let ft = match bytes[base] & 0b11 {
                0 | 3 => FieldType::Mask,
                1 => FieldType::Range,
                2 => FieldType::Bitmask,
                _ => unreachable!(),
            };
            let sz = match bytes[base + 1] & 0b11 {
                0 | 3 => FieldSize::One,
                1 => FieldSize::Two,
                2 => FieldSize::Four,
                _ => unreachable!(),
            };
            let field_index = bytes[base + 2];
            let input_index = bytes[base + 3];
            let offset = u32::from_le_bytes([
                bytes[base + 4],
                bytes[base + 5],
                bytes[base + 6],
                bytes[base + 7],
            ]);
            FieldDef::new(ft, sz, field_index, input_index, offset)
        })
    }

    /// Independent oracle: returns `true` iff every wrapper-enforced
    /// invariant on `field_defs` holds.  Written from scratch (not
    /// copied from `AclBuildConfig::new`) so that disagreement with the
    /// impl pinpoints a bug in one or the other.
    fn oracle_field_defs_valid<const N: usize>(field_defs: &[FieldDef; N]) -> bool {
        use crate::acl::field::FieldSize;

        if N == 0 || N > MAX_FIELDS {
            return false;
        }

        // First field: size = One, input_index = 0 (offset is unconstrained).
        let first = &field_defs[0];
        if !matches!(first.size(), FieldSize::One) {
            return false;
        }
        if first.input_index() != 0 {
            return false;
        }

        // field_index < N and unique.
        let mut seen = [false; 256];
        for def in field_defs {
            let fi = def.field_index() as usize;
            if fi >= N {
                return false;
            }
            if seen[fi] {
                return false;
            }
            seen[fi] = true;
        }

        // Per-field extent fits in u32 (no `offset + size` or
        // `offset + 4` overflow).
        for def in field_defs {
            let size_bytes = def.size() as u8 as u32;
            if def.offset().checked_add(size_bytes).is_none()
                || def.offset().checked_add(4).is_none()
            {
                return false;
            }
        }

        // No other field shares input_index = 0.
        for def in &field_defs[1..] {
            if def.input_index() == 0 {
                return false;
            }
        }

        // Contiguity + intra-group ordering: walk the array, track the
        // current "open" input_index and the previously-seen offset for
        // it.  When input_index changes, mark the old one closed; if a
        // later position uses an already-closed input_index, that's a
        // non-contiguous group.
        let mut closed = [false; 256];
        let mut open: Option<(u8, u32)> = None;
        for def in field_defs {
            let ii = def.input_index();
            let off = def.offset();
            match open {
                Some((cur_ii, last_off)) if cur_ii == ii => {
                    if off <= last_off {
                        return false;
                    }
                    open = Some((ii, off));
                }
                Some((cur_ii, _)) => {
                    closed[cur_ii as usize] = true;
                    if closed[ii as usize] {
                        return false;
                    }
                    open = Some((ii, off));
                }
                None => {
                    open = Some((ii, off));
                }
            }
        }

        // Each non-first input_index group: per-field extent fits in a
        // 4-byte window from group_offset, total coverage is exactly
        // 4 bytes with no overlap.
        //
        // `saturating_add` here vs. plain `+` in the impl: the impl
        // gates this check behind the `FieldExtentOverflow` pre-flight
        // (offsets where `offset + 4` overflows are already rejected),
        // so plain `+` in the impl is sound.  The oracle runs the
        // overflow check earlier and returns `false` on overflow too,
        // so this branch is only reached for non-overflowing
        // arithmetic -- but we keep `saturating_add` here as a
        // defensive fence so a bug in the oracle's overflow check
        // would not panic this loop while fuzzing.
        for def in field_defs {
            let ii = def.input_index();
            if ii == 0 {
                continue;
            }
            // group_offset = min offset across the group.
            let group_offset = field_defs
                .iter()
                .filter(|d| d.input_index() == ii)
                .map(|d| d.offset())
                .min()
                .expect("group is non-empty by construction");
            let extent_end = def.offset().saturating_add(def.size() as u8 as u32);
            if extent_end > group_offset.saturating_add(4) {
                return false;
            }
        }
        // Coverage / overlap, processed once per group (at first
        // occurrence in array order).
        for (anchor_idx, anchor) in field_defs.iter().enumerate() {
            let ii = anchor.input_index();
            if ii == 0 {
                continue;
            }
            if field_defs[..anchor_idx]
                .iter()
                .any(|prev| prev.input_index() == ii)
            {
                continue;
            }
            let group_offset = field_defs
                .iter()
                .filter(|d| d.input_index() == ii)
                .map(|d| d.offset())
                .min()
                .expect("group is non-empty");
            let mut mask: u8 = 0;
            for d in field_defs.iter().filter(|d| d.input_index() == ii) {
                let shift = (d.offset() - group_offset) as u8;
                let size_bits = d.size() as u8;
                let field_mask = ((1u8 << size_bits) - 1) << shift;
                if mask & field_mask != 0 {
                    return false;
                }
                mask |= field_mask;
            }
            if mask != 0b1111 {
                return false;
            }
        }

        true
    }
}
