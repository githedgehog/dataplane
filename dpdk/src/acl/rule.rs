// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL rule types.
//!
//! These types provide safe, `#[repr(C)]` wrappers around the DPDK ACL rule structures.
//! The key types are:
//!
//! - [`RuleData`] -- rule metadata (category mask, priority, user data).
//! - [`AclField`] -- a single field value with its mask or range bound.
//! - [`Rule`]`<N>` -- a complete rule comprising [`RuleData`] followed by `N` [`AclField`] entries.
//!
//! # Layout guarantee
//!
//! [`Rule`]`<N>` is `#[repr(C)]` and has an identical memory layout to the struct produced by
//! DPDK's `RTE_ACL_RULE_DEF(name, N)` C macro.  This means a `*const Rule<N>` can be safely cast
//! to `*const rte_acl_rule` when calling [`rte_acl_add_rules`][dpdk_sys::rte_acl_add_rules],
//! provided the context was created with `rule_size = size_of::<Rule<N>>()`.
//!
//! # Byte order
//!
//! All fields in [`Rule`] structures are expected to be in **host byte order**, as documented by
//! DPDK.  This is in contrast to the *input data buffers* passed to
//! [`rte_acl_classify`][dpdk_sys::rte_acl_classify], which must be in **network byte order**
//! (MSB).

use core::fmt;
use core::mem;
use core::num::NonZero;

// ---------------------------------------------------------------------------
// Priority
// ---------------------------------------------------------------------------

/// DPDK ACL rule priority bounds.
///
/// A result of `0` from classification means "no match", so valid user data values and priorities
/// must respect these bounds.
pub mod priority {
    /// Minimum valid rule priority (inclusive).
    ///
    /// Corresponds to
    /// [`RTE_ACL_MIN_PRIORITY`][dpdk_sys::_bindgen_ty_4::RTE_ACL_MIN_PRIORITY].
    pub const MIN: i32 = dpdk_sys::_bindgen_ty_4::RTE_ACL_MIN_PRIORITY as i32;

    /// Maximum valid rule priority (inclusive).
    ///
    /// Corresponds to
    /// [`RTE_ACL_MAX_PRIORITY`][dpdk_sys::_bindgen_ty_4::RTE_ACL_MAX_PRIORITY].
    pub const MAX: i32 = dpdk_sys::_bindgen_ty_4::RTE_ACL_MAX_PRIORITY as i32;
}

/// A validated ACL rule priority.
///
/// The inner [`NonZero<i32>`] is guaranteed to fall in the closed range
/// \[[`priority::MIN`], [`priority::MAX`]\] (DPDK's `RTE_ACL_MIN_PRIORITY` is
/// `1`, so zero is unreachable).  `#[repr(transparent)]` means this is
/// layout-compatible with the underlying `i32` field of
/// [`rte_acl_rule_data`][dpdk_sys::rte_acl_rule_data], and `Option<Priority>`
/// is niche-optimised down to 4 bytes -- matching the
/// [`userdata: NonZero<u32>`](RuleData) treatment.
///
/// Construct via [`new`][Priority::new] (which is `const fn`, so it works in
/// `const` contexts at the cost of an `?` or `.unwrap()`).  The
/// [`MIN`][Priority::MIN] and [`MAX`][Priority::MAX] constants are pre-validated
/// shorthand for the range endpoints.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Priority(NonZero<i32>);

/// Error returned when [`Priority::new`] is given an out-of-range value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "ACL priority {value} out of range [{}, {}]",
    priority::MIN,
    priority::MAX
)]
pub struct InvalidPriority {
    /// The out-of-range value the caller supplied.
    pub value: i32,
}

impl Priority {
    // Both constants below evaluate at compile time.  `NonZero::new` +
    // `.unwrap()` in a const context surfaces as a const-eval error
    // (not a runtime panic) if the value happens to be zero -- which
    // would itself be a compile-time bug.  Clippy's
    // `useless_nonzero_new_unchecked` lint prefers this form over
    // `NonZero::new_unchecked` for const items.

    /// Smallest valid priority value (equal to [`priority::MIN`] = DPDK's
    /// `RTE_ACL_MIN_PRIORITY`, currently `1`).
    pub const MIN: Self = match NonZero::new(priority::MIN) {
        Some(nz) => Self(nz),
        // unreachable in const context: priority::MIN is a positive i32
        // (verified at compile time); reaching this arm would be a
        // compile error, not a runtime panic.
        None => panic!("priority::MIN must be non-zero"),
    };

    /// Largest valid priority value (equal to [`priority::MAX`] = DPDK's
    /// `RTE_ACL_MAX_PRIORITY`).
    pub const MAX: Self = match NonZero::new(priority::MAX) {
        Some(nz) => Self(nz),
        None => panic!("priority::MAX must be non-zero"),
    };

    /// Construct a `Priority` from a raw value.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPriority`] when `value` is outside
    /// \[[`priority::MIN`], [`priority::MAX`]\].
    pub const fn new(value: i32) -> Result<Self, InvalidPriority> {
        if value < priority::MIN || value > priority::MAX {
            return Err(InvalidPriority { value });
        }
        // priority::MIN == 1 (DPDK's RTE_ACL_MIN_PRIORITY), so the
        // range check above guarantees value >= 1 and therefore != 0;
        // the `unreachable!()` arm is dead.  Preferred over
        // `unsafe { NonZero::new_unchecked }` so a wrong invariant
        // faults loudly instead of being undefined behaviour.
        match NonZero::new(value) {
            Some(nz) => Ok(Self(nz)),
            None => unreachable!(),
        }
    }

    /// Get the raw `i32`.
    #[must_use]
    pub const fn get(self) -> i32 {
        self.0.get()
    }
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<i32> for Priority {
    type Error = InvalidPriority;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// CategoryMask
// ---------------------------------------------------------------------------

/// A validated category bitmask for an ACL rule.
///
/// Each bit corresponds to one category (bit `i` enables category `i`).  DPDK
/// supports up to [`RTE_ACL_MAX_CATEGORIES`][dpdk_sys::RTE_ACL_MAX_CATEGORIES]
/// categories, so only the low `RTE_ACL_MAX_CATEGORIES` bits may be set.
///
/// `#[repr(transparent)]` and inner [`NonZero<u32>`] make `Option<CategoryMask>`
/// niche-optimised to 4 bytes and rule out the zero-mask case (a rule with no
/// categories enabled can never match).  The bit-range check enforces the
/// type-level invariant that no out-of-range categories are referenced.
///
/// A successful build with `num_categories = k` does not imply `k = 32`; the
/// per-build category count is checked by DPDK at `rte_acl_build` time.  This
/// newtype enforces the upper bound common to all builds.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CategoryMask(NonZero<u32>);

/// Error returned when [`CategoryMask::new`] is given an invalid bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidCategoryMask {
    /// The mask is zero -- the rule would match no category.
    #[error("category mask is zero")]
    Zero,
    /// The mask has bits set above `RTE_ACL_MAX_CATEGORIES`.
    #[error(
        "category mask {value:#010x} has bits set above bit {} \
         (RTE_ACL_MAX_CATEGORIES = {})",
        dpdk_sys::RTE_ACL_MAX_CATEGORIES - 1,
        dpdk_sys::RTE_ACL_MAX_CATEGORIES
    )]
    OutOfRange {
        /// The out-of-range value the caller supplied.
        value: u32,
    },
}

impl CategoryMask {
    /// Bit mask covering all categories DPDK supports: bits 0 through
    /// `RTE_ACL_MAX_CATEGORIES - 1` inclusive.
    pub const ALLOWED_BITS: u32 = {
        // Avoid (1 << 32) overflow when MAX_CATEGORIES is 32; (1u32 << 32) is UB
        // in C and a debug-panic in Rust, so guard.
        let max = dpdk_sys::RTE_ACL_MAX_CATEGORIES;
        if max >= 32 {
            u32::MAX
        } else {
            (1u32 << max) - 1
        }
    };

    /// Construct a `CategoryMask` from a raw `u32`.
    ///
    /// # Errors
    ///
    /// - [`InvalidCategoryMask::Zero`] if `value == 0`.
    /// - [`InvalidCategoryMask::OutOfRange`] if any bit above
    ///   `RTE_ACL_MAX_CATEGORIES - 1` is set.
    pub const fn new(value: u32) -> Result<Self, InvalidCategoryMask> {
        if value == 0 {
            return Err(InvalidCategoryMask::Zero);
        }
        if value & !Self::ALLOWED_BITS != 0 {
            return Err(InvalidCategoryMask::OutOfRange { value });
        }
        // The `value == 0` check above guarantees value != 0, so the
        // `unreachable!()` arm is dead.  Preferred over
        // `unsafe { NonZero::new_unchecked }` so a wrong invariant
        // faults loudly instead of being undefined behaviour.
        match NonZero::new(value) {
            Some(nz) => Ok(Self(nz)),
            None => unreachable!(),
        }
    }

    /// The raw `u32` value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for CategoryMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0.get())
    }
}

impl TryFrom<u32> for CategoryMask {
    type Error = InvalidCategoryMask;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// RuleData
// ---------------------------------------------------------------------------

/// Metadata associated with an ACL rule.
///
/// This is the safe Rust equivalent of [`rte_acl_rule_data`][dpdk_sys::rte_acl_rule_data] and has
/// an identical `#[repr(C)]` memory layout.
///
/// # Important: `userdata` must be non-zero
///
/// DPDK uses `userdata == 0` as a sentinel meaning "no match".  If you set `userdata` to `0`,
/// the rule will effectively never be reported as matching.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct RuleData {
    /// Bitmask of categories this rule applies to.
    ///
    /// Each bit corresponds to one category (bit `i` enables category `i`).
    /// Validated at construction; see [`CategoryMask::new`].
    pub category_mask: CategoryMask,

    /// Rule priority.  Higher numeric value means higher priority.
    ///
    /// When multiple rules match a given input for the same category, the rule with the highest
    /// priority wins.  Validated to be in the range
    /// \[[`priority::MIN`], [`priority::MAX`]\] at construction; see [`Priority::new`].
    pub priority: Priority,

    /// Opaque value returned to the caller on match.
    ///
    /// **Must be non-zero.**  A classification result of `0` indicates that no rule matched.
    pub userdata: NonZero<u32>,
}

// Compile-time layout assertions against the raw DPDK type.
const _: () = {
    assert!(
        mem::size_of::<RuleData>() == mem::size_of::<dpdk_sys::rte_acl_rule_data>(),
        "RuleData size must match rte_acl_rule_data"
    );
    assert!(
        mem::align_of::<RuleData>() == mem::align_of::<dpdk_sys::rte_acl_rule_data>(),
        "RuleData alignment must match rte_acl_rule_data"
    );
};

impl fmt::Display for RuleData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RuleData {{ category_mask: {}, priority: {}, userdata: {} }}",
            self.category_mask, self.priority, self.userdata,
        )
    }
}

// ---------------------------------------------------------------------------
// AclField
// ---------------------------------------------------------------------------

/// A single field value within an ACL rule.
///
/// This is the safe Rust equivalent of [`rte_acl_field`][dpdk_sys::rte_acl_field] and has an
/// identical `#[repr(C)]` memory layout.
///
/// The interpretation of the value and mask/range depends on the
/// [`FieldType`][super::field::FieldType] specified in the corresponding
/// [`FieldDef`][super::field::FieldDef]:
///
/// | [`FieldType`][super::field::FieldType] | value      | mask/range         |
/// |----------------------------------------|------------|--------------------|
/// | [`Mask`][super::field::FieldType::Mask]       | match value  | prefix length      |
/// | [`Range`][super::field::FieldType::Range]     | range low    | range high         |
/// | [`Bitmask`][super::field::FieldType::Bitmask] | match value  | bitmask            |
///
/// Use the [`from_u8`][AclField::from_u8], [`from_u16`][AclField::from_u16],
/// [`from_u32`][AclField::from_u32], or [`from_u64_raw`][AclField::from_u64_raw] constructors to set
/// the value and mask/range for the appropriate field width.
///
/// # Why the union fields are private
///
/// The `rte_acl_field_types` union is exposed via private fields so that safe
/// code cannot construct an `AclField` with a narrow union member set and
/// uninitialized upper bytes (e.g. `rte_acl_field_types { u8_: 5 }` leaves
/// bytes 1..8 undefined).  Safe accessors read `u64_` and would observe those
/// uninit bytes, which is undefined behavior.  Forcing construction through
/// [`from_u8`][AclField::from_u8] / [`from_u16`][AclField::from_u16] /
/// [`from_u32`][AclField::from_u32] / [`from_u64_raw`][AclField::from_u64_raw] (each
/// of which zeroes the full 8 bytes before writing the narrow member)
/// upholds the "all 8 bytes initialized" invariant that the union accessors
/// rely on.
///
/// `AclField` is layout-compatible with [`rte_acl_field`][dpdk_sys::rte_acl_field] (verified by
/// the const asserts below).  We keep the Rust newtype rather than re-exporting the bindgen
/// struct so that we can attach typed constructors, safe accessors, and proper `Debug` /
/// `Display` impls without leaking the `_bindgen_ty_*` union name into consumer code.
// INVARIANT (union access on AclField).
//
// Every `AclField` reachable through this crate's safe API must have its
// `value` and `mask_range` unions **fully initialized in all 8 bytes**.  All
// constructors uphold this:
//
// * `Default::default()` -- explicit `u64_: 0` initializer per union
//   (zeroes all 8 bytes; no `unsafe` needed).
// * `from_u8` / `from_u16` / `from_u32` -- call `Self::default()` first
//   (zeroing both unions) then overwrite a narrow member.
// * `from_u64_raw` -- writes both unions with explicit `u64_` initializers.
// * `zero()` -- delegates to `Default::default()`.
//
// Given this invariant, reading any union member (including the widest,
// `u64_`) is sound: every member of `rte_acl_field_types` is an integer
// type, so any bit pattern is a valid value.  Each `unsafe` block that
// reads a union member cites this anchor as its SAFETY argument so that
// removing one impl (e.g. `Debug`) does not orphan the invariant for the
// others.
//
// The `mem::size_of::<rte_acl_field_types>() == 8` const-assert below is
// the load-bearing check that "writing 8 bytes" covers the whole union;
// a future bindgen change adding a non-integer member trips it.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AclField {
    /// The match value (or range lower bound).  Private -- see the type-level
    /// doc for why, and the INVARIANT comment above for the union-access
    /// soundness argument.
    value: dpdk_sys::rte_acl_field_types,
    /// The mask, bitmask, or range upper bound (interpretation depends on the
    /// field type).  Private -- see the type-level doc and the INVARIANT
    /// comment above.
    mask_range: dpdk_sys::rte_acl_field_types,
}

// Compile-time layout assertions against the raw DPDK type.
//
// The union-accessor soundness argument (every constructor writes 8 bytes;
// every union member is an integer type) depends on the union being exactly
// 8 bytes wide.  We assert that directly so a future bindgen change that
// adds, e.g., a `__m128` member trips here rather than silently making the
// safe accessors unsound.
const _: () = {
    assert!(
        mem::size_of::<dpdk_sys::rte_acl_field_types>() == 8,
        "rte_acl_field_types union must be exactly 8 bytes for the \
         'all 8 bytes initialized' invariant on AclField accessors"
    );
    assert!(
        mem::size_of::<AclField>() == mem::size_of::<dpdk_sys::rte_acl_field>(),
        "AclField size must match rte_acl_field"
    );
    assert!(
        mem::align_of::<AclField>() == mem::align_of::<dpdk_sys::rte_acl_field>(),
        "AclField alignment must match rte_acl_field"
    );
};

impl Default for AclField {
    /// Returns a zero-initialized field.
    ///
    /// For [`Mask`][super::field::FieldType::Mask]-type fields, this is a wildcard that matches
    /// any input (value `0` with mask `0`).
    fn default() -> Self {
        // Explicit per-union initialization through the `u64_` member
        // zeroes all 8 bytes of each union without going through
        // `mem::zeroed`.  This is safe (no `unsafe` needed) and upholds
        // the same "all 8 bytes initialised" invariant the union
        // accessors rely on.
        Self {
            value: dpdk_sys::rte_acl_field_types { u64_: 0 },
            mask_range: dpdk_sys::rte_acl_field_types { u64_: 0 },
        }
    }
}

impl fmt::Debug for AclField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: see the INVARIANT (union access on AclField) block above
        // the struct definition.  Every constructor leaves all 8 bytes of
        // each union initialized; reading `u64_` is defined behavior.
        let (value, mask) = unsafe { (self.value.u64_, self.mask_range.u64_) };
        f.debug_struct("AclField")
            .field("value", &format_args!("{value:#018x}"))
            .field("mask_range", &format_args!("{mask:#018x}"))
            .finish()
    }
}

impl fmt::Display for AclField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: see the INVARIANT (union access on AclField) block above
        // the struct definition.
        //
        // Format choice: labeled `value=... mask_range=...` instead of
        // `value/mask_range`.  The latter reads like a CIDR prefix
        // (`addr/len`), but `mask_range` for Mask-typed fields actually IS
        // a prefix length while for Bitmask/Range it's a bitmask or upper
        // bound -- the slash form would mislead in two of three cases.
        let (value, mask) = unsafe { (self.value.u64_, self.mask_range.u64_) };
        write!(f, "value={value:#018x} mask_range={mask:#018x}")
    }
}

impl PartialEq for AclField {
    fn eq(&self, other: &Self) -> bool {
        // SAFETY: see the INVARIANT (union access on AclField) block above the struct definition.
        unsafe {
            self.value.u64_ == other.value.u64_ && self.mask_range.u64_ == other.mask_range.u64_
        }
    }
}

// `Eq` cannot be derived because the underlying bindgen union does not implement `Eq`.
// Manual impl is sound because `PartialEq` is reflexive for the integer-typed union members.
impl Eq for AclField {}

impl core::hash::Hash for AclField {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // SAFETY: see the INVARIANT (union access on AclField) block above the struct definition.
        let (value, mask) = unsafe { (self.value.u64_, self.mask_range.u64_) };
        value.hash(state);
        mask.hash(state);
    }
}

impl AclField {
    /// Create a field from `u8` value and mask/range.
    ///
    /// Use this for fields declared with [`FieldSize::One`][super::field::FieldSize::One].
    ///
    /// The upper bytes of the underlying union are zeroed.
    #[must_use]
    pub fn from_u8(value: u8, mask_range: u8) -> Self {
        // Zero-initialize first so that the upper bytes are deterministic.
        let mut field = Self::default();
        field.value.u8_ = value;
        field.mask_range.u8_ = mask_range;
        field
    }

    /// Create a field from `u16` value and mask/range.
    ///
    /// Use this for fields declared with [`FieldSize::Two`][super::field::FieldSize::Two].
    ///
    /// The upper bytes of the underlying union are zeroed.
    #[must_use]
    pub fn from_u16(value: u16, mask_range: u16) -> Self {
        let mut field = Self::default();
        field.value.u16_ = value;
        field.mask_range.u16_ = mask_range;
        field
    }

    /// Create a field from `u32` value and mask/range.
    ///
    /// Use this for fields declared with [`FieldSize::Four`][super::field::FieldSize::Four].
    ///
    /// The upper bytes of the underlying union are zeroed.
    #[must_use]
    pub fn from_u32(value: u32, mask_range: u32) -> Self {
        let mut field = Self::default();
        field.value.u32_ = value;
        field.mask_range.u32_ = mask_range;
        field
    }

    /// Create a field from a raw `u64` value and mask/range, writing all
    /// 8 bytes of each union member directly.
    ///
    /// The wrapper's [`FieldSize`][super::field::FieldSize] caps at 4
    /// bytes, so bits above the declared `size_bytes * 8` are ignored by
    /// DPDK at classify time and will be rejected by
    /// [`Rule::validate`] /
    /// [`add_rules`][super::context::AclContext::add_rules] when
    /// invariant-checking against the
    /// [`AclBuildConfig<N>`][super::config::AclBuildConfig].  Prefer
    /// [`from_u8`][AclField::from_u8] / [`from_u16`][AclField::from_u16] /
    /// [`from_u32`][AclField::from_u32] for normal use; this constructor
    /// exists for explicit bit-pattern composition (e.g. test fixtures
    /// or low-level data interop).
    #[must_use]
    pub fn from_u64_raw(value: u64, mask_range: u64) -> Self {
        Self {
            value: dpdk_sys::rte_acl_field_types { u64_: value },
            mask_range: dpdk_sys::rte_acl_field_types { u64_: mask_range },
        }
    }

    /// Create a fully-zeroed field -- value `0` with mask/range `0`.
    ///
    /// Equivalent to [`AclField::default()`].
    ///
    /// # Important: this is **not** a universal wildcard
    ///
    /// Whether a zero field matches anything depends on the field's
    /// [`FieldType`][super::field::FieldType] in the build config:
    ///
    /// - [`Mask`][super::field::FieldType::Mask] -- matches **anything**
    ///   (`mask_range == 0` means "prefix length 0", i.e. compare zero bits).
    /// - [`Range`][super::field::FieldType::Range] -- matches **only the
    ///   value 0** (low and high bounds both 0).  For a range wildcard use
    ///   [`from_u32`][AclField::from_u32]`(0, u32::MAX)` or the appropriate
    ///   width.
    /// - [`Bitmask`][super::field::FieldType::Bitmask] -- matches anything
    ///   (predicate is `(input & 0) == 0`, which is trivially true), but
    ///   you almost always want a non-zero mask in practice; reach for an
    ///   explicit constructor instead.
    #[must_use]
    pub fn zero() -> Self {
        Self::default()
    }

    /// Read the value as `u8`.
    ///
    /// Reading any integer-typed union member is sound for any [`AclField`]
    /// constructed through this crate's public API.  The caller should still
    /// ensure the field was constructed via [`from_u8`][AclField::from_u8] or
    /// that the `u8` interpretation is meaningful in context; otherwise the
    /// returned value is the low byte of whatever wider member was stored.
    #[must_use]
    pub fn value_u8(&self) -> u8 {
        // SAFETY: see the INVARIANT (union access on AclField) block
        // above the struct definition.  Every constructor leaves all 8
        // bytes of each union initialized via explicit `u64_: 0` followed
        // by narrow-member writes, so reading any union member is defined
        // behavior.
        unsafe { self.value.u8_ }
    }

    /// Read the mask/range as `u8`.
    ///
    /// See [`value_u8`][AclField::value_u8] for the interpretation note.
    #[must_use]
    pub fn mask_range_u8(&self) -> u8 {
        // SAFETY: see value_u8.
        unsafe { self.mask_range.u8_ }
    }

    /// Read the value as `u16`.
    ///
    /// See [`value_u8`][AclField::value_u8] for the interpretation note.
    #[must_use]
    pub fn value_u16(&self) -> u16 {
        // SAFETY: see value_u8.
        unsafe { self.value.u16_ }
    }

    /// Read the mask/range as `u16`.
    ///
    /// See [`value_u8`][AclField::value_u8] for the interpretation note.
    #[must_use]
    pub fn mask_range_u16(&self) -> u16 {
        // SAFETY: see value_u8.
        unsafe { self.mask_range.u16_ }
    }

    /// Read the value as `u32`.
    ///
    /// See [`value_u8`][AclField::value_u8] for the interpretation note.
    #[must_use]
    pub fn value_u32(&self) -> u32 {
        // SAFETY: see value_u8.
        unsafe { self.value.u32_ }
    }

    /// Read the mask/range as `u32`.
    ///
    /// See [`value_u8`][AclField::value_u8] for the interpretation note.
    #[must_use]
    pub fn mask_range_u32(&self) -> u32 {
        // SAFETY: see value_u8.
        unsafe { self.mask_range.u32_ }
    }

    /// Read the value as `u64`.
    #[must_use]
    pub fn value_u64(&self) -> u64 {
        // SAFETY: see the INVARIANT (union access on AclField) block above the struct definition.
        unsafe { self.value.u64_ }
    }

    /// Read the mask/range as `u64`.
    #[must_use]
    pub fn mask_range_u64(&self) -> u64 {
        // SAFETY: see the INVARIANT (union access on AclField) block above the struct definition.
        unsafe { self.mask_range.u64_ }
    }
}

// ---------------------------------------------------------------------------
// Rule<N>
// ---------------------------------------------------------------------------

/// A complete ACL rule with `N` fields.
///
/// This type is `#[repr(C)]` and has the same memory layout as the struct produced by the DPDK
/// `RTE_ACL_RULE_DEF(name, N)` macro:
///
/// ```c
/// struct name {
///     struct rte_acl_rule_data data;
///     struct rte_acl_field     field[N];
/// };
/// ```
///
/// Because of this layout guarantee, a `*const Rule<N>` can be cast to `*const rte_acl_rule` and
/// passed directly to [`rte_acl_add_rules`][dpdk_sys::rte_acl_add_rules], as long as the ACL
/// context was created with `rule_size = core::mem::size_of::<Rule<N>>()`.
///
/// # Const parameter `N`
///
/// `N` is the number of fields in this rule and must match the number of
/// [`FieldDef`][super::field::FieldDef] entries in the
/// [`AclBuildConfig`][super::config::AclBuildConfig] used to build the
/// [`AclContext`][super::context::AclContext].  Using the same const generic for both the context
/// and its rules catches field-count mismatches at compile time.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Rule<const N: usize> {
    /// Rule metadata: category mask, priority, and user data.
    ///
    /// Private so that constructing a `Rule<N>` must go through
    /// [`Rule::new`], which enforces the `N > 0` compile-time check.  Read via
    /// [`Rule::data`] / [`Rule::data_mut`].
    data: RuleData,
    /// Field values (one per field definition in the ACL context).
    ///
    /// Private for the same reason as `data` -- see the doc above.  Read via
    /// [`Rule::fields`] / [`Rule::fields_mut`].
    fields: [AclField; N],
}

impl<const N: usize> Rule<N> {
    /// Compile-time guard: a zero-field rule has nothing to match against
    /// and DPDK would reject it at build time anyway.  Catch it earlier.
    const _CHECK_N_NONZERO: () = assert!(N > 0, "Rule<N> requires N > 0");

    /// Compile-time guard: `Rule<N>` must have exactly the layout produced by
    /// the C macro `RTE_ACL_RULE_DEF(_, N)`: 12 bytes of `rte_acl_rule_data`
    /// plus 4 bytes of padding (to reach 8-byte alignment of `rte_acl_field`)
    /// plus `N * 16` bytes of fields.  This is evaluated for every concrete
    /// `N` reached at runtime (forced via the let-binding in `new`).
    const _CHECK_LAYOUT: () = {
        let expected = mem::size_of::<dpdk_sys::rte_acl_rule>()
            + N * mem::size_of::<dpdk_sys::rte_acl_field>();
        assert!(
            mem::size_of::<Self>() == expected,
            "Rule<N> layout must match RTE_ACL_RULE_DEF(_, N)"
        );
        assert!(
            mem::align_of::<Self>() == mem::align_of::<dpdk_sys::rte_acl_rule>(),
            "Rule<N> alignment must match rte_acl_rule"
        );
    };

    /// The size of this rule type in bytes, suitable for passing as `rule_size` when creating an
    /// ACL context.
    ///
    /// This is equivalent to `core::mem::size_of::<Rule<N>>()` but provided as a named constant
    /// for clarity at call sites.
    pub const RULE_SIZE: u32 = mem::size_of::<Self>() as u32;

    /// Create a new rule.
    ///
    /// # Arguments
    ///
    /// * `data` -- the rule metadata (category mask, priority, and user data).
    /// * `fields` -- the field values for this rule; one entry per field definition.
    #[must_use]
    pub const fn new(data: RuleData, fields: [AclField; N]) -> Self {
        // Force evaluation of the const checks at every instantiation of `new`.
        let () = Self::_CHECK_N_NONZERO;
        let () = Self::_CHECK_LAYOUT;
        Self { data, fields }
    }

    /// Borrow the rule metadata.
    #[must_use]
    pub const fn data(&self) -> &RuleData {
        &self.data
    }

    /// Mutable access to the rule metadata.
    ///
    /// Note: mutations made through this reference are not re-validated
    /// until the [`Rule`] is handed to
    /// [`AclContext::add_rules`][super::context::AclContext::add_rules],
    /// which calls [`validate`][Rule::validate] before forwarding to
    /// DPDK.  Any out-of-range mutation (e.g. setting `category_mask`
    /// bits beyond `num_categories`) is caught at that point.
    #[must_use]
    pub const fn data_mut(&mut self) -> &mut RuleData {
        &mut self.data
    }

    /// Borrow the field values.
    #[must_use]
    pub const fn fields(&self) -> &[AclField; N] {
        &self.fields
    }

    /// Mutable access to the field values.
    ///
    /// See [`data_mut`][Rule::data_mut] for the re-validation note --
    /// the same caveat applies: mutations are checked against the
    /// build config at
    /// [`add_rules`][super::context::AclContext::add_rules] time.
    #[must_use]
    pub const fn fields_mut(&mut self) -> &mut [AclField; N] {
        &mut self.fields
    }

    /// Validate this rule's field values against the layout in
    /// [`AclBuildConfig<N>`][super::config::AclBuildConfig].
    ///
    /// Run before each [`add_rules`][super::context::AclContext::add_rules]
    /// call by the wrapper; exposed publicly so callers can pre-flight
    /// rules in test fixtures or batch validators.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidRule`][super::error::InvalidRule] on the first
    /// violation found.  Specifically catches:
    ///
    /// - **Soundness-critical:** a [`FieldType::Mask`][super::field::FieldType::Mask]
    ///   field whose `mask_range` (prefix length) exceeds the field's bit
    ///   width.  DPDK would compute `RTE_ACL_MASKLEN_TO_BITMASK(prefix_len, size)`
    ///   on this, which shifts by `>= 8 * size` -- undefined behaviour in C.
    /// - A [`FieldType::Range`][super::field::FieldType::Range] field with
    ///   reversed low/high bounds.
    /// - A `category_mask` with bits set at positions
    ///   `>= config.num_categories()` (DPDK would silently mask them off).
    ///
    /// Each field is read through the union member that **DPDK** reads
    /// for that field type:
    ///
    /// - [`FieldType::Mask`][super::field::FieldType::Mask]: `mask_range`
    ///   is read via `u64_`, because DPDK feeds the entire 64-bit value
    ///   to `RTE_ACL_MASKLEN_TO_BITMASK`.  Validating via the same view
    ///   catches big-endian narrow writes (where `from_u8(_, 1)` lands
    ///   at the MSB of the union and would shift by `>= 8 * size` -- UB
    ///   in C).  On little-endian targets the `u64_` view and the
    ///   size-specific view agree.
    /// - [`FieldType::Range`][super::field::FieldType::Range]: `value` /
    ///   `mask_range` are read through the size-appropriate union member
    ///   (`u8_` for `FieldSize::One`, `u16_` for `Two`, `u32_` for `Four`),
    ///   because DPDK's range-trie generator reads the bounds byte-wise
    ///   over `size` bytes.  Garbage bits in wider union members are
    ///   ignored: DPDK never reads through them for a size-narrower field.
    /// - [`FieldType::Bitmask`][super::field::FieldType::Bitmask]: not
    ///   validated here.  DPDK reads the bitmask byte-wise over `size`
    ///   bytes and an unsatisfiable `value & !mask_range != 0` predicate
    ///   produces a dead rule, not UB.
    pub fn validate(
        &self,
        config: &super::config::AclBuildConfig<N>,
    ) -> Result<(), super::error::InvalidRule> {
        use super::error::InvalidRule;
        use super::field::FieldType;

        // category_mask: any bit at position >= num_categories will be
        // silently masked out by DPDK at build time.  Reject up-front so
        // the rule's intended category set is what actually gets matched.
        let num_categories = config.num_categories();
        let category_mask = self.data.category_mask.get();
        let allowed_categories: u32 = if num_categories >= 32 {
            u32::MAX
        } else {
            (1u32 << num_categories) - 1
        };
        let extra_bits = category_mask & !allowed_categories;
        if extra_bits != 0 {
            return Err(InvalidRule::CategoryMaskExceedsNumCategories {
                category_mask,
                num_categories,
                extra_bits,
            });
        }

        for def in config.field_defs() {
            // field_index < N is guaranteed by AclBuildConfig::new.
            let field = &self.fields[def.field_index() as usize];
            let size_bytes = def.size() as u8;
            let max_bits = u32::from(size_bytes) * 8;

            match def.field_type() {
                FieldType::Mask => {
                    // DPDK reads `mask_range.u64` for MASK fields and
                    // feeds it to `RTE_ACL_MASKLEN_TO_BITMASK`, which
                    // shifts `(uint64_t)-1` by `8 * size - prefix_length`.
                    // We must validate against the same view DPDK will
                    // see: on big-endian, a narrow constructor like
                    // `from_u8(_, 1)` lands at the most-significant
                    // byte of the union and reading `mask_range.u64`
                    // yields `1 << 56`, far exceeding `max_bits` and
                    // making the C shift undefined.  Validating via
                    // `mask_range_u64` rejects that input up-front
                    // with a clear error rather than silently passing
                    // a UB-triggering value to DPDK.  On little-endian
                    // (currently the only tested target) the u64 view
                    // and the size-specific view agree, so this
                    // changes nothing for LE callers.
                    let prefix_length = field.mask_range_u64();
                    if prefix_length > u64::from(max_bits) {
                        return Err(InvalidRule::PrefixLengthOutOfRange {
                            field_index: def.field_index(),
                            prefix_length,
                            max_bits,
                        });
                    }
                }
                FieldType::Range => {
                    // DPDK reads RANGE bounds byte-wise over `size`
                    // bytes (see `acl_gen_range_trie`), so the
                    // size-matching union member is the right view
                    // for the bounds-ordering check.
                    let (value, mask_range): (u64, u64) = match def.size() {
                        super::field::FieldSize::One => (
                            u64::from(field.value_u8()),
                            u64::from(field.mask_range_u8()),
                        ),
                        super::field::FieldSize::Two => (
                            u64::from(field.value_u16()),
                            u64::from(field.mask_range_u16()),
                        ),
                        super::field::FieldSize::Four => (
                            u64::from(field.value_u32()),
                            u64::from(field.mask_range_u32()),
                        ),
                    };
                    if value > mask_range {
                        return Err(InvalidRule::RangeReversed {
                            field_index: def.field_index(),
                            low: value,
                            high: mask_range,
                        });
                    }
                }
                FieldType::Bitmask => {
                    // No wrapper-side check.  DPDK reads BITMASK
                    // value/mask_range byte-wise over `size` bytes
                    // and ignores wider bytes.  A user-mistake like
                    // `value & !mask_range != 0` (an unsatisfiable
                    // bitmask predicate) is not UB; it just produces
                    // a dead rule.  If a future lint pass surfaces
                    // those, it belongs in a separate diagnostic
                    // module, not in the soundness-critical
                    // validator here.
                }
            }
        }
        Ok(())
    }
}

impl<const N: usize> fmt::Display for Rule<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rule<{N}> {{ {}, fields: [", self.data)?;
        for (i, field) in self.fields.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{field}")?;
        }
        write!(f, "] }}")
    }
}

// ---------------------------------------------------------------------------
// Layout verification
// ---------------------------------------------------------------------------

/// Compile-time pins for the DPDK struct sizes that the [`Rule`]`<N>` layout
/// formula depends on.
///
/// The field array in [`rte_acl_rule`][dpdk_sys::rte_acl_rule] starts at offset
/// 16 (12 bytes of `rte_acl_rule_data` + 4 bytes of padding to reach 8-byte
/// alignment of `rte_acl_field`), so the layout invariant
/// `size_of::<Rule<N>>() == size_of::<rte_acl_rule>() + N * size_of::<rte_acl_field>()`
/// is checked for every concrete `N` by [`Rule::_CHECK_LAYOUT`], not by spot
/// checks here.
const _: () = {
    // rte_acl_rule_data is 12 bytes, alignment 4
    assert!(mem::size_of::<dpdk_sys::rte_acl_rule_data>() == 12);
    assert!(mem::align_of::<dpdk_sys::rte_acl_rule_data>() == 4);
    // rte_acl_field is 16 bytes, alignment 8
    assert!(mem::size_of::<dpdk_sys::rte_acl_field>() == 16);
    assert!(mem::align_of::<dpdk_sys::rte_acl_field>() == 8);
    // rte_acl_rule (with flexible array) is 16 bytes base, alignment 8
    assert!(mem::size_of::<dpdk_sys::rte_acl_rule>() == 16);
    assert!(mem::align_of::<dpdk_sys::rte_acl_rule>() == 8);
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_data_display() {
        let data = RuleData {
            category_mask: CategoryMask::new(0x1).unwrap(),
            priority: Priority::new(100).unwrap(),
            userdata: 42.try_into().unwrap(),
        };
        let s = format!("{data}");
        assert!(s.contains("category_mask: 0x00000001"));
        assert!(s.contains("priority: 100"));
        assert!(s.contains("userdata: 42"));
    }

    // Tests below cross between union members (write narrow, read u64)
    // and therefore observe the host's endianness.  Gated to LE because:
    //
    //   - On LE the narrow value lands in the low bytes of the union,
    //     so reading u64 yields the same numeric value zero-extended.
    //   - On BE the narrow value lands in the high bytes, so the
    //     numeric u64 read would be `value << (64 - 8*size)`.
    //
    // The wrapper supports BE for the actual data flow (input data is
    // in host byte order; DPDK reads through the matching union member
    // on the same host).  Only the test's cross-width readback is
    // endian-dependent.
    #[cfg(target_endian = "little")]
    #[test]
    fn acl_field_from_u8_zeroes_upper_bytes() {
        let field = AclField::from_u8(0xAB, 0xCD);
        assert_eq!(field.value_u64(), 0xAB);
        assert_eq!(field.mask_range_u64(), 0xCD);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn acl_field_from_u16_zeroes_upper_bytes() {
        let field = AclField::from_u16(0xABCD, 0x1234);
        assert_eq!(field.value_u64(), 0xABCD);
        assert_eq!(field.mask_range_u64(), 0x1234);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn acl_field_from_u32_zeroes_upper_bytes() {
        let field = AclField::from_u32(0xDEAD_BEEF, 0xFFFF_FF00);
        assert_eq!(field.value_u64(), 0xDEAD_BEEF);
        assert_eq!(field.mask_range_u64(), 0xFFFF_FF00);
    }

    #[test]
    fn acl_field_from_u64_raw_full_range() {
        let field = AclField::from_u64_raw(0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);
        assert_eq!(field.value_u64(), 0x0123_4567_89AB_CDEF);
        assert_eq!(field.mask_range_u64(), 0xFEDC_BA98_7654_3210);
    }

    #[test]
    fn acl_field_zero_is_all_zero() {
        let w = AclField::zero();
        assert_eq!(w.value_u64(), 0);
        assert_eq!(w.mask_range_u64(), 0);
    }

    #[test]
    fn acl_field_equality() {
        let a = AclField::from_u32(10, 20);
        let b = AclField::from_u32(10, 20);
        let c = AclField::from_u32(10, 21);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn acl_field_debug_is_hex() {
        // The hex digits depend on which bytes of the u64 the narrow
        // u32 write lands in -- LE-specific.  See the note on
        // `acl_field_from_u8_zeroes_upper_bytes`.
        let field = AclField::from_u32(0xFF, 0xAA);
        let dbg = format!("{field:?}");
        assert!(dbg.contains("0x00000000000000ff"), "got: {dbg}");
        assert!(dbg.contains("0x00000000000000aa"), "got: {dbg}");
    }

    #[test]
    fn rule_display() {
        let rule: Rule<2> = Rule::new(
            RuleData {
                category_mask: CategoryMask::new(1).unwrap(),
                priority: Priority::new(10).unwrap(),
                userdata: 1.try_into().unwrap(),
            },
            [AclField::from_u32(0, 0), AclField::from_u16(80, 80)],
        );
        let s = format!("{rule}");
        assert!(s.starts_with("Rule<2>"));
    }

    #[test]
    fn rule_equality() {
        let r1: Rule<1> = Rule::new(
            RuleData {
                category_mask: CategoryMask::new(1).unwrap(),
                priority: Priority::new(1).unwrap(),
                userdata: 1.try_into().unwrap(),
            },
            [AclField::from_u32(100, 200)],
        );
        let r2 = r1;
        assert_eq!(r1, r2);
    }

    #[test]
    fn rule_size_constant_matches_size_of() {
        assert_eq!(Rule::<1>::RULE_SIZE as usize, mem::size_of::<Rule<1>>());
        assert_eq!(Rule::<5>::RULE_SIZE as usize, mem::size_of::<Rule<5>>());
        assert_eq!(Rule::<10>::RULE_SIZE as usize, mem::size_of::<Rule<10>>());
    }

    #[test]
    fn priority_constants_match_dpdk() {
        assert_eq!(priority::MIN, 1);
        assert_eq!(
            priority::MAX,
            dpdk_sys::_bindgen_ty_4::RTE_ACL_MAX_PRIORITY as i32
        );
    }

    /// Property: `Priority::new` accepts exactly the closed interval
    /// `[priority::MIN, priority::MAX]` and rejects everything else.
    #[test]
    fn priority_new_validates_range() {
        bolero::check!().with_type::<i32>().for_each(|value: &i32| {
            let result = Priority::new(*value);
            if (priority::MIN..=priority::MAX).contains(value) {
                let p = result.unwrap_or_else(|_| {
                    panic!("Priority::new({value}) should accept in-range value")
                });
                assert_eq!(p.get(), *value);
            } else {
                assert!(
                    result.is_err(),
                    "Priority::new({value}) should reject out-of-range value"
                );
            }
        });
    }
}
