// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL rule types.
//!
//! These types provide safe, `#[repr(C)]` wrappers around the DPDK ACL rule structures.
//! The key types are:
//!
//! - [`RuleData`] — rule metadata (category mask, priority, user data).
//! - [`AclField`] — a single field value with its mask or range bound.
//! - [`Rule`]`<N>` — a complete rule comprising [`RuleData`] followed by `N` [`AclField`] entries.
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

// ---------------------------------------------------------------------------
// Priority constants
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
    /// Each bit corresponds to one category (up to
    /// [`RTE_ACL_MAX_CATEGORIES`][dpdk_sys::RTE_ACL_MAX_CATEGORIES]).
    /// Set bit `i` to include this rule in category `i`.
    pub category_mask: u32,

    /// Rule priority.  Higher numeric value means higher priority.
    ///
    /// When multiple rules match a given input for the same category, the rule with the highest
    /// priority wins.  Must be in the range
    /// \[[`priority::MIN`], [`priority::MAX`]\].
    pub priority: i32,

    /// Opaque value returned to the caller on match.
    ///
    /// **Must be non-zero.**  A classification result of `0` indicates that no rule matched.
    pub userdata: std::num::NonZero<u32>,
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
            "RuleData {{ category_mask: {:#010x}, priority: {}, userdata: {} }}",
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
/// The interpretation of [`value`][AclField::value] and [`mask_range`][AclField::mask_range]
/// depends on the [`FieldType`][super::field::FieldType] specified in the corresponding
/// [`FieldDef`][super::field::FieldDef]:
///
/// | [`FieldType`][super::field::FieldType] | `value`    | `mask_range`       |
/// |----------------------------------------|------------|--------------------|
/// | [`Mask`][super::field::FieldType::Mask]       | match value  | bitmask            |
/// | [`Range`][super::field::FieldType::Range]     | range low    | range high         |
/// | [`Bitmask`][super::field::FieldType::Bitmask] | match value  | bitmask            |
///
/// Use the [`from_u8`][AclField::from_u8], [`from_u16`][AclField::from_u16],
/// [`from_u32`][AclField::from_u32], or [`from_u64`][AclField::from_u64] constructors to set
/// the value and mask/range for the appropriate field width.
// TODO: if this is identical to the c repr why not just use that?
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AclField {
    /// The match value (or range lower bound).
    pub value: dpdk_sys::rte_acl_field_types,
    /// The mask, bitmask, or range upper bound — interpretation depends on the field type.
    pub mask_range: dpdk_sys::rte_acl_field_types,
}

// Compile-time layout assertions against the raw DPDK type.
const _: () = {
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
        Self {
            value: dpdk_sys::rte_acl_field_types::default(),
            mask_range: dpdk_sys::rte_acl_field_types::default(),
        }
    }
}

impl fmt::Debug for AclField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // SAFETY: reading the u64 member of the union is always valid — all union members occupy
        // the same bytes at offset 0 and u64 is the widest member, so no bytes are uninitialised.
        let (value, mask) = unsafe { (self.value.u64_, self.mask_range.u64_) };
        f.debug_struct("AclField")
            .field("value", &format_args!("{value:#018x}"))
            .field("mask_range", &format_args!("{mask:#018x}"))
            .finish()
    }
}

impl fmt::Display for AclField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (value, mask) = unsafe { (self.value.u64_, self.mask_range.u64_) };
        write!(f, "{value:#018x}/{mask:#018x}")
    }
}

impl PartialEq for AclField {
    fn eq(&self, other: &Self) -> bool {
        // SAFETY: same rationale as Debug — u64 is the widest union member.
        unsafe { self.value.u64_ == other.value.u64_ && self.mask_range.u64_ == other.mask_range.u64_ }
    }
}

impl Eq for AclField {} // wat? Why not derive

// TODO: these all lack validation on the range lengths
impl AclField {
    /// Create a field from `u8` value and mask/range.
    ///
    /// Use this for fields declared with [`FieldSize::One`][super::field::FieldSize::One].
    ///
    /// The upper bytes of the underlying union are zeroed.
    #[must_use]
    pub fn from_u8(value: u8, mask_range: u8) -> Self {
        // Zero-initialise first so that the upper bytes are deterministic.
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

    /// Create a field from `u64` value and mask/range.
    ///
    /// Use this for fields declared with [`FieldSize::Eight`][super::field::FieldSize::Eight].
    #[must_use]
    pub fn from_u64(value: u64, mask_range: u64) -> Self {
        Self {
            value: dpdk_sys::rte_acl_field_types { u64_: value },
            mask_range: dpdk_sys::rte_acl_field_types { u64_: mask_range },
        }
    }

    /// Create a wildcard field that matches any input.
    ///
    /// Equivalent to [`AclField::default()`] — value `0` with mask `0` — which matches
    /// everything when the field type is [`Mask`][super::field::FieldType::Mask].
    #[must_use]
    pub fn wildcard() -> Self {
        Self::default()
    }

    // TODO: This is _quite_ a safety requirement.  I feel like we should have had a macro somewhere which made a more
    // complex and type safe abstraction.
    /// Read the value as `u8`.
    ///
    /// # Safety
    ///
    /// The caller must ensure this field was constructed with [`from_u8`][AclField::from_u8] or
    /// that reading the `u8` member of the union is meaningful in context.
    #[must_use]
    pub unsafe fn value_u8(&self) -> u8 {
        unsafe { self.value.u8_ }
    }

    /// Read the mask/range as `u8`.
    ///
    /// # Safety
    ///
    /// Same as [`value_u8`][AclField::value_u8].
    #[must_use]
    pub unsafe fn mask_range_u8(&self) -> u8 {
        unsafe { self.mask_range.u8_ }
    }

    /// Read the value as `u16`.
    ///
    /// # Safety
    ///
    /// The caller must ensure this field was constructed with [`from_u16`][AclField::from_u16] or
    /// that reading the `u16` member of the union is meaningful in context.
    #[must_use]
    pub unsafe fn value_u16(&self) -> u16 {
        unsafe { self.value.u16_ }
    }

    /// Read the mask/range as `u16`.
    ///
    /// # Safety
    ///
    /// Same as [`value_u16`][AclField::value_u16].
    #[must_use]
    pub unsafe fn mask_range_u16(&self) -> u16 {
        unsafe { self.mask_range.u16_ }
    }

    /// Read the value as `u32`.
    ///
    /// # Safety
    ///
    /// The caller must ensure this field was constructed with [`from_u32`][AclField::from_u32] or
    /// that reading the `u32` member of the union is meaningful in context.
    #[must_use]
    pub unsafe fn value_u32(&self) -> u32 {
        unsafe { self.value.u32_ }
    }

    /// Read the mask/range as `u32`.
    ///
    /// # Safety
    ///
    /// Same as [`value_u32`][AclField::value_u32].
    #[must_use]
    pub unsafe fn mask_range_u32(&self) -> u32 {
        unsafe { self.mask_range.u32_ }
    }

    /// Read the value as `u64`.
    ///
    /// This is always safe because `u64` is the widest member of the underlying union and
    /// therefore covers all bytes.
    #[must_use]
    pub fn value_u64(&self) -> u64 {
        // SAFETY: u64 is the widest member — reading it is always valid.
        unsafe { self.value.u64_ }
    }

    /// Read the mask/range as `u64`.
    ///
    /// This is always safe because `u64` is the widest member of the underlying union.
    #[must_use]
    pub fn mask_range_u64(&self) -> u64 {
        // SAFETY: u64 is the widest member — reading it is always valid.
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
#[derive(Debug, Copy, Clone)]
pub struct Rule<const N: usize> {
    /// Rule metadata: category mask, priority, and user data.
    pub data: RuleData,
    /// Field values (one per field definition in the ACL context).
    pub fields: [AclField; N],
}

impl<const N: usize> Rule<N> {
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
    /// * `data` — the rule metadata (category mask, priority, and user data).
    /// * `fields` — the field values for this rule; one entry per field definition.
    #[must_use]
    pub const fn new(data: RuleData, fields: [AclField; N]) -> Self {
        Self { data, fields }
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

impl<const N: usize> PartialEq for Rule<N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.fields == other.fields
    }
}

impl<const N: usize> Eq for Rule<N> {}

// ---------------------------------------------------------------------------
// Layout verification
// ---------------------------------------------------------------------------

/// Compile-time assertion that [`Rule`]`<N>` has the same size as `rte_acl_rule_data` (with
/// padding for field alignment) plus `N * size_of::<rte_acl_field>()`.
///
/// The field array in [`rte_acl_rule`][dpdk_sys::rte_acl_rule] starts at offset 16 (12 bytes of
/// `rte_acl_rule_data` + 4 bytes of padding to reach 8-byte alignment of `rte_acl_field`).
/// Therefore `size_of::<Rule<N>>() == 16 + 16 * N`.
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

    // Verify our Rule<N> layout for a selection of field counts.
    assert!(mem::size_of::<Rule<0>>() == 16);
    assert!(mem::size_of::<Rule<1>>() == 16 + 16);
    assert!(mem::size_of::<Rule<2>>() == 16 + 16 * 2);
    assert!(mem::size_of::<Rule<5>>() == 16 + 16 * 5);
    assert!(mem::size_of::<Rule<10>>() == 16 + 16 * 10);

    assert!(mem::align_of::<Rule<1>>() == 8);
    assert!(mem::align_of::<Rule<5>>() == 8);
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
            category_mask: 0x1,
            priority: 100,
            userdata: 42.try_into().unwrap(),
        };
        let s = alloc::format!("{data}");
        assert!(s.contains("category_mask: 0x00000001"));
        assert!(s.contains("priority: 100"));
        assert!(s.contains("userdata: 42"));
    }

    #[test]
    fn acl_field_from_u8_zeroes_upper_bytes() {
        let field = AclField::from_u8(0xAB, 0xCD);
        assert_eq!(field.value_u64(), 0xAB);
        assert_eq!(field.mask_range_u64(), 0xCD);
    }

    #[test]
    fn acl_field_from_u16_zeroes_upper_bytes() {
        let field = AclField::from_u16(0xABCD, 0x1234);
        assert_eq!(field.value_u64(), 0xABCD);
        assert_eq!(field.mask_range_u64(), 0x1234);
    }

    #[test]
    fn acl_field_from_u32_zeroes_upper_bytes() {
        let field = AclField::from_u32(0xDEAD_BEEF, 0xFFFF_FF00);
        assert_eq!(field.value_u64(), 0xDEAD_BEEF);
        assert_eq!(field.mask_range_u64(), 0xFFFF_FF00);
    }

    #[test]
    fn acl_field_from_u64_full_range() {
        let field = AclField::from_u64(0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);
        assert_eq!(field.value_u64(), 0x0123_4567_89AB_CDEF);
        assert_eq!(field.mask_range_u64(), 0xFEDC_BA98_7654_3210);
    }

    #[test]
    fn acl_field_wildcard_is_zero() {
        let w = AclField::wildcard();
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

    #[test]
    fn acl_field_debug_is_hex() {
        let field = AclField::from_u32(0xFF, 0xAA);
        let dbg = alloc::format!("{field:?}");
        assert!(dbg.contains("0x00000000000000ff"), "got: {dbg}");
        assert!(dbg.contains("0x00000000000000aa"), "got: {dbg}");
    }

    #[test]
    fn rule_display() {
        let rule: Rule<2> = Rule::new(
            RuleData {
                category_mask: 1,
                priority: 10,
                userdata: 1.try_into().unwrap(),
            },
            [AclField::from_u32(0, 0), AclField::from_u16(80, 80)],
        );
        let s = alloc::format!("{rule}");
        assert!(s.starts_with("Rule<2>"));
    }

    #[test]
    fn rule_equality() {
        let r1: Rule<1> = Rule::new(
            RuleData {
                category_mask: 1,
                priority: 1,
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
}
