// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL field definition types.
//!
//! These types provide safe, strongly-typed wrappers around DPDK's [`rte_acl_field_def`] and the
//! associated `RTE_ACL_FIELD_TYPE_*` constants.
//!
//! Using Rust enums for [`FieldType`] and [`FieldSize`] makes it impossible to construct an
//! invalid field definition at the type level -- there is no representation for, say, a 3-byte
//! field or an undefined comparison type.
//!
//! [`rte_acl_field_def`]: dpdk_sys::rte_acl_field_def

use core::fmt::{Display, Formatter};

/// The comparison semantics for an ACL field.
///
/// Each field in an ACL rule is compared against input data using one of three
/// strategies.  The choice of strategy also determines how the `mask_range`
/// value in [`AclField`][super::rule::AclField] is interpreted (see the
/// constructor docs on [`AclField`][super::rule::AclField] for the
/// type-vs-`mask_range` mapping).
///
/// Maps to the `RTE_ACL_FIELD_TYPE_*` constants.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// Prefix-length match.
    ///
    /// `mask_range` holds the **prefix length** -- the number of
    /// most-significant bits to compare.  DPDK derives the bitmask internally
    /// from the prefix length and the field size.
    ///
    /// Examples (for a 4-byte field):
    /// - `32` -- exact match on all 32 bits.
    /// - `24` -- IPv4 `/24` (compare the top 24 bits only).
    /// - `0`  -- wildcard (matches anything).
    ///
    /// Corresponds to [`RTE_ACL_FIELD_TYPE_MASK`][dpdk_sys::_bindgen_ty_3::RTE_ACL_FIELD_TYPE_MASK].
    Mask = 0,

    /// Range match.
    ///
    /// The comparison is: `low <= input <= high`.  `value` is the low bound
    /// and `mask_range` is the high bound.  Typically used for port ranges.
    ///
    /// Corresponds to [`RTE_ACL_FIELD_TYPE_RANGE`][dpdk_sys::_bindgen_ty_3::RTE_ACL_FIELD_TYPE_RANGE].
    Range = 1,

    /// Bitmask match.
    ///
    /// The comparison is: `(input & mask_range) == value`.  `mask_range`
    /// holds the bitmask applied to the input before comparison with
    /// `value`.  Typically used for flag-style fields (TCP flags, protocol
    /// numbers with don't-care bits, etc.).
    ///
    /// Example: to match a TCP protocol number (`6`) exactly, use `value = 6`
    /// and `mask_range = 0xFF`.
    ///
    /// Corresponds to [`RTE_ACL_FIELD_TYPE_BITMASK`][dpdk_sys::_bindgen_ty_3::RTE_ACL_FIELD_TYPE_BITMASK].
    Bitmask = 2,
}

impl Display for FieldType {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            FieldType::Mask => write!(f, "Mask"),
            FieldType::Range => write!(f, "Range"),
            FieldType::Bitmask => write!(f, "Bitmask"),
        }
    }
}

/// Valid byte widths for an ACL field.
///
/// DPDK restricts ACL field sizes to 1, 2, or 4 bytes per
/// [`FieldDef`] within a single `input_index` group.  The C library also
/// supports 8-byte logical fields by spanning two adjacent 4-byte groups,
/// but the wrapper does not model that split-load behaviour, so
/// [`AclBuildConfig::new`][super::config::AclBuildConfig::new] rejects
/// any layout that would have required it.  `FieldSize` therefore omits
/// `Eight` to keep "constructible width" and "build-valid width" in sync.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FieldSize {
    /// 1 byte (e.g. IP protocol number).
    One = 1,
    /// 2 bytes (e.g. TCP/UDP port).
    Two = 2,
    /// 4 bytes (e.g. IPv4 address).
    Four = 4,
}

impl Display for FieldSize {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", *self as u8)
    }
}

/// Definition of a single field within an ACL rule.
///
/// This is the safe Rust equivalent of [`rte_acl_field_def`][dpdk_sys::rte_acl_field_def].
/// A collection of field definitions describes the overall layout of rules and input data for an
/// ACL context.
///
/// # Input grouping
///
/// For performance reasons the inner loop of the DPDK ACL search function is unrolled to process
/// four input bytes at a time.  Fields must therefore be grouped into sets of 4 consecutive bytes
/// via the [`input_index`][FieldDef::input_index] value.  The first input byte is processed as
/// part of setup, so subsequent groups must be aligned to 4-byte boundaries.
///
/// See the [DPDK ACL documentation](https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html)
/// for full details on input grouping rules.
///
/// # Why the fields are private
///
/// Fields are private so that callers cannot construct a `FieldDef` whose
/// `field_index` would be out of range for the `N` used in the eventual
/// [`AclBuildConfig<N>`][super::config::AclBuildConfig].  Construction goes
/// through [`FieldDef::new`]; the array-level invariants (`field_index < N`,
/// uniqueness, first-field-is-one-byte) are validated by
/// [`AclBuildConfig::new`][super::config::AclBuildConfig::new] when the
/// definitions are assembled.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct FieldDef {
    /// The comparison type for this field.
    field_type: FieldType,
    /// Width of the field in bytes.
    size: FieldSize,
    /// Zero-based index of this field within a rule (must be unique per rule layout and < N).
    field_index: u8,
    /// Input grouping index.
    ///
    /// Fields are processed in groups of 4 consecutive bytes.  All fields that share the same
    /// `input_index` must fit within 4 bytes starting at the offset of the first field in the
    /// group.
    input_index: u8,
    /// Byte offset of this field within the input data buffer.
    offset: u32,
}

impl FieldDef {
    /// Construct a field definition.
    ///
    /// The cross-field invariants (`field_index < N`, uniqueness within the
    /// array, the first field being one byte wide) are validated by
    /// [`AclBuildConfig::new`][super::config::AclBuildConfig::new] when the
    /// definitions are assembled into an array.  The DPDK 4-byte
    /// `input_index` grouping rule is checked by DPDK itself at
    /// `rte_acl_build` time.
    #[must_use]
    pub const fn new(
        field_type: FieldType,
        size: FieldSize,
        field_index: u8,
        input_index: u8,
        offset: u32,
    ) -> Self {
        Self {
            field_type,
            size,
            field_index,
            input_index,
            offset,
        }
    }

    /// The comparison strategy for this field.
    #[must_use]
    pub const fn field_type(&self) -> FieldType {
        self.field_type
    }

    /// The field width in bytes.
    #[must_use]
    pub const fn size(&self) -> FieldSize {
        self.size
    }

    /// Zero-based index of this field within the rule layout.
    #[must_use]
    pub const fn field_index(&self) -> u8 {
        self.field_index
    }

    /// The input grouping index.
    #[must_use]
    pub const fn input_index(&self) -> u8 {
        self.input_index
    }

    /// Byte offset of this field within the input data buffer.
    #[must_use]
    pub const fn offset(&self) -> u32 {
        self.offset
    }
}

impl Display for FieldDef {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FieldDef {{ type: {}, size: {}, field_index: {}, input_index: {}, offset: {} }}",
            self.field_type, self.size, self.field_index, self.input_index, self.offset,
        )
    }
}

impl From<FieldDef> for dpdk_sys::rte_acl_field_def {
    fn from(def: FieldDef) -> Self {
        (&def).into()
    }
}

impl From<&FieldDef> for dpdk_sys::rte_acl_field_def {
    fn from(def: &FieldDef) -> Self {
        dpdk_sys::rte_acl_field_def {
            type_: def.field_type as u8,
            size: def.size as u8,
            field_index: def.field_index,
            input_index: def.input_index,
            offset: def.offset,
        }
    }
}

// Layout asserts for `rte_acl_field_def`.  The `From<&FieldDef>` impl
// above produces an `rte_acl_field_def` value by struct-literal
// composition (not by transmute), so a size/align mismatch with the
// bindgen struct cannot cause UB on its own.  These asserts are a
// canary: if DPDK ever changes the layout (added padding, reordered
// fields, widened a type), the `[FieldDef; N] -> [rte_acl_field_def;
// N]` conversion that `AclBuildConfig::to_raw` builds when populating
// `rte_acl_config::defs` would silently produce wrong results.
// Symmetric with the matching asserts on `RuleData` (rule.rs) and
// `AclField` (rule.rs).
const _: () = {
    assert!(
        core::mem::size_of::<dpdk_sys::rte_acl_field_def>() == 8,
        "rte_acl_field_def size changed; recheck FieldDef -> rte_acl_field_def conversion"
    );
    assert!(
        core::mem::align_of::<dpdk_sys::rte_acl_field_def>() == 4,
        "rte_acl_field_def alignment changed; recheck FieldDef -> rte_acl_field_def conversion"
    );
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_type_discriminants_match_dpdk() {
        assert_eq!(
            FieldType::Mask as u8,
            dpdk_sys::_bindgen_ty_3::RTE_ACL_FIELD_TYPE_MASK as u8
        );
        assert_eq!(
            FieldType::Range as u8,
            dpdk_sys::_bindgen_ty_3::RTE_ACL_FIELD_TYPE_RANGE as u8
        );
        assert_eq!(
            FieldType::Bitmask as u8,
            dpdk_sys::_bindgen_ty_3::RTE_ACL_FIELD_TYPE_BITMASK as u8
        );
    }

    #[test]
    fn field_def_converts_to_raw() {
        let def = FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 2, 12);
        let raw: dpdk_sys::rte_acl_field_def = def.into();
        assert_eq!(raw.type_, 0);
        assert_eq!(raw.size, 4);
        assert_eq!(raw.field_index, 1);
        assert_eq!(raw.input_index, 2);
        assert_eq!(raw.offset, 12);
    }

    #[test]
    fn field_def_ref_converts_to_raw() {
        let def = FieldDef::new(FieldType::Range, FieldSize::Two, 3, 4, 20);
        let raw: dpdk_sys::rte_acl_field_def = (&def).into();
        assert_eq!(raw.type_, 1);
        assert_eq!(raw.size, 2);
        assert_eq!(raw.field_index, 3);
        assert_eq!(raw.input_index, 4);
        assert_eq!(raw.offset, 20);
    }
}
