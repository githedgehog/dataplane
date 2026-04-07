// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL field definition types.
//!
//! These types provide safe, strongly-typed wrappers around DPDK's [`rte_acl_field_def`] and the
//! associated `RTE_ACL_FIELD_TYPE_*` constants.
//!
//! Using Rust enums for [`FieldType`] and [`FieldSize`] makes it impossible to construct an
//! invalid field definition at the type level — there is no representation for, say, a 3-byte
//! field or an undefined comparison type.
//!
//! [`rte_acl_field_def`]: dpdk_sys::rte_acl_field_def

use core::fmt::{Display, Formatter};

/// The comparison semantics for an ACL field.
///
/// Each field in an ACL rule is compared against input data using one of three strategies.
/// The choice of strategy also determines how the
/// [`mask_range`][super::rule::AclField::mask_range] value in [`AclField`][super::rule::AclField]
/// is interpreted.
///
/// Maps to the `RTE_ACL_FIELD_TYPE_*` constants.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FieldType {
    /// Exact match with bitmask.
    ///
    /// The comparison is: `(input & mask) == (value & mask)`.
    ///
    /// The [`mask_range`][super::rule::AclField::mask_range] field holds the bitmask.
    /// For example, an IPv4 prefix `/24` would use mask `0xFFFFFF00`.
    ///
    /// Corresponds to [`RTE_ACL_FIELD_TYPE_MASK`][dpdk_sys::_bindgen_ty_3::RTE_ACL_FIELD_TYPE_MASK].
    Mask = 0,

    /// Range match.
    ///
    /// The comparison is: `low <= input <= high`.
    ///
    /// The [`value`][super::rule::AclField] holds the low bound and
    /// [`mask_range`][super::rule::AclField::mask_range] holds the high bound.
    /// This is typically used for port ranges.
    ///
    /// Corresponds to [`RTE_ACL_FIELD_TYPE_RANGE`][dpdk_sys::_bindgen_ty_3::RTE_ACL_FIELD_TYPE_RANGE].
    Range = 1,

    /// Bitwise AND match.
    ///
    /// The comparison is: `(input & value) != 0`.
    ///
    /// This is typically used for protocol fields where you want to match any of several flags.
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
/// DPDK restricts ACL field sizes to exactly 1, 2, 4, or 8 bytes.
/// Representing this as an enum makes invalid widths unrepresentable.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FieldSize {
    /// 1 byte (e.g. IP protocol number).
    One = 1,
    /// 2 bytes (e.g. TCP/UDP port).
    Two = 2,
    /// 4 bytes (e.g. IPv4 address).
    Four = 4,
    /// 8 bytes (e.g. a combined field or IPv6 half).
    Eight = 8,
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
/// TODO: is this meaningfully different from the more weakly typed version?  Should we just use a thin wrapper over that?  Actually, maybe derive a builder on this type?
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct FieldDef {
    /// The comparison type for this field.
    pub field_type: FieldType,
    /// Width of the field in bytes.
    pub size: FieldSize,
    /// Zero-based index of this field within a rule (must be unique per rule layout and < N).
    pub field_index: u8,
    /// Input grouping index.
    ///
    /// Fields are processed in groups of 4 consecutive bytes.  All fields that share the same
    /// `input_index` must fit within 4 bytes starting at the offset of the first field in the
    /// group.
    pub input_index: u8,
    /// Byte offset of this field within the input data buffer.
    pub offset: u32,
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
        let def = FieldDef {
            field_type: FieldType::Mask,
            size: FieldSize::Four,
            field_index: 1,
            input_index: 2,
            offset: 12,
        };
        let raw: dpdk_sys::rte_acl_field_def = def.into();
        assert_eq!(raw.type_, 0);
        assert_eq!(raw.size, 4);
        assert_eq!(raw.field_index, 1);
        assert_eq!(raw.input_index, 2);
        assert_eq!(raw.offset, 12);
    }

    #[test]
    fn field_def_ref_converts_to_raw() {
        let def = FieldDef {
            field_type: FieldType::Range,
            size: FieldSize::Two,
            field_index: 3,
            input_index: 4,
            offset: 20,
        };
        let raw: dpdk_sys::rte_acl_field_def = (&def).into();
        assert_eq!(raw.type_, 1);
        assert_eq!(raw.size, 2);
        assert_eq!(raw.field_index, 3);
        assert_eq!(raw.input_index, 4);
        assert_eq!(raw.offset, 20);
    }
}
