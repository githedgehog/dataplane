// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Raw DPDK bindings for Rust.

// We don't need to throw down over differences in name style between C and Rust in the bindings.
#![allow(
    clippy::all,
    clippy::pedantic,
    deprecated,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    // Rust v1.93 reports unnecessary transmutes in bindgen output, when processing the bitfields
    // for struct _IO_FILE's _flags2, from /usr/include/bits/types/struct_FILE.h.
    // Remove once bindgen is fixed.
    unnecessary_transmutes,
)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

/// Stable accessors for ACL enum values that DPDK declares in anonymous enums.
///
/// Bindgen names each anonymous enum after its discovery order
/// (`_bindgen_ty_N`).  That counter is sensitive to which preprocessor
/// branches the active target takes through `<rte_config.h>` and the
/// system headers, so the suffix differs between targets -- e.g. the
/// ACL priority enum lands at `_bindgen_ty_4` on x86_64-gnu but a
/// different slot on aarch64-musl, which broke the `+cross/full`
/// build before we routed everything through this module.
///
/// The values themselves are pinned by DPDK's ABI contract in
/// `lib/acl/rte_acl.h`.  They have not changed since rte_acl was
/// introduced.
pub mod acl_const {
    /// Smallest priority `rte_acl_add_rules` will accept (`RTE_ACL_MIN_PRIORITY`).
    pub const RTE_ACL_MIN_PRIORITY: i32 = 1;
    /// Largest priority `rte_acl_add_rules` will accept (`RTE_ACL_MAX_PRIORITY`,
    /// equal to `(1 << RTE_ACL_TYPE_SHIFT) - 1`).
    pub const RTE_ACL_MAX_PRIORITY: i32 = (1 << 29) - 1;

    /// `RTE_ACL_FIELD_TYPE_MASK`: match the masked bits of the field exactly.
    pub const RTE_ACL_FIELD_TYPE_MASK: u32 = 0;
    /// `RTE_ACL_FIELD_TYPE_RANGE`: match a closed numeric range.
    pub const RTE_ACL_FIELD_TYPE_RANGE: u32 = 1;
    /// `RTE_ACL_FIELD_TYPE_BITMASK`: match the union of the set bits.
    pub const RTE_ACL_FIELD_TYPE_BITMASK: u32 = 2;
}
