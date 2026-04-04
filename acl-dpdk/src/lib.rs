// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! DPDK ACL backend for the `dataplane-acl` crate.
//!
//! Compiles [`AclTable`](acl::AclTable) rules into DPDK ACL contexts
//! by grouping rules by [`FieldSignature`](acl::FieldSignature) and
//! mapping each signature to a DPDK `FieldDef` array.

pub mod compiler;
pub mod field_map;
pub mod rule_translate;
