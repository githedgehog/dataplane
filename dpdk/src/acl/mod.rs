// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Safe Rust abstraction over DPDK's ACL (Access Control List) library.
//!
//! This module is built up incrementally across several commits.  Sub-modules
//! present so far:
//!
//! - [`field`]: field-layout primitives ([`FieldDef`][field::FieldDef],
//!   [`FieldType`][field::FieldType], [`FieldSize`][field::FieldSize]).
//! - [`error`]: dedicated error enums for the fallible ACL operations
//!   (`create`, `add_rules`, `build`, `classify`, `set_algorithm`).

pub mod error;
pub mod field;
