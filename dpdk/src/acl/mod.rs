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
//! - [`classify`]: the [`ClassifyAlgorithm`][classify::ClassifyAlgorithm]
//!   enum that selects DPDK's classify backend (Default / Scalar / NEON
//!   / SSE / AVX2 / AVX512X16 / AVX512X32 / Altivec).

pub mod classify;
pub mod error;
pub mod field;
