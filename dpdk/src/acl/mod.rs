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
//! - [`config`]: validated [`AclBuildConfig<N>`][config::AclBuildConfig] and
//!   [`AclCreateParams<N>`][config::AclCreateParams].  Includes the
//!   compile-time `N > 0` / `N <= MAX_FIELDS` guards and the
//!   input-index grouping validator.
//! - [`rule`]: validated [`Rule<N>`][rule::Rule],
//!   [`AclField`][rule::AclField], [`Priority`][rule::Priority], and
//!   [`CategoryMask`][rule::CategoryMask].  `Rule::validate` reads each
//!   field through the union member that matches the declared
//!   [`FieldSize`][field::FieldSize], so the validator is endian-safe.
//! - [`context`]: [`AclContext<N, State>`][context::AclContext] -- the
//!   typestate-driven safe wrapper around `rte_acl_create` /
//!   `rte_acl_add_rules` / `rte_acl_build` / `rte_acl_classify`.

pub mod classify;
pub mod config;
pub mod context;
pub mod error;
pub mod field;
pub mod rule;
