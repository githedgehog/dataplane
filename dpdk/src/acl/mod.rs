// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Safe Rust abstraction over DPDK's ACL (Access Control List) library.
//!
//! This module is built up incrementally across several commits.  At this
//! stage the only public sub-module is [`field`], which carries the
//! field-layout primitives ([`FieldDef`][field::FieldDef],
//! [`FieldType`][field::FieldType], [`FieldSize`][field::FieldSize]) that the
//! rest of the wrapper -- errors, rules, build configuration, context,
//! classify -- will depend on.

pub mod field;
