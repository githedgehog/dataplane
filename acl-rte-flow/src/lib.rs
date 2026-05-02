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

//! `rte_flow` backend for the `dataplane-acl` crate.
//!
//! Compiles [`AclRule`](acl::AclRule)s into `rte_flow` rule components:
//! [`FlowAttr`], [`FlowMatch`] patterns, and [`FlowAction`] sequences.
//!
//! # Limitations (v1)
//!
//! - **Exact matches only.**  Prefix matches and port ranges are not yet
//!   supported — they require ternary decomposition or backend-specific
//!   range matchers.  Rules with non-exact fields will fail translation.
//! - **Drop and Forward fates only.**  Forward lowers to `PassThrough`.
//! - **No rule installation.**  This crate produces the rte_flow structs
//!   but does not call `rte_flow_create`.  Installation requires a DPDK
//!   EAL context and a port handle.

pub mod compile;
