// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)] // shape settling; doc once stable

//! Match-action classifier backends for [`match_action::MatchKey`]
//! tables, behind the [`lookup::Lookup`] interface.
//!
//! - [`dpdk`] (`dpdk` feature): production `rte_acl` backend; in this
//!   PR the static type machinery (layout planner + rule lowering).
//!   The runtime install / classify path lands next.
//! - [`reference`](mod@reference): linear-scan software classifier;
//!   differential oracle and a mutable cascade front.  Always built.
//!
//! [`lookup::Lookup`]: lookup::Lookup
//! [`match_action::MatchKey`]: match_action::MatchKey

#[cfg(feature = "dpdk")]
pub mod dpdk;
pub mod reference;
