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
//! - [`reference`](mod@reference): linear-scan software classifier;
//!   differential oracle and a mutable cascade front.  Always built.
//!
//! The production `rte_acl` backend lands behind a follow-up `dpdk`
//! feature gate.
//!
//! [`lookup::Lookup`]: lookup::Lookup
//! [`match_action::MatchKey`]: match_action::MatchKey

pub mod reference;
