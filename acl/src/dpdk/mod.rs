// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK `rte_acl` backend for [`match_action::MatchKey`] tables.
//!
//! This PR lands the static type machinery only:
//!
//! - [`layout`] -- plan the `rte_acl` field layout from `FieldSpec`s
//!   (group bucketing, padding, packed stride).
//! - [`rule`] -- [`Dpdk`](rule::Dpdk) marker, [`AclWord`](rule::AclWord)
//!   trait, `IntoBackendField` impls, rule-field splicing.
//!
//! The runtime backend (`install`, `lookup`) and the
//! `dpdk_table_alias!` macro land in a follow-up PR.
//!
//! [`match_action::MatchKey`]: match_action::MatchKey

// `RuleSpec` and `DpdkLayout::stride` are wired up by `install` /
// `lookup` in the next PR; until then they read as dead code.
#![allow(dead_code)]

pub mod layout;
pub mod rule;
