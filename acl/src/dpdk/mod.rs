// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK `rte_acl` backend for [`match_action::MatchKey`] tables.
//!
//! Translates a user `MatchKey` struct into a built
//! [`dpdk::acl::AclContext`] wrapped in [`self::lookup::DpdkAclLookup`]
//! (a `lookup::Lookup` backend; the trait link is unlinked here because
//! this module has a child `lookup` that shadows the extern crate in
//! doc-link resolution).  Submodules:
//!
//! - [`layout`] -- plan the `rte_acl` field layout from `FieldSpec`s
//!   (group bucketing, padding, packed stride).
//! - [`rule`] -- [`Dpdk`](rule::Dpdk) marker, [`AclWord`](rule::AclWord)
//!   trait, `IntoBackendField` impls, rule-field splicing.
//! - [`install`] -- build an `AclContext` from a `MatchKey` + rules.
//! - [`mod@self::lookup`] -- the backend itself + the batch
//!   `rte_acl_classify` path.
//!
//! [`match_action::MatchKey`]: match_action::MatchKey
//! [`dpdk::acl::AclContext`]: dpdk::acl::AclContext

pub mod install;
pub mod layout;
pub mod lookup;
pub mod rule;
