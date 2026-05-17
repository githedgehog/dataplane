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

//! ACL classifier built on top of the cascade primitive.
//!
//! The public surface is [`Classifier`]: construct one with a
//! default action, install rules, rotate (publish), and classify
//! packet headers.  The underlying cascade machinery handles
//! atomic publication, snapshot consistency, and compaction; the
//! ACL crate provides the domain-specific layer types and the
//! match-expression evaluation.
//!
//! # Composition
//!
//! ```text
//!   Cascade<H = AclHead, S = AclFrozen, T = AclTail>
//!     - AclHead   : multi-writer BTreeMap, returns Continue (writes
//!                   visible after the next rotate)
//!     - AclFrozen : immutable priority-sorted Vec<AclRule>
//!     - AclTail   : same shape as AclFrozen for now (DPDK ACL
//!                   variant will land later)
//! ```
//!
//! [`Cascade`]: cascade::Cascade
//! [`Classifier`]: crate::Classifier

pub mod classifier;
pub mod layers;
pub mod types;

pub use classifier::Classifier;
pub use layers::{AclFrozen, AclHead, AclOp, AclTail};
pub use types::{AclRule, Action, Headers, Match, Priority, Protocol};
