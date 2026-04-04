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

//! ACL rule builder with compile-time match field ordering.
//!
//! This module uses the same trait-driven typestate pattern as
//! the header builder in `dataplane-net` to enforce valid ACL match field
//! layering at compile time.
//!
//! # Design
//!
//! Each match field layer participates in three traits:
//!
//! - [`Within<T>`] -- declares that `Self` can follow match layer `T`,
//!   and auto-constrains the parent (e.g., adding a [`TcpMatch`] after
//!   an [`Ipv4Match`] sets the IPv4 protocol field to TCP).
//! - [`Install<T>`] -- implemented on [`AclMatchFields`] for each match
//!   type, describing where to store the layer.
//! - [`Blank`] -- produces an all-wildcard (don't-care) match layer.
//!
//! [`AclRuleBuilder<T>`] is the state carrier.  Chain `.eth(...)`,
//! `.ipv4(...)`, `.tcp(...)`, etc., then finalize with
//! `.permit(priority)` or `.deny(priority)`.
//!
//! # Examples
//!
//! ```ignore
//! use net::acl::*;
//!
//! // Match TCP port 80 traffic from 10.0.0.0/8
//! let rule = AclRuleBuilder::new()
//!     .eth(|_| {})
//!     .ipv4(|ip| {
//!         ip.src = Some(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
//!     })
//!     .tcp(|tcp| {
//!         tcp.dst = Some(PortRange::exact(TcpPort::new_checked(80).unwrap()));
//!     })
//!     .permit(Priority::new(100).unwrap());
//!
//! // Deny all IPv6 traffic
//! let rule = AclRuleBuilder::new()
//!     .eth(|_| {})
//!     .ipv6(|_| {})
//!     .deny(Priority::new(200).unwrap());
//!
//! // Build a table and compile
//! let table = AclTableBuilder::new(Action::Deny)
//!     .add_rule(rule)
//!     .build();
//! ```

mod action;
mod builder;
pub mod category;
mod classify;
pub mod match_expr;
mod match_fields;
pub mod metadata;
mod priority;
mod range;
mod rule;
mod signature;
mod table;

pub use action::Action;
pub use builder::{AclMatchFields, AclRuleBuilder, Blank, Install, Within};
pub use category::{CategorizedRule, CategorizedTable, CategoryError, CategorySet, Compiler};
pub use classify::LinearClassifier;
pub use match_expr::{ExactMatch, FieldMatch, MaskedMatch, RangeMatch};
pub use match_fields::{EthMatch, Icmp4Match, Ipv4Match, Ipv6Match, TcpMatch, UdpMatch};
pub use metadata::Metadata;
pub use priority::{Priority, PriorityZeroError};
pub use range::{Ipv4Prefix, Ipv4PrefixError, Ipv6Prefix, Ipv6PrefixError, PortRange};
pub use signature::FieldSignature;
pub use rule::AclRule;
pub use table::{AclTable, AclTableBuilder};
