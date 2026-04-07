// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! ACL match-action classification engine.
//!
//! Provides a type-safe rule builder, compiled classifier, and
//! match-action engine for network packet classification.

mod action;
mod builder;
mod cascade;
pub mod category;
mod classify;
mod classifier;
#[cfg(any(test, feature = "bolero"))]
mod generators;
#[cfg(any(test, feature = "bolero"))]
pub use generators::{GenerateAclTable, GenerateTablePair};
mod match_expr;
mod overlap;
mod signature;
mod match_fields;
pub mod metadata;
mod priority;
mod rule;
mod table;
mod update;

pub use classifier::Classifier;
pub use classify::ClassifyOutcome;
pub use overlap::{analyze_overlaps, OverlapAnalysis, OverlapPair};
pub use signature::{group_rules_by_signature, FieldSignature, SignatureGroup};

pub use action::{ActionSequence, Fate, Step};
pub use match_expr::{ExactMatch, FieldMatch, MaskedMatch};
pub use match_fields::{EthMatch, Icmp4Match, Ipv4Match, Ipv6Match, TcpMatch, UdpMatch, VlanMatch};
pub use builder::{AclMatchFields, AclRuleBuilder, Blank, Install, Within};
pub use category::{CategorizedRule, CategorizedTable, CategoryError, CategorySet, Compiler};
pub use cascade::{
    compile_cascade, Assignment, BackendCapabilities, CompilationPlan, TrapRule,
};
pub use metadata::Metadata;
pub use rule::AclRule;
pub use table::{AclTable, AclTableBuilder};
pub use update::{build_tiered, diff_tables, plan_update, TableDiff, UpdatePlan};
pub use priority::{Priority, PriorityZeroError};
pub use lpm::prefix::{Ipv4Prefix, Ipv6Prefix, IpPrefix, PrefixError};
