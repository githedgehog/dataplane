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
//! let table = AclTableBuilder::new(Fate::Drop)
//!     .add_rule(rule)
//!     .build();
//! ```

mod action;
mod builder;
mod cascade;
pub mod category;
mod classifier;
mod classify;
#[cfg(any(test, feature = "bolero"))]
mod generators;
pub mod match_expr;
mod match_fields;
pub mod metadata;
use std::{
    borrow::Cow,
    collections::HashMap,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    time::Instant,
};

#[cfg(any(test, feature = "bolero"))]
pub use generators::{GenerateAclTable, GenerateTablePair};
mod overlap;
mod priority;
mod range;
mod rule;
mod signature;
mod table;
mod update;

pub use action::{ActionSequence, Fate, Step};
pub use builder::{AclMatchFields, AclRuleBuilder, Blank, Install, Within};
pub use cascade::{Assignment, BackendCapabilities, CompilationPlan, TrapRule, compile_cascade};
pub use category::{CategorizedRule, CategorizedTable, CategoryError, CategorySet, Compiler};
pub use classifier::Classifier;
pub use classify::ClassifyOutcome;
pub use match_expr::{ExactMatch, FieldMatch, MaskedMatch, RangeMatch};
pub use match_fields::{EthMatch, Icmp4Match, Ipv4Match, Ipv6Match, TcpMatch, UdpMatch, VlanMatch};
pub use metadata::Metadata;
use net::{
    eth::{
        Eth,
        mac::{Mac, SourceMac},
    },
    ipv4::{Ipv4, UnicastIpv4Addr},
    ipv6::{Ipv6, UnicastIpv6Addr},
    tcp::{Tcp, TcpPort},
    udp::{Udp, UdpPort},
};
pub use overlap::{OverlapAnalysis, OverlapPair, analyze_overlaps};
pub use priority::{Priority, PriorityZeroError};
pub use range::{Ipv4Prefix, Ipv4PrefixError, Ipv6Prefix, Ipv6PrefixError, PortRange};
pub use rule::AclRule;
pub use signature::{FieldSignature, SignatureGroup, group_rules_by_signature};
pub use table::{AclTable, AclTableBuilder};
pub use update::{TableDiff, UpdatePlan, build_tiered, diff_tables, plan_update};

// -------- scratch ---------

#[repr(transparent)]
struct Field<T, U>
where
    U: Decision,
{
    tracked: T,
    level: PhantomData<U>,
}

// this would be sealed for sure
trait Decision {}

// read is passive: not eligible for use in branch conditions, may not be updated by function author
// Example: hit counters for a rule
#[repr(transparent)]
#[non_exhaustive]
#[allow(dead_code)] // marker
struct Passive;

// read is actionable: eligible for use in branch conditions
// Example: ttl == 0, or rate limit exceeded.
#[repr(transparent)]
#[non_exhaustive]
#[allow(dead_code)] // marker
struct Actionable;

// read permits mutations: eligible for use in branch conditions, eli
// Example: NAT of src ip
#[repr(transparent)]
#[non_exhaustive]
#[allow(dead_code)] // marker
struct Mutating;

impl Decision for Passive {}
impl Decision for Actionable {}
impl Decision for Mutating {}

// ----- scratch 2 ------

// Imagine that we construct (or derive) a "builder" / "overlay" / copy-on-write version of `Headers`.
//
// 1. automatic coalesce of multiple writes to same field (op log vec appends instead)
// 2. (possibly?) saves on L1d space because a batch oriented bump alloc of `DiffHeaders` (or whatever we call it)
//    gets to recycle mutual exclusion space via enum mechanics while the Vec does not.
//
// We could also potentially assign a compile time Id to each element in Headers and use a bitset to track access /
// mutation.

// ----- scratch 3 ------

// let's just game out a basic framework aware nat and see if and when it feels right to make it feel more transparent.

// todo: seal?
trait Port: Copy + std::hash::Hash + PartialEq + Eq + Ord + PartialOrd + 'static {}

// todo: seal?
trait Address: Copy + std::hash::Hash + PartialEq + Eq + Ord + PartialOrd + 'static {
    type Unicast: Address<Unicast = Self::Unicast> + Into<Self> + AsRef<Self> + TryFrom<Self>;
}

impl Port for TcpPort {}
impl Port for UdpPort {}

impl Address for Ipv4Addr {
    type Unicast = UnicastIpv4Addr;
}

impl Address for UnicastIpv4Addr {
    type Unicast = Self;
}

impl Address for Ipv6Addr {
    type Unicast = UnicastIpv6Addr;
}

impl Address for UnicastIpv6Addr {
    type Unicast = Self;
}

impl Address for Mac {
    type Unicast = SourceMac;
}

impl Address for SourceMac {
    type Unicast = Self;
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct NatTableEntry<Addr, Port> {
    forward: NatMatch<Addr, Port>,
    reverse: NatMatch<Addr, Port>,
    hits: u64,
    established: Instant,
    last_hit: Instant,
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct NatMatch<Addr, Port> {
    addr: Addr,
    port: Port,
}

#[derive(Clone)]
enum NatState<Addr, Port> {
    New(NatMatch<Addr, Port>),
    Established(NatMatch<Addr, Port>),
    Related(NatMatch<Addr, Port>),
    Expected(NatMatch<Addr, Port>),
    Invalid,
}

trait Table {
    type Match<'a>
    where
        Self: 'a;
    type Action<'a>
    where
        Self: 'a;
    fn lookup(&self, match_: Self::Match<'_>) -> Self::Action<'_>;
}

enum NatOutcome<'a, Addr, Port> {
    UseExistingMapping(&'a NatTableEntry<Addr, Port>),
    CreateNewMapping(NatMatch<Addr, Port>),
}

struct NatTable<Addr, Port> {
    forward: HashMap<NatMatch<Addr, Port>, usize>,
    reverse: HashMap<NatMatch<Addr, Port>, usize>,
    mappings: slab::Slab<NatTableEntry<Addr, Port>>,
}

impl<A, P> Table for NatTable<A, P>
where
    A: Address,
    P: Port,
{
    type Match<'a>
        = NatMatch<A, P>
    where
        Self: 'a;

    type Action<'a>
        = NatOutcome<'a, A, P>
    where
        Self: 'a;

    #[allow(clippy::panic)] // scratch code
    fn lookup(&self, match_: Self::Match<'_>) -> Self::Action<'_> {
        if let Some(&key) = self.forward.get(&match_) {
            match self.mappings.get(key) {
                Some(rule) => NatOutcome::UseExistingMapping(rule),
                None => {
                    panic!("programmer error");
                }
            }
        } else {
            #[allow(unreachable_code, clippy::diverging_sub_expression, unused_variables)]
            // scratch
            {
                // allocate a new mapping
                let new_mapping: NatMatch<A, P> = unimplemented!("magic allocation function");
                NatOutcome::CreateNewMapping(new_mapping)
            }
        }
    }
}
