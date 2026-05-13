// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Metadata matching for ACL rules.
//!
//! Metadata fields are values associated with a packet that don't come
//! from protocol headers  --  VRF ID, VNI (from an already-stripped tunnel),
//! ingress interface, DSCP, packet marks, etc.
//!
//! Unlike protocol header matches, metadata matches don't participate in
//! layer ordering ([`Within`](`crate::Within`)).  They're an orthogonal
//! axis that can be attached to any rule regardless of its header match
//! shape.
//!
//! # Usage
//!
//! Define a struct with `Option<MatchExpr>` fields and implement
//! [`Metadata`] for it:
//!
//! ```ignore
//! use net::acl::metadata::Metadata;
//! use net::acl::match_expr::ExactMatch;
//!
//! #[derive(Debug, Clone, PartialEq, Eq, Default)]
//! struct MyMeta {
//!     vrf: Option<ExactMatch<u32>>,
//!     vni: Option<ExactMatch<u32>>,
//! }
//!
//! impl Metadata for MyMeta {}
//! ```
//!
//! Then use it in the builder:
//!
//! ```ignore
//! AclRuleBuilder::new()
//!     .metadata(|m: &mut MyMeta| {
//!         m.vrf = Some(ExactMatch::new(42));
//!     })
//!     .eth_match(|_| {})
//!     .ipv4_match(|ip| { ... })
//!     .permit(100);
//! ```

use std::fmt::Debug;

/// Trait for user-defined metadata match types.
///
/// Implement this for a struct whose fields are `Option<MatchExpr<T>>`
/// to define metadata that can be matched in ACL rules.
///
/// The `Default` impl should produce an all-wildcard (all-`None`) state.
///
/// # Associated types
///
/// `Values` is the concrete metadata carried by a packet at classification
/// time.  For example, if the match type has `vrf: Option<ExactMatch<u32>>`,
/// the values type might have `vrf: u32`.
///
/// # Contract
///
/// `matches_values` must return `true` when the metadata match criteria
/// are satisfied by the given values.  A default-constructed metadata
/// (all wildcards) must match any values.
pub trait Metadata: Default + Clone + Debug + PartialEq + Eq {
    /// The concrete metadata values carried by a packet.
    type Values: Debug;

    /// Returns `true` if the metadata match criteria are satisfied by
    /// the given packet metadata values.
    fn matches_values(&self, values: &Self::Values) -> bool;
}

/// The trivial metadata type  --  no metadata matching.
///
/// Always matches.  `Values = ()`  --  no metadata to provide.
impl Metadata for () {
    type Values = ();

    fn matches_values(&self, _values: &()) -> bool {
        true
    }
}
