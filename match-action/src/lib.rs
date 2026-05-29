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

//! Backend-agnostic match-action key vocabulary.
//!
//! Struct fields annotated with `#[prefix]` / `#[mask]` / `#[range]` /
//! `#[exact]`; `#[derive(MatchKey)]` emits the [`MatchKey`] impl and
//! a parallel `<Name>Rule` struct of kind-typed `*Spec`s.
//!
//! ```ignore
//! #[derive(MatchKey)]
//! struct FiveTuple {
//!     #[exact]  proto: u8,
//!     #[prefix] src_ip: Ipv4Addr,
//!     #[range]  dst_port: u16,
//! }
//! ```
//!
//! Backends consume via [`MatchKey::field_specs`] (structural view)
//! and [`MatchKey::as_key_into`] (byte packer).  Rule wrappers and
//! backend lowering live in [`rule`]; the type-erased
//! [`FieldPredicate`] lives in [`predicate`].

pub mod field;
pub mod predicate;
pub mod rule;

pub use field::FixedSize;
pub use predicate::{Erased, FieldBytes, FieldPredicate, MAX_FIELD_BYTES};
pub use rule::{
    Accepts, Backend, ExactSpec, IntoBackendField, IsUniversal, MaskSpec, PrefixSpec, RangeSpec,
    RuleField,
};

#[cfg(feature = "derive")]
pub use match_action_derive::MatchKey;

/// One of the four predicate flavors.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FieldKind {
    Prefix,
    Mask,
    Range,
    Exact,
}

/// Static layout of one field within a [`MatchKey`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FieldSpec {
    pub name: &'static str,
    pub kind: FieldKind,
    pub size: usize,
    pub offset: usize,
}

/// A match-action lookup key.
///
/// Emitted by `#[derive(MatchKey)]`, which also adds an inherent
/// `FIELD_SPECS` const and (for non-generic structs) an `as_key() ->
/// [u8; KEY_SIZE]` for ergonomics.
///
/// Trait methods take slices instead of `Self::N`-sized arrays
/// because `Self::N` in a trait fn needs unstable
/// `generic_const_exprs`; sized inherents sidestep that.
pub trait MatchKey: Sized {
    const N: usize;
    const KEY_SIZE: usize;
    fn field_specs() -> &'static [FieldSpec];
    /// `out.len() >= KEY_SIZE`; the derive emits a length check.
    fn as_key_into(&self, out: &mut [u8]);
}
