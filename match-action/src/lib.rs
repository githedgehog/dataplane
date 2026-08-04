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
#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod display;
pub mod field;
pub mod predicate;
pub mod rule;

#[cfg(feature = "bolero")]
pub mod generator;

pub use display::{Field, RuleFields, write_grid};
pub use field::{FixedSize, MaskBits};
pub use predicate::{Erased, FieldBytes, FieldPredicate, MAX_FIELD_BYTES};
pub use rule::{
    Accepts, Backend, ExactSpec, IntoBackendField, IsUniversal, MaskSpec, PrefixSpec, RangeSpec,
    RuleField,
};

#[cfg(feature = "bolero")]
pub use generator::{FieldHit, FieldMiss};

#[cfg(feature = "derive")]
pub use match_action_derive::MatchKey;
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FieldKind {
    Prefix,
    Mask,
    Range,
    Exact,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FieldSpec {
    pub name: &'static str,
    pub kind: FieldKind,
    pub size: usize,
    pub offset: usize,
}
pub trait MatchKey: Sized {
    /// The rule (predicate) form of this key: one spec per match field, still carrying each
    /// field's type. A table can therefore retain the rules it was built from in a form that
    /// renders itself, without having to decode erased bytes back into domain types.
    type Rule;

    const N: usize;
    const KEY_SIZE: usize;
    fn field_specs() -> &'static [FieldSpec];
    fn as_key_into(&self, out: &mut [u8]);
}
