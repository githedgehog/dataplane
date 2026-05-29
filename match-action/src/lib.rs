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

pub mod field;
pub mod predicate;
pub mod rule;

#[cfg(feature = "bolero")]
pub mod generator;

pub use field::FixedSize;
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
    const N: usize;
    const KEY_SIZE: usize;
    fn field_specs() -> &'static [FieldSpec];
    fn as_key_into(&self, out: &mut [u8]);
}
