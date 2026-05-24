// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The mutable head of the cascade.
//!
//! [`MutableHead`] extends [`Layer`] with the writer-facing
//! capabilities: accepting concurrent writes via [`write`], reporting
//! occupancy for drain-trigger purposes via [`approx_size`], and
//! converting itself into an immutable frozen layer via [`freeze`].
//!
//! The head is the only multi-writer level in the cascade.  Frozen
//! intermediate layers and the tail are immutable after construction.

use crate::layer::Layer;

/// A cascade level that accepts concurrent writes.
///
/// Implementations are typically built around a concurrent hash map
/// (`dashmap`, `papaya`, or similar) plus a strategy for combining
/// concurrent writes against the same key via the [`Upsert`](crate::Upsert)
/// trait on the value type.
///
/// # Freezing
///
/// Freezing produces an immutable
/// [`Frozen`](MutableHead::Frozen) layer that captures the head's
/// current contents.  After freezing, a fresh head is constructed
/// to receive new writes; the frozen layer joins the cascade
/// between the new head and the (older) tail.
///
/// Freezing must be cheap.  A head's whole reason for existence is
/// to absorb writes at line rate; if the freeze operation requires
/// non-trivial work (sorting, rebuilding indices, allocating large
/// buffers) the drain throttles.  Defer expensive build work to the
/// compactor step (`Cascade::compact`) that fuses frozen layers and
/// possibly rebuilds the tail.
// TODO: this feels like a job for typestate pattern.  That isn't far
// off from what we have now.  Deferred: the `Frozen` output type is
// genuinely different from `Self`, so collapsing them into a single
// typestate-parameterised type would force a sum type at every layer
// position.  Worth revisiting if Frozen ends up structurally
// identical to Self in practice.
pub trait MutableHead: Layer {
    /// The user's operation type, supplied to [`write`](Self::write).
    type Op;

    /// The immutable layer type produced by [`freeze`](Self::freeze).
    /// Must share the head's [`Input`](Layer::Input) and
    /// [`Output`](Layer::Output) so the cascade can compose them.
    ///
    /// The associated type is named `Frozen` (rather than the more
    /// common `Sealed`) to avoid overlap with the well-known
    /// "sealed trait" pattern -- `Sealed` is widely used as a
    /// trait name to prevent external implementations, and reusing
    /// it here as an associated type was confusing in practice.
    type Frozen: Layer<Input = Self::Input, Output = Self::Output>;

    /// Apply `op` to the head.  Concurrent writes against the same
    /// key are resolved by the value type's
    /// [`Upsert`](crate::Upsert) impl.
    fn write(&self, op: Self::Op);

    /// Snapshot this head into an immutable frozen layer.
    ///
    /// Takes `&self` because in production the head is published
    /// via [`Slot`](concurrency::slot::Slot) and lives behind an
    /// `Arc`.  The frozen layer captures the head's contents at
    /// the moment of the call; concurrent writes may or may not be
    /// reflected depending on the implementation's internal
    /// synchronisation, and any writes arriving after the freeze
    /// that still land on this (now-orphaned) head are silently
    /// lost.  Callers are expected to refresh their head `Arc` from
    /// the [`Cascade`](crate::Cascade) frequently enough that this
    /// transient is not a correctness concern -- see the cascade's
    /// [`rotate`](crate::Cascade::rotate) flow for the ordering
    /// guarantees that make this safe.
    fn freeze(&self) -> Self::Frozen;

    /// Approximate occupancy, used by the drain trigger.  Need not
    /// be precise; the cascade only consults it to decide "is this
    /// head big enough to freeze."
    fn approx_size(&self) -> usize;
}
