// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The mutable head of the cascade.
//!
//! [`MutableHead`] extends [`Layer`] with the writer-facing
//! capabilities: accepting concurrent writes via [`write`], reporting
//! occupancy for drain-trigger purposes via [`approx_size`], and
//! converting itself into an immutable sealed layer via [`seal`].
//!
//! The head is the only multi-writer level in the cascade.  Sealed
//! intermediate layers and the tail are immutable after construction.

use crate::layer::Layer;

/// A cascade level that accepts concurrent writes.
///
/// Implementations are typically built around a concurrent hash map
/// (`dashmap`, `papaya`, or similar) plus a strategy for combining
/// concurrent writes against the same key via the [`Absorb`](crate::Absorb)
/// trait on the value type.  See `default_head` for a starter
/// implementation once one ships.
///
/// # Sealing
///
/// Sealing is a single-shot conversion: the head consumes itself
/// and produces an immutable [`Sealed`](MutableHead::Sealed) layer.
/// After sealing, a fresh head is constructed to receive new writes;
/// the sealed layer joins the cascade between the new head and the
/// (older) tail.
///
/// Sealing must be cheap.  A head's whole reason for existence is to
/// absorb writes at line rate; if the seal operation requires
/// non-trivial work (sorting, rebuilding indices, allocating large
/// buffers) the drain throttles.  Defer expensive build work to the
/// [`Compactor`](crate::cascade) step that fuses sealed layers and
/// possibly rebuilds the tail.
pub trait MutableHead: Layer {
    /// The user's operation type, supplied to [`write`](Self::write).
    type Op;

    /// The immutable layer type produced by [`seal`](Self::seal).
    /// Must share the head's [`Input`](Layer::Input) and
    /// [`Output`](Layer::Output) so the cascade can compose them.
    type Sealed: Layer<Input = Self::Input, Output = Self::Output>;

    /// Apply `op` to the head.  Concurrent writes against the same
    /// key are resolved by the value type's
    /// [`Absorb`](crate::Absorb) impl.
    fn write(&self, op: Self::Op);

    /// Convert this head into an immutable sealed layer.
    fn seal(self) -> Self::Sealed;

    /// Approximate occupancy, used by the drain trigger.  Need not
    /// be precise; the cascade only consults it to decide "is this
    /// head big enough to seal."
    fn approx_size(&self) -> usize;
}
