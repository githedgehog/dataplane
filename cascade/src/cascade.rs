// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The cascade itself.
//!
//! Wires a [`MutableHead`], a `Vec<Arc<Sealed>>` of intermediate
//! layers, and an `ArcSwap`-published tail into a single read path.
//! The data-plane fast path is [`Cascade::lookup`] -- one atomic
//! load to obtain the head, then a cascade walk through sealed
//! layers and the tail.
//!
//! The writer-side machinery (drain triggers, seal-and-rotate,
//! compactor, subscription) is intentionally not on this struct yet
//! -- the present sketch focuses on locking down the reader/writer
//! trait contracts.  Those pieces will arrive in a follow-on commit
//! once the trait shape settles.

use concurrency::sync::Arc;

use crate::head::MutableHead;
use crate::layer::{Layer, Outcome};

/// A three-level cascade.
///
/// `H` is the multi-writer head.  `S` is the sealed-layer type
/// (must agree with `H::Sealed`).  `T` is the tail.  All three must
/// share an [`Input`](Layer::Input) and [`Output`](Layer::Output) so
/// that the cascade walk has a single coherent signature.
///
/// # Concurrency
///
/// The struct itself is owned by a single LSM-manager task.  Readers
/// hold an `Arc<Cascade<H, S, T>>` (or, more typically, just an
/// `Arc<H>` obtained from a published snapshot) and call
/// [`lookup`](Cascade::lookup).  The head is concurrent-mutable by
/// its trait; sealed layers and the tail are immutable after
/// construction.
///
/// # Note
///
/// This struct is a sketch.  In the eventual production shape the
/// head and tail will be published via `concurrency::slot::Slot`
/// (ArcSwap-equivalent) so readers can pick up new generations
/// without coordination; the `Vec<Arc<Sealed>>` of intermediates
/// will move behind a similar published handle.  The fields here
/// are placeholder-public for design iteration.
pub struct Cascade<H, S, T>
where
    H: MutableHead<Sealed = S>,
    S: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    /// The mutable head.  Owned by the cascade for the moment;
    /// production shape will be `Slot<Arc<H>>`.
    pub head: H,
    /// Sealed intermediate layers, ordered newest-first.  A newly
    /// sealed head is pushed to index 0; compaction drains from
    /// the back of the vec into the tail.
    pub sealed: Vec<Arc<S>>,
    /// The ground-truth tail.  Production shape will wrap this in
    /// `Slot<Arc<T>>` so the compactor can publish new tail
    /// generations without disturbing readers.
    pub tail: Arc<T>,
}

impl<H, S, T> Cascade<H, S, T>
where
    H: MutableHead<Sealed = S>,
    S: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    /// Construct an empty cascade with no sealed layers.
    pub fn new(head: H, tail: Arc<T>) -> Self {
        Self {
            head,
            sealed: Vec::new(),
            tail,
        }
    }

    /// Walk the cascade and return the first definitive match.
    ///
    /// Order: head, then sealed layers newest-first, then tail.
    /// Each layer's [`may_contain`](Layer::may_contain) is consulted
    /// before [`lookup`](Layer::lookup) to skip layers that the
    /// bloom hint excludes.
    pub fn lookup(&self, input: &H::Input) -> Option<&H::Output> {
        // Head first.  No bloom (the head is small and mutable; the
        // filter would have to be atomic to be correct).
        match self.head.lookup(input) {
            Outcome::Match(v) => return Some(v),
            Outcome::Forbid => return None,
            Outcome::Miss => {}
        }

        // Sealed layers, newest-first.
        for layer in &self.sealed {
            if !layer.may_contain(input) {
                continue;
            }
            match layer.lookup(input) {
                Outcome::Match(v) => return Some(v),
                Outcome::Forbid => return None,
                Outcome::Miss => {}
            }
        }

        // Tail.
        if !self.tail.may_contain(input) {
            return None;
        }
        match self.tail.lookup(input) {
            Outcome::Match(v) => Some(v),
            Outcome::Forbid | Outcome::Miss => None,
        }
    }
}
