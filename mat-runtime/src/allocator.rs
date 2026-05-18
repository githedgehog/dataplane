// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Policy generation allocator.
//!
//! The dataplane-wide counter that tags every policy update.  The
//! two-atomic pattern separates allocation (writers prepare a
//! rollout) from publication (workers see the new gen at batch
//! boundary):
//!
//! - `next`: monotonic allocator.  [`begin_rollout`] consumes the
//!   next value and increments.  Frozen layers produced by
//!   `Cascade::rotate` during a rollout are tagged with the
//!   allocated value.
//! - `current`: published value.  Workers read this at batch start
//!   via [`current`] and use it as the `lookup_at` horizon.
//!   [`publish`] bumps it to the supplied gen -- the commit point
//!   of a rollout.
//!
//! A rollout that fails before [`publish`] simply does not call
//! [`publish`]; workers continue seeing the old `current` value
//! and the staged frozen layers remain invisible to them (because
//! their gen > horizon).  Cleanup of those staged layers is the
//! manager's responsibility -- they sit in the chain until
//! compacted away.
//!
//! [`begin_rollout`]: PolicyGenAllocator::begin_rollout
//! [`current`]: PolicyGenAllocator::current
//! [`publish`]: PolicyGenAllocator::publish

use core::sync::atomic::{AtomicU64, Ordering};

use cascade::Generation;

/// Outcome of [`PolicyGenAllocator::begin_rollout`].
#[derive(Debug)]
pub enum AllocateError {
    /// The internal counter overflowed `u64::MAX`.  Operationally
    /// unreachable -- decades of rotations at thousands per second.
    /// Returned rather than panicked because `clippy::panic` is
    /// denied workspace-wide.
    Overflow,
}

/// The dataplane-wide policy generation counter.
///
/// Owned by exactly one pipeline manager per dataplane.  Cascades
/// receive generations from this allocator via their `rotate`
/// calls; workers read the published `current` value at batch
/// boundaries.
pub struct PolicyGenAllocator {
    next: AtomicU64,
    current: AtomicU64,
}

impl PolicyGenAllocator {
    /// Construct a fresh allocator.
    ///
    /// `current` starts at [`Generation::FIRST`] (the
    /// "no rollouts published yet" horizon).  `next` starts at
    /// `FIRST + 1`, so the first [`begin_rollout`](Self::begin_rollout)
    /// returns `FIRST + 1` -- strictly above the initial `current`.
    ///
    /// This gap is what makes staging-but-not-publishing a rollout
    /// invisible to workers: a frozen layer tagged `FIRST + 1` has
    /// `gen > current = FIRST`, so `Snapshot::lookup_at` skips it
    /// until [`publish`](Self::publish) bumps `current` to match.
    ///
    /// A worker that calls [`current`](Self::current) immediately
    /// after `new` sees [`Generation::FIRST`].  No rollout has been
    /// performed yet, so no frozen layers exist -- `lookup_at`
    /// falls through to the tail unconditionally.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // The +1 cannot panic: FIRST is 1 and the result is 2.
            next: AtomicU64::new(Generation::FIRST.get().saturating_add(1)),
            current: AtomicU64::new(Generation::FIRST.get()),
        }
    }

    /// Allocate the next [`Generation`] for a rollout.
    ///
    /// The returned value is the gen that pending writes/rotations
    /// should be tagged with.  The caller commits the rollout by
    /// calling [`publish`](Self::publish) with the same value once
    /// all relevant rotations have completed.
    ///
    /// # Errors
    ///
    /// Returns [`AllocateError::Overflow`] if the internal counter
    /// has reached `u64::MAX`.  Treat as an operational catastrophe
    /// -- the manager should escalate (reset / restart) since a u64
    /// counter at any realistic rotation rate takes decades to
    /// exhaust.
    pub fn begin_rollout(&self) -> Result<Generation, AllocateError> {
        let raw = self.next.fetch_add(1, Ordering::Relaxed);
        Generation::new(raw).ok_or(AllocateError::Overflow)
    }

    /// Publish a rollout.  Workers reading
    /// [`current`](Self::current) now see this generation.
    ///
    /// The caller must have completed every rotation in this
    /// rollout before calling `publish` -- otherwise workers can
    /// observe a torn pipeline view.  No invariant is enforced by
    /// the allocator; the manager owns the discipline.
    pub fn publish(&self, generation: Generation) {
        self.current.store(generation.get(), Ordering::Release);
    }

    /// The currently-published [`Generation`].  Workers call this
    /// once per batch and pass the result to every
    /// `Snapshot::lookup_at` in the batch.
    ///
    /// # Panics
    ///
    /// Never panics in normal operation; the internal counter is
    /// initialised to a non-zero value and `publish` only stores
    /// values produced by [`begin_rollout`].  If a non-zero value
    /// is ever observed it indicates allocator corruption; this
    /// returns [`Generation::FIRST`] in that pathological case
    /// rather than panicking.
    #[must_use]
    pub fn current(&self) -> Generation {
        let raw = self.current.load(Ordering::Acquire);
        Generation::new(raw).unwrap_or(Generation::FIRST)
    }

    /// The next value that would be returned by
    /// [`begin_rollout`](Self::begin_rollout).
    ///
    /// Diagnostic.  Used by the manager's wrap/reset policy to
    /// decide when to apply back-pressure or attempt opportunistic
    /// reset.
    #[must_use]
    pub fn peek_next(&self) -> Generation {
        let raw = self.next.load(Ordering::Relaxed);
        Generation::new(raw).unwrap_or(Generation::FIRST)
    }
}

impl Default for PolicyGenAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::PolicyGenAllocator;
    use cascade::Generation;

    #[test]
    fn fresh_allocator_publishes_first() {
        let a = PolicyGenAllocator::new();
        // current is the "no rollouts published yet" sentinel: FIRST.
        assert_eq!(a.current(), Generation::FIRST);
        // next sits one above FIRST so the first allocation lands
        // strictly above current.
        assert!(a.peek_next() > a.current());
        assert_eq!(a.peek_next().get(), Generation::FIRST.get() + 1);
    }

    #[test]
    fn begin_rollout_advances_next_but_not_current() {
        let a = PolicyGenAllocator::new();
        let g1 = a.begin_rollout().expect("alloc");
        // First allocation is strictly above the initial current
        // (so a staged-but-unpublished rollout is invisible).
        assert!(g1 > a.current());
        assert_eq!(g1.get(), Generation::FIRST.get() + 1);

        // current is still FIRST -- publish has not been called.
        assert_eq!(a.current(), Generation::FIRST);

        // peek_next has advanced to the next allocation value.
        assert!(a.peek_next() > g1);
        assert_eq!(a.peek_next().get(), g1.get() + 1);
    }

    #[test]
    fn publish_makes_rollout_visible() {
        let a = PolicyGenAllocator::new();
        let g = a.begin_rollout().expect("alloc");
        a.publish(g);
        assert_eq!(a.current(), g);
    }

    #[test]
    fn out_of_order_publish_is_caller_responsibility() {
        // Allocate g1 and g2 but only publish g2.  current sees g2.
        let a = PolicyGenAllocator::new();
        let _g1 = a.begin_rollout().expect("alloc1");
        let g2 = a.begin_rollout().expect("alloc2");
        a.publish(g2);
        assert_eq!(a.current(), g2);

        // Subsequently publishing g1 also "succeeds" (the
        // allocator does not validate monotonicity).  In
        // production the manager arranges for this not to happen;
        // this test documents the discipline boundary.
        let g1 = Generation::FIRST;
        a.publish(g1);
        assert_eq!(a.current(), g1);
    }
}
