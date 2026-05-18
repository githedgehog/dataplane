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

/// Pressure regime reported by [`PolicyGenAllocator::pressure`].
///
/// The pipeline manager polls this to decide whether to allocate
/// new generations freely, throttle policy updates, or stop and
/// attempt a counter reset.
///
/// The thresholds are defined in terms of the *wire stamp* (u24) of
/// the next allocation, not the internal u64 counter, because the
/// constraint that drives the regime is stamp-space exhaustion on
/// the wire / NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureLevel {
    /// Below [`PolicyGenAllocator::THROTTLE_AT`].  Counter advances
    /// freely.
    Free,
    /// Between [`PolicyGenAllocator::THROTTLE_AT`] and
    /// [`PolicyGenAllocator::AGGRESSIVE_AT`].  Manager should slow
    /// the policy-update intake (linear or mild exponential
    /// back-off) and start opportunistic reset attempts.
    Throttle,
    /// Between [`PolicyGenAllocator::AGGRESSIVE_AT`] and
    /// [`PolicyGenAllocator::BLOCK_AT`].  Manager should apply
    /// aggressive (exponential) back-pressure and actively try
    /// to quiesce for reset.
    Aggressive,
    /// At or above [`PolicyGenAllocator::BLOCK_AT`].  Manager
    /// should block all new rollouts until reset succeeds.  If
    /// quiescence cannot be reached in a bounded window, the
    /// manager should escalate (mark a NIC failed, crash the
    /// process, etc.).
    Block,
}

/// Outcome of [`PolicyGenAllocator::try_reset`].
#[derive(Debug)]
pub enum ResetError {
    /// A rollout has been started ([`begin_rollout`] called) but
    /// not yet published.  Reset would orphan the staged frozen
    /// layer.  Caller should either complete the rollout (publish)
    /// or wait.
    ///
    /// [`begin_rollout`]: PolicyGenAllocator::begin_rollout
    RolloutStaged,
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
    /// Wire-stamp value at which back-pressure begins
    /// ([`PressureLevel::Throttle`]).  `2^23` = half of the u24
    /// stamp space.
    pub const THROTTLE_AT: u32 = 0x0080_0000;

    /// Wire-stamp value at which aggressive back-pressure begins
    /// ([`PressureLevel::Aggressive`]).  `~7/8` of the u24 stamp
    /// space.
    pub const AGGRESSIVE_AT: u32 = 0x00E0_0000;

    /// Wire-stamp value at which new allocations must be blocked
    /// until reset ([`PressureLevel::Block`]).  Two below
    /// `2^24 - 1` to leave headroom for any in-flight allocations
    /// that race the manager's pressure check.
    pub const BLOCK_AT: u32 = 0x00FF_FFFE;

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

    /// Current pressure regime based on the wire-stamp value of the
    /// next allocation.
    ///
    /// The manager calls this before [`begin_rollout`] to decide
    /// whether to proceed, back off, or attempt a reset.  See
    /// [`PressureLevel`] for the semantics of each regime.
    ///
    /// The check is on the *wire stamp* (next % `2^24`), not the
    /// raw u64 counter -- the constraint that drives the regime
    /// is the u24 NIC stamp space, not internal counter exhaustion
    /// (which would take decades at any realistic rotation rate).
    ///
    /// [`begin_rollout`]: Self::begin_rollout
    #[must_use]
    pub fn pressure(&self) -> PressureLevel {
        let stamp = self.peek_next().wire_stamp();
        if stamp < Self::THROTTLE_AT {
            PressureLevel::Free
        } else if stamp < Self::AGGRESSIVE_AT {
            PressureLevel::Throttle
        } else if stamp < Self::BLOCK_AT {
            PressureLevel::Aggressive
        } else {
            PressureLevel::Block
        }
    }

    /// Reset both counters back to the initial state.
    ///
    /// # Allocator-checked preconditions
    /// - No rollout is staged: `next == current + 1`.  Otherwise
    ///   returns [`ResetError::RolloutStaged`].
    ///
    /// # Caller-enforced preconditions (load-bearing -- cannot be
    /// verified by the allocator)
    /// - Every cascade fed by this allocator has an empty frozen
    ///   chain (all frozen layers compacted into the tail).
    /// - No in-flight packet carries a wire stamp from before this
    ///   reset.  In practice the manager verifies this via the
    ///   hardware-offload subscriber's watermark report ("I have
    ///   drained past generation X across every RX queue").
    /// - No worker is mid-`lookup_at` with a horizon drawn from
    ///   before the reset.  At batch boundaries this is naturally
    ///   satisfied; long-running snapshots would violate it.
    ///
    /// Violating any caller-enforced precondition can cause
    /// `Snapshot::lookup_at` to silently consult the wrong rule
    /// set or skip valid layers.  Reset is a stop-the-world
    /// operation and the manager owns the quiescence discipline.
    ///
    /// # Concurrency
    ///
    /// Reset is not safe to call concurrently with `begin_rollout`
    /// or `publish`.  Caller must serialise externally.
    ///
    /// # Errors
    ///
    /// Returns [`ResetError::RolloutStaged`] when `next` is not
    /// exactly one above `current`, i.e. a
    /// [`begin_rollout`](Self::begin_rollout) has not been matched
    /// by [`publish`](Self::publish).
    pub fn try_reset(&self) -> Result<(), ResetError> {
        let next = self.next.load(Ordering::Relaxed);
        let current = self.current.load(Ordering::Acquire);
        // Steady state: next is one ahead of current.  Anything
        // else means a rollout is staged or out-of-order publish
        // has happened.
        if next != current.saturating_add(1) {
            return Err(ResetError::RolloutStaged);
        }
        // Order: store current first so a worker reading current
        // after the reset sees the small value; then store next.
        // A racing `begin_rollout` between the two stores would
        // get the OLD large value (worst case: we don't reset
        // this round and need to retry).  Caller is supposed to
        // serialise reset against begin_rollout anyway.
        self.current
            .store(Generation::FIRST.get(), Ordering::Release);
        self.next
            .store(Generation::FIRST.get().saturating_add(1), Ordering::Relaxed);
        Ok(())
    }
}

impl Default for PolicyGenAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyGenAllocator {
    /// Jump the internal counter to a target value, for tests that
    /// want to exercise pressure thresholds without doing millions
    /// of real allocations.
    ///
    /// Sets both `current` (target - 1) and `next` (target) such
    /// that the steady-state invariant `next == current + 1` holds.
    #[cfg(test)]
    pub(crate) fn jump_to_for_test(&self, next: u64) {
        let new_next = next.max(2);
        let new_current = new_next.saturating_sub(1);
        self.current.store(new_current, Ordering::Release);
        self.next.store(new_next, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{PolicyGenAllocator, PressureLevel, ResetError};
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

    // ----------------------------------------------------------------------
    // Pressure regimes
    // ----------------------------------------------------------------------

    #[test]
    fn pressure_is_free_immediately_after_construction() {
        let a = PolicyGenAllocator::new();
        assert_eq!(a.pressure(), PressureLevel::Free);
    }

    #[test]
    fn pressure_transitions_through_regimes_with_wire_stamp_position() {
        let a = PolicyGenAllocator::new();

        // Just below THROTTLE_AT -> Free.
        a.jump_to_for_test(u64::from(PolicyGenAllocator::THROTTLE_AT) - 1);
        assert_eq!(a.pressure(), PressureLevel::Free);

        // At THROTTLE_AT -> Throttle.
        a.jump_to_for_test(u64::from(PolicyGenAllocator::THROTTLE_AT));
        assert_eq!(a.pressure(), PressureLevel::Throttle);

        // Just below AGGRESSIVE_AT -> Throttle.
        a.jump_to_for_test(u64::from(PolicyGenAllocator::AGGRESSIVE_AT) - 1);
        assert_eq!(a.pressure(), PressureLevel::Throttle);

        // At AGGRESSIVE_AT -> Aggressive.
        a.jump_to_for_test(u64::from(PolicyGenAllocator::AGGRESSIVE_AT));
        assert_eq!(a.pressure(), PressureLevel::Aggressive);

        // Just below BLOCK_AT -> Aggressive.
        a.jump_to_for_test(u64::from(PolicyGenAllocator::BLOCK_AT) - 1);
        assert_eq!(a.pressure(), PressureLevel::Aggressive);

        // At BLOCK_AT -> Block.
        a.jump_to_for_test(u64::from(PolicyGenAllocator::BLOCK_AT));
        assert_eq!(a.pressure(), PressureLevel::Block);
    }

    #[test]
    fn pressure_is_based_on_wire_stamp_not_raw_counter() {
        // Verify the modulo: a u64 value just above 2^24 should
        // produce a low wire stamp and therefore Free pressure.
        let a = PolicyGenAllocator::new();
        a.jump_to_for_test((1u64 << 24) + 10);
        assert_eq!(a.pressure(), PressureLevel::Free);
    }

    // ----------------------------------------------------------------------
    // Reset
    // ----------------------------------------------------------------------

    #[test]
    fn try_reset_succeeds_at_steady_state() {
        let a = PolicyGenAllocator::new();
        let g = a.begin_rollout().expect("alloc");
        a.publish(g);

        // Steady state: next == current + 1.
        assert!(a.try_reset().is_ok());

        // After reset: back to initial state.
        assert_eq!(a.current(), Generation::FIRST);
        assert_eq!(a.peek_next().get(), Generation::FIRST.get() + 1);
    }

    #[test]
    fn try_reset_refuses_when_rollout_is_staged() {
        let a = PolicyGenAllocator::new();
        let _g = a.begin_rollout().expect("alloc");
        // Did NOT publish: next has advanced past current+1.

        match a.try_reset() {
            Err(ResetError::RolloutStaged) => {}
            other => panic!("expected RolloutStaged, got {other:?}"),
        }

        // Counter state is unchanged.
        assert_eq!(a.current(), Generation::FIRST);
    }

    #[test]
    fn try_reset_from_high_value_restores_low_pressure() {
        let a = PolicyGenAllocator::new();
        a.jump_to_for_test(u64::from(PolicyGenAllocator::AGGRESSIVE_AT));
        assert_eq!(a.pressure(), PressureLevel::Aggressive);

        assert!(a.try_reset().is_ok());

        assert_eq!(a.pressure(), PressureLevel::Free);
        assert_eq!(a.current(), Generation::FIRST);
    }

    #[test]
    fn allocations_resume_correctly_after_reset() {
        let a = PolicyGenAllocator::new();
        let g1 = a.begin_rollout().expect("g1");
        a.publish(g1);
        a.try_reset().expect("reset");

        // First post-reset allocation lands at FIRST+1 (same as
        // first-ever allocation).
        let g_after = a.begin_rollout().expect("g_after");
        assert_eq!(g_after.get(), Generation::FIRST.get() + 1);
        a.publish(g_after);
        assert_eq!(a.current(), g_after);
    }
}
