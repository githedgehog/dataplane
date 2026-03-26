// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// All items in this module are pub(crate) for consumption by the harness.
// Suppress dead-code warnings until those consumers land.
#![allow(dead_code)]

//! Deterministic simulated clock for driving smoltcp's time-dependent behavior.
//!
//! [`SimClock`] owns a monotonic instant that starts at zero and only advances
//! when the test code explicitly asks it to.
//! This makes tests fully deterministic — retransmission timers, keepalives,
//! and idle timeouts fire only when the test deliberately moves time forward.
//!
//! The public API speaks [`std::time::Duration`]; the smoltcp-specific
//! [`smoltcp::time::Instant`] is exposed only within this crate.

use std::time::Duration;

use smoltcp::time::Instant;

/// A deterministic clock for driving smoltcp's time-dependent behavior.
///
/// Time starts at zero and advances only via [`advance`](Self::advance).
/// This ensures that no wall-clock jitter can affect test outcomes.
pub struct SimClock {
    now: Instant,
}

impl SimClock {
    /// The time increment applied on each [`step`](super::harness::FlowHarness::step) tick.
    ///
    /// 1 ms is short enough to keep simulations responsive while being long
    /// enough for smoltcp's internal timers to make meaningful progress when
    /// tests advance time by many ticks.
    pub(crate) const TICK: Duration = Duration::from_millis(1);

    /// Create a clock starting at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            now: Instant::ZERO,
        }
    }

    /// Current simulated time as a smoltcp [`Instant`].
    ///
    /// This is `pub(crate)` because smoltcp types must not leak through the
    /// public API.
    #[must_use]
    pub(crate) fn now(&self) -> Instant {
        self.now
    }

    /// Advance the clock by `duration`.
    ///
    /// # Panics
    ///
    /// Panics if `duration` is zero.  A zero advance is almost certainly a
    /// bug in the test logic — if you intended to poll without moving time
    /// forward, call [`FlowHarness::step`](super::harness::FlowHarness::step)
    /// instead.
    pub fn advance(&mut self, duration: Duration) {
        assert!(
            !duration.is_zero(),
            "SimClock::advance() called with Duration::ZERO; \
             time must move forward on every advance"
        );
        // smoltcp::time::Duration uses u64 microseconds internally.
        // std::time::Duration::as_micros() returns u128, so we saturate
        // to u64::MAX which is ~584 000 years — more than enough.
        #[allow(clippy::cast_possible_truncation)] // deliberately saturating
        let us = duration.as_micros().min(u128::from(u64::MAX)) as u64;
        self.now += smoltcp::time::Duration::from_micros(us);
    }

    /// Advance the clock by one [`TICK`](Self::TICK).
    pub(crate) fn tick(&mut self) {
        self.advance(Self::TICK);
    }

    /// Elapsed time since the clock was created, as a [`std::time::Duration`].
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        // smoltcp Instant::total_micros() returns i64; our clock never goes
        // negative so the cast is safe.
        #[allow(clippy::cast_sign_loss)] // clock is monotonic from zero
        let us = self.now.total_micros() as u64;
        Duration::from_micros(us)
    }
}

impl Default for SimClock {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_zero() {
        let clock = SimClock::new();
        assert_eq!(clock.elapsed(), Duration::ZERO);
        assert_eq!(clock.now(), Instant::ZERO);
    }

    #[test]
    fn advance_increases_elapsed() {
        let mut clock = SimClock::new();
        clock.advance(Duration::from_millis(100));
        assert_eq!(clock.elapsed(), Duration::from_millis(100));
    }

    #[test]
    #[should_panic(expected = "Duration::ZERO")]
    fn advance_by_zero_panics() {
        let mut clock = SimClock::new();
        clock.advance(Duration::ZERO);
    }

    #[test]
    fn advance_is_cumulative() {
        let mut clock = SimClock::new();
        clock.advance(Duration::from_millis(50));
        clock.advance(Duration::from_millis(75));
        assert_eq!(clock.elapsed(), Duration::from_millis(125));
    }

    #[test]
    fn tick_advances_by_one_millisecond() {
        let mut clock = SimClock::new();
        clock.tick();
        assert_eq!(clock.elapsed(), Duration::from_millis(1));
    }

    #[test]
    fn multiple_ticks_accumulate() {
        let mut clock = SimClock::new();
        for _ in 0..100 {
            clock.tick();
        }
        assert_eq!(clock.elapsed(), Duration::from_millis(100));
    }

    #[test]
    fn default_starts_at_zero() {
        let clock = SimClock::default();
        assert_eq!(clock.elapsed(), Duration::ZERO);
    }

    #[test]
    fn now_returns_correct_smoltcp_instant() {
        let mut clock = SimClock::new();
        clock.advance(Duration::from_secs(1));
        assert_eq!(clock.now(), Instant::from_millis(1000));
    }
}
