// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backend-routed clock for the dataplane workspace.
//!
//! One place the workspace reads the time, so that a test can control it. The shape follows
//! [`concurrency`][concurrency], which routes synchronization primitives to `parking_lot` in
//! production and to a model checker under a feature; this routes the monotonic clock to `std` in
//! production and to tokio's pausable clock under the `virtual` feature.
//!
//! [concurrency]: https://docs.rs/dataplane-concurrency
//!
//! # Why this exists
//!
//! Anything with a timeout is untestable in a useful way if its deadline comes from the wall clock:
//! the test either sleeps for real -- seconds of CI time per case, and flaky under emulation -- or
//! it does not test expiry at all. The flow table's expiry, the masquerade and port-forwarding
//! timeouts, the stats delivery schedule and the FRR reconnect timers are all in that position.
//!
//! tokio can already pause and advance time, and the dataplane already runs on tokio. What stopped
//! that from working was an asymmetry: **the waits were on tokio's clock and the deadlines were on
//! `std`'s.**
//!
//! ```text
//! deadline = std::time::Instant::now() + timeout     // does not move when a test advances time
//! sleep_until(tokio::time::Instant::from_std(deadline))  // does move
//! ```
//!
//! Those agree at the moment a test pauses the clock and diverge immediately after, so a paused
//! clock bought exactly one time step: anything created after the first `advance` was born with a
//! deadline already in the past. Reading the clock here fixes that, because [`now`] follows whatever
//! clock the timers are following.
//!
//! # What needs routing, and what does not
//!
//! * **[`now`] does.** It is the only way to read the monotonic clock.
//! * **[`Duration`] does not.** A duration is a plain value with no clock in it -- `Duration::from_secs(5)`
//!   means the same thing under any clock. It is re-exported here for convenience only, and the lint
//!   does not ask for it.
//! * **Timers do not.** `tokio::time::sleep` and friends are already on tokio's clock, so they are
//!   already controllable. `std::thread::sleep` is not, and a blocking sleep in async code is a
//!   separate bug from this one.
//! * **[`system_now`] cannot be.** See below.
//!
//! # The lint is the point
//!
//! A facade nobody is obliged to use decays: the next `std::time::Instant::now()` compiles, passes
//! review, and then some unrelated timeout test starts behaving strangely under a paused clock. So
//! `.semgrep/rules/no-std-time-direct.yaml` refuses direct clock reads outside this crate, the same
//! way `no-std-sync-direct.yaml` refuses direct `std::sync` imports.

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![deny(unsafe_code)]

pub use std::time::{Duration, Instant, SystemTime, SystemTimeError, TryFromFloatSecsError};

/// The current instant on the monotonic clock.
///
/// Production reads `std::time::Instant::now()`. Under the `virtual` feature it reads tokio's clock,
/// which is the same clock until a test calls `tokio::time::pause` (or uses
/// `#[tokio::test(start_paused = true)]`), and thereafter is whatever that test has advanced it to.
///
/// Safe to call with no tokio runtime in scope, and cheap: tokio's routed read is a single relaxed
/// atomic load until something in the process actually pauses the clock, and falls back to the real
/// clock on any thread with no clock installed.
#[must_use]
pub fn now() -> Instant {
    #[cfg(feature = "virtual")]
    {
        tokio::time::Instant::now().into_std()
    }
    #[cfg(not(feature = "virtual"))]
    {
        Instant::now()
    }
}

/// The current wall-clock time.
///
/// **Not routed, and cannot be.** tokio pauses its monotonic clock, not the system clock, and
/// nothing in the workspace would be well served by a fake `SystemTime` -- the values that use it are
/// timestamps reported outwards (a configuration's creation and application times, the router's
/// synchronization timestamp), not deadlines anything waits on.
///
/// It lives here anyway so that the lint can name a single chokepoint for reading a clock of any
/// kind. If a test ever does need to control wall-clock time, this is where that would go, and the
/// call sites will not have to move.
#[must_use]
pub fn system_now() -> SystemTime {
    SystemTime::now()
}

#[cfg(test)]
mod tests {
    use super::{Duration, now, system_now};

    /// The clock moves forward, whichever backend is routed.
    #[test]
    fn now_is_monotonic() {
        let first = now();
        let second = now();
        assert!(second >= first, "the monotonic clock went backwards");
    }

    /// Reading the clock off a tokio runtime is legal under either backend.
    ///
    /// Worth pinning: most of the workspace's tests have no runtime, and a routed read that panicked
    /// without one would make this facade unusable in exactly the places it is meant to be invisible.
    #[test]
    fn now_works_with_no_runtime() {
        let _ = now();
        let _ = system_now();
    }

    /// A duration is a value, not a clock reading, and is unaffected by routing.
    #[test]
    fn durations_are_plain_values() {
        assert_eq!(Duration::from_secs(1).as_millis(), 1000);
    }
}
