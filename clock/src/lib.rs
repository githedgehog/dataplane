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
//! # One clock, and a check that says so
//!
//! tokio's clock is per *runtime*, and reading it goes through the calling thread's runtime
//! context -- so a second runtime is a second timeline, and a thread with **no** runtime silently
//! answers from the wall clock. Measured: after a one-hour advance an unentered thread reads an
//! hour behind an entered one, and it is the unentered one that looks normal.
//!
//! [`virtual_time`] is therefore the only way a test drives this clock: one
//! [`virtual_time::Paused`] per property, its handle threaded to every thread that reads a clock,
//! and while one is alive [`now`] panics on a thread with no runtime context rather than answering
//! from the wrong timeline. See that module for the reasoning and for the one false positive it
//! accepts.
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

#[cfg(feature = "virtual")]
pub mod virtual_time;

/// The current instant on the monotonic clock.
///
/// Production reads `std::time::Instant::now()`. Under the `virtual` feature it reads tokio's clock,
/// which is the same clock until a test calls `tokio::time::pause` (or uses
/// `#[tokio::test(start_paused = true)]`), and thereafter is whatever that test has advanced it to.
///
/// Cheap: tokio's routed read is a single relaxed atomic load until something in the process
/// actually pauses the clock.
///
/// # Panics
///
/// Under the `virtual` feature, if a [`virtual_time::Paused`] is alive and this thread has no
/// runtime context. Without one the read would answer from the wall clock while the rest of the
/// test is an hour ahead, so it is refused loudly instead. With no `Paused` alive -- which is every
/// test that does not drive the clock -- calling this without a runtime is fine.
#[must_use]
pub fn now() -> Instant {
    #[cfg(all(feature = "virtual", not(wall_clock)))]
    {
        // One relaxed-ish load when nothing is paused, which is every read in every test that does
        // not drive the clock. The arm that panics is out of line -- see `virtual_time::refuse`.
        if virtual_time::armed() && tokio::runtime::Handle::try_current().is_err() {
            virtual_time::refuse();
        }
        tokio::time::Instant::now().into_std()
    }
    #[cfg(not(all(feature = "virtual", not(wall_clock))))]
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

/// Serializes this crate's own tests against each other.
///
/// Not a general facility -- callers get process isolation from `cargo nextest` instead. It is here
/// because this crate is the worst case for the false positive [`refuse`] accepts: a third of its
/// tests pause the clock, so under the plain `cargo test` runner an innocent reader landed inside a
/// paused section about three runs in ten. Measured, which is why this exists.
///
/// **Every test in this crate that reads a clock takes it**, driving or not. That is the whole rule,
/// and it is why this is `pub(crate)` rather than private to the module below.
#[cfg(test)]
pub(crate) fn serially() -> concurrency::sync::MutexGuard<'static, ()> {
    static SERIAL: concurrency::sync::Mutex<()> = concurrency::sync::Mutex::new(());
    // `concurrency::sync` rather than `std::sync`, which `clippy.toml` disallows workspace-wide, and
    // which would need poison handling here because one of these tests panics by design.
    SERIAL.lock()
}

#[cfg(test)]
mod tests {
    use super::serially;
    use super::{Duration, now, system_now};

    /// The clock moves forward, whichever backend is routed.
    #[test]
    fn now_is_monotonic() {
        let _serial = serially();
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
        let _serial = serially();
        let _ = now();
        let _ = system_now();
    }

    /// A duration is a value, not a clock reading, and is unaffected by routing.
    #[test]
    fn durations_are_plain_values() {
        assert_eq!(Duration::from_secs(1).as_millis(), 1000);
    }
}
