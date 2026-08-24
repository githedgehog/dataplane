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

// Mirrors the cfg on `virtual_time::inherit_across_spawns`, which is the only user: declaring the
// feature in a build that has no routed clock is an unused-feature warning.
#![cfg_attr(
    all(has_spawn_hook, feature = "virtual", not(wall_clock)),
    feature(thread_spawn_hook)
)]
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
/// Under the `virtual` feature, if this thread is inside a [`virtual_time::Paused`]'s world and has
/// no runtime context -- the read would answer from the wall clock while the rest of the test is an
/// hour ahead. A thread spawned with `std::thread` inherits both, so reaching this means the thread
/// came from somewhere else. A thread outside the world is not checked at all.
#[must_use]
pub fn now() -> Instant {
    #[cfg(all(feature = "virtual", not(wall_clock)))]
    {
        checked_now().unwrap_or_else(|| virtual_time::refuse())
    }
    #[cfg(not(all(feature = "virtual", not(wall_clock))))]
    {
        Instant::now()
    }
}

/// [`now`], or `None` where [`now`] would refuse.
///
/// For the readers that must not fail: a log timestamp, a metric label, anything whose job is to
/// describe what happened rather than to decide something. For those, "this thread cannot see the
/// clock the test is driving" is an answer worth printing, and a panic in the middle of formatting a
/// log line would replace the diagnostic with a worse one.
///
/// Everything that compares against a deadline wants [`now`] instead. A `None` silently treated as
/// "no timeout" is the class of bug this whole facade exists to prevent.
#[must_use]
pub fn checked_now() -> Option<Instant> {
    #[cfg(all(feature = "virtual", not(wall_clock)))]
    {
        // One atomic load when nothing is paused, which is every read in every test that does not
        // drive the clock.
        if virtual_time::armed() && tokio::runtime::Handle::try_current().is_err() {
            return None;
        }
        Some(tokio::time::Instant::now().into_std())
    }
    #[cfg(not(all(feature = "virtual", not(wall_clock))))]
    {
        Some(Instant::now())
    }
}

/// Whether [`now`] follows a clock a test can drive.
///
/// `false` in production and under `--cfg wall_clock`. A caller wants this to decide how to *render*
/// a time, not whether to read one -- see [`elapsed_since_first_reading`].
#[must_use]
pub const fn is_routed() -> bool {
    cfg!(all(feature = "virtual", not(wall_clock)))
}

/// How far the clock has moved since the first time this was called.
///
/// A stamp for logs, where the useful question under a driven clock is "how far into the test is
/// this line" rather than what the wall says. `None` on a thread that cannot see the driven clock,
/// which is worth rendering as such rather than being papered over with a wall reading from a
/// different timeline.
///
/// Signed, because the origin is the first reading and a *second* paused section in the same process
/// starts behind it. `cargo nextest` gives each test its own process, so there is one section and
/// the offsets count up from zero; under a shared process they can go negative, which is at least
/// visibly odd rather than silently floored to zero.
#[must_use]
pub fn elapsed_since_first_reading() -> Option<(bool, Duration)> {
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let reading = checked_now()?;
    let origin = *ORIGIN.get_or_init(|| reading);
    Some(if reading >= origin {
        (false, reading.saturating_duration_since(origin))
    } else {
        (true, origin.saturating_duration_since(reading))
    })
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
/// Not a general facility. It is here because these tests contend for `LIVE`, which is process-wide
/// -- one test dropping its clock while another still holds one would disarm the check underneath
/// it. `cargo nextest` gives each test its own process and would not need this; the crate's own
/// tests should pass under the plain runner too, so they take turns.
///
/// **Every test in this crate that reads a clock takes it**, driving or not.
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
