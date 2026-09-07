// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The one place the dataplane reads the time.
//!
//! Every clock read goes through [`now`] rather than [`std::time::Instant::now`],
//! and an opengrep rule enforces it. The point is that a test can then *drive*
//! time instead of waiting for it: with the `virtual` feature the reads come
//! from a paused tokio clock a test advances by hand, so a property about
//! expiry, smoothing or timeout is decided rather than raced.
//!
//! The re-exports below are deliberate. Code says `clock::Instant`, so pointing
//! the facade at a different source is a change here rather than a sweep of
//! every call site.

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

/// How long since `anchor`, read through the facade.
///
/// `anchor.elapsed()` is the obvious spelling and it is the one thing this crate
/// exists to stop: `Instant::elapsed` is `std::time::Instant::now() - self`, so it
/// reads `std` no matter where the anchor came from. Under the `virtual` feature
/// that is not merely a clock that fails to follow -- the anchor is a tokio
/// instant and the subtrahend is a wall instant, so the result saturates to zero
/// and stays there, and a paused-clock test of anything gated on it proves
/// nothing while appearing to pass.
///
/// Saturating rather than panicking, because a caller asking "how long since" has
/// nothing useful to do with a backwards clock.
#[must_use]
pub fn elapsed(anchor: Instant) -> Duration {
    now().saturating_duration_since(anchor)
}

#[must_use]
pub fn checked_now() -> Option<Instant> {
    #[cfg(all(feature = "virtual", not(wall_clock)))]
    {
        if virtual_time::armed() {
            match tokio::runtime::Handle::try_current() {
                // A runtime of this thread's own, and one of the paused worlds it is
                // inside: same timeline, so the read stands.
                Ok(handle) if virtual_time::is_a_paused_runtime(handle.id()) => {}
                // A runtime, but not one of them. `tokio::time::Instant::now()` would
                // answer from *that* runtime -- the wall clock, if it is not paused --
                // while every deadline around it came from the paused one. Asking "is
                // there a runtime" instead of "is it this world's" is how a read an hour
                // out of step gets accepted.
                Ok(_) => return None,
                // No context of this thread's own -- but the spawn hook may have
                // handed it the driving one, and reading through that is the same
                // timeline. Anything else here is not, so `None` means refuse.
                Err(_) => return virtual_time::read_inherited(),
            }
        }
        Some(tokio::time::Instant::now().into_std())
    }
    #[cfg(not(all(feature = "virtual", not(wall_clock))))]
    {
        Some(Instant::now())
    }
}

#[must_use]
pub const fn is_routed() -> bool {
    cfg!(all(feature = "virtual", not(wall_clock)))
}

#[must_use]
pub fn elapsed_since_first_reading() -> Option<(bool, Duration)> {
    // nosemgrep: rust-no-direct-std-sync-import
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let reading = checked_now()?;
    let origin = *ORIGIN.get_or_init(|| reading);
    Some(if reading >= origin {
        (false, reading.saturating_duration_since(origin))
    } else {
        (true, origin.saturating_duration_since(reading))
    })
}

#[must_use]
pub fn system_now() -> SystemTime {
    SystemTime::now()
}

/// One section per *process*, so plain `#[test]`s do not race each other's global state.
///
/// Deliberately `process_global`, not [`concurrency::sync`]. A facade primitive belongs to the
/// model-checker execution that created it, and a `static` outlives every execution: under
/// shuttle the second touch aborts with `ExecutionState is not set`, which is what eleven of
/// this crate's twelve tests did. Nothing here asks for shuttle -- it arrives by feature
/// unification from `dataplane/shuttle -> concurrency/shuttle`.
///
/// The facade was reached for in the first place because `Mutex::new` is not `const fn` under
/// loom or shuttle, so the in-place `static` form stops compiling. `process_global::Mutex::new`
/// is `const fn`, so no `LazyLock` wrapper is needed either -- and the wrapper was what turned
/// a compile error into a runtime one.
///
/// `clippy::disallowed_types` resolves through the re-export to `std::sync::Mutex`, so the
/// allowance cannot live on the re-export and has to be here.
#[cfg(test)]
#[allow(clippy::disallowed_types)]
pub(crate) fn serially() -> concurrency::process_global::MutexGuard<'static, ()> {
    static SERIAL: concurrency::process_global::Mutex<()> =
        concurrency::process_global::Mutex::new(());
    SERIAL
        .lock()
        .unwrap_or_else(concurrency::process_global::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::serially;
    use super::{Duration, now, system_now};

    #[test]
    fn now_is_monotonic() {
        let _serial = serially();
        let first = now();
        let second = now();
        assert!(second >= first, "the monotonic clock went backwards");
    }

    #[test]
    fn now_works_with_no_runtime() {
        let _serial = serially();
        let _ = now();
        let _ = system_now();
    }

    /// The claim every paused-clock test in the workspace rests on.
    ///
    /// Worth having *here* rather than inferring it from a NAT or routing test:
    /// a regression -- a tokio bump that changes `into_std`, someone re-pointing
    /// the facade -- otherwise surfaces several crates away as a mysterious
    /// expiry failure rather than as a clock failure.
    #[test]
    #[cfg(all(feature = "virtual", not(wall_clock)))]
    fn now_follows_a_paused_clock() {
        let _serial = serially();
        let clock = super::virtual_time::Paused::new();
        clock.block_on(async {
            let before = now();
            super::virtual_time::advance(Duration::from_hours(1)).await;
            assert_eq!(
                now().saturating_duration_since(before),
                Duration::from_hours(1),
                "the facade did not follow the clock it is pointed at"
            );
            assert_eq!(
                super::elapsed(before),
                Duration::from_hours(1),
                "`elapsed` did not follow the clock `now` follows"
            );
        });
    }

    #[test]
    fn durations_are_plain_values() {
        assert_eq!(Duration::from_secs(1).as_millis(), 1000);
    }
}
