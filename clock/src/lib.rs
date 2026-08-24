// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A clock facade that lets tests control time without changing production call sites.

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

/// Get the elapsed time since `anchor`
///
/// `anchor.elapsed()` is the obvious spelling for this, but this crate exists
/// to provide an abstraction for that method so we can have virtual clocks
/// for tests and other purposes.  Without it, `anchor.elapsed()` returns the
/// wrong thing and tests pass without having tested anything.
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
        if virtual_time::armed() && tokio::runtime::Handle::try_current().is_err() {
            // No context of this thread's own -- but the spawn hook may have
            // handed it the driving one, and reading through that is the same
            // timeline. Anything else here is not, so `None` means refuse.
            return virtual_time::read_inherited();
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

#[cfg(test)]
pub(crate) fn serially() -> concurrency::sync::MutexGuard<'static, ()> {
    // Lazily, not `static SERIAL: Mutex<()> = Mutex::new(())`. The facade's
    // `Mutex::new` is not `const fn` under loom or shuttle -- `concurrency::sync`
    // says so in its own module docs -- so the in-place form stops compiling the
    // moment the workspace is built with `--features shuttle`. Nothing in this
    // crate asks for shuttle; it arrives by feature unification from
    // `dataplane/shuttle -> concurrency/shuttle`, and `clock` depends on
    // `concurrency`. That is why `just shuttle` never got as far as running.
    static SERIAL: concurrency::sync::LazyLock<concurrency::sync::Mutex<()>> =
        concurrency::sync::LazyLock::new(|| concurrency::sync::Mutex::new(()));
    SERIAL.lock()
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
