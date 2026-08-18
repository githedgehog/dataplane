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

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![deny(unsafe_code)]

pub use std::time::{Duration, Instant, SystemTime, SystemTimeError, TryFromFloatSecsError};

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
pub fn system_now() -> SystemTime {
    SystemTime::now()
}

#[cfg(test)]
mod tests {
    use super::{Duration, now, system_now};

    #[test]
    fn now_is_monotonic() {
        let first = now();
        let second = now();
        assert!(second >= first, "the monotonic clock went backwards");
    }

    #[test]
    fn now_works_with_no_runtime() {
        let _ = now();
        let _ = system_now();
    }

    #[test]
    fn durations_are_plain_values() {
        assert_eq!(Duration::from_secs(1).as_millis(), 1000);
    }
}
