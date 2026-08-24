// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

#[must_use]
pub fn checked_now() -> Option<Instant> {
    #[cfg(all(feature = "virtual", not(wall_clock)))]
    {
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
    static SERIAL: concurrency::sync::Mutex<()> = concurrency::sync::Mutex::new(());
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

    #[test]
    fn durations_are_plain_values() {
        assert_eq!(Duration::from_secs(1).as_millis(), 1000);
    }
}
