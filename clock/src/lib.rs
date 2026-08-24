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
