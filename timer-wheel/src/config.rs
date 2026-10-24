// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::num::NonZeroU32;
use std::time::Duration;

/// The shape of a [`Wheel`](crate::Wheel): how long a tick is and how many buckets there are.
///
/// Timers fire up to one `tick` late. A wheel spans `tick * slots`; deadlines further out are
/// revisited once per revolution until they come into range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WheelConfig {
    tick: Duration,
    slots: NonZeroU32,
}

/// Why a [`WheelConfig`] was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A tick must be at least a nanosecond.
    #[error("the tick must be at least 1 ns, got {0:?}")]
    TickTooShort(Duration),
    /// The wheel needs at least two buckets (one being swept, one to move entries to).
    #[error("the wheel needs at least 2 slots, got {0}")]
    TooFewSlots(u32),
    /// Bucket indices must fit below the slab's sentinel.
    #[error("the wheel can have at most {max} slots, got {0}", max = WheelConfig::MAX_SLOTS)]
    TooManySlots(u32),
}

impl WheelConfig {
    /// The largest number of buckets.
    pub const MAX_SLOTS: u32 = 1 << 24;

    /// 10 ms ticks, 8192 buckets: a span of about 82 s.
    // Both values are in range.
    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn standard() -> Self {
        Self::new(Duration::from_millis(10), 8192).expect("valid")
    }

    /// A wheel shape.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] if `tick` is zero or `slots` is outside `2..=MAX_SLOTS`.
    pub fn new(tick: Duration, slots: u32) -> Result<Self, ConfigError> {
        if tick.is_zero() {
            return Err(ConfigError::TickTooShort(tick));
        }
        if slots < 2 {
            return Err(ConfigError::TooFewSlots(slots));
        }
        if slots > Self::MAX_SLOTS {
            return Err(ConfigError::TooManySlots(slots));
        }
        let slots = NonZeroU32::new(slots).ok_or(ConfigError::TooFewSlots(slots))?;
        Ok(Self { tick, slots })
    }

    /// How long a tick is.
    #[must_use]
    pub fn tick(&self) -> Duration {
        self.tick
    }

    /// How many buckets the wheel has.
    #[must_use]
    pub fn slots(&self) -> u32 {
        self.slots.get()
    }

    pub(crate) fn slots_usize(&self) -> usize {
        self.slots.get() as usize
    }

    pub(crate) fn tick_nanos(&self) -> u128 {
        self.tick.as_nanos()
    }
}
