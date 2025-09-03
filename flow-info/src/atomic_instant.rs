// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use atomic_instant_full;
use std::fmt::{Debug, Formatter};
use std::ops::Deref;
use std::sync::atomic::Ordering;
use std::time::Instant;

#[repr(transparent)]
pub struct AtomicInstant(atomic_instant_full::AtomicInstant);

impl Debug for AtomicInstant {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?})", self.0.load(Ordering::Relaxed))
    }
}

impl Deref for AtomicInstant {
    type Target = atomic_instant_full::AtomicInstant;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AtomicInstant {
    #[must_use]
    pub fn new(instant: Instant) -> Self {
        Self(atomic_instant_full::AtomicInstant::new(instant))
    }
}
