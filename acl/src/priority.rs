// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ACL rule priority.

use std::num::NonZero;

/// ACL rule priority.
///
/// Lower values are evaluated first (higher precedence).
/// Wraps [`NonZero<u32>`] because priority 0 is reserved by DPDK ACL
/// to indicate "no match."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Priority(NonZero<u32>);

/// Error constructing a [`Priority`] from zero.
#[derive(Debug, thiserror::Error)]
#[error("ACL priority must be non-zero (0 is reserved for 'no match')")]
pub struct PriorityZeroError;

impl Priority {
    /// Create a priority from a `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`PriorityZeroError`] if `value` is 0.
    pub const fn new(value: u32) -> Result<Self, PriorityZeroError> {
        match NonZero::new(value) {
            Some(nz) => Ok(Self(nz)),
            None => Err(PriorityZeroError),
        }
    }

    /// The underlying `u32` value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl From<Priority> for u32 {
    fn from(p: Priority) -> Self {
        p.get()
    }
}
