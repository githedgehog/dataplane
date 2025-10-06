// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic, clippy::unwrap_used)]

use std::num::NonZero;

pub mod group;
pub mod mem;

/// A non-zero byte count used throughout the crate for memory sizes.
///
/// Using `NonZero` ensures that zero-byte sizes are not representable,
/// which helps catch errors at compile time.
pub type ByteCount = NonZero<usize>;
