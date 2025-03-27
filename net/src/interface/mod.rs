// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Data structures and methods for interacting with / describing network interfaces

use std::fmt::{Debug, Display, Formatter};

/// A network interface id (also known as ifindex in linux).
///
/// These are 32 bit values which are generally assigned by the linux kernel.
/// You can't generally meaningfully persist or assign them.
/// They don't typically mean anything "between" machines or even reboots.
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u32", into = "u32")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceIndex(u32);

impl Debug for InterfaceIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Debug>::fmt(&self.0, f)
    }
}

impl Display for InterfaceIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Display>::fmt(&self.0, f)
    }
}

impl InterfaceIndex {
    /// Treat the provided `u32` as an [`InterfaceIndex`].
    #[must_use]
    pub fn new(raw: u32) -> InterfaceIndex {
        InterfaceIndex(raw)
    }

    /// Treat this [`InterfaceIndex`] as a `u32`.
    #[must_use]
    pub fn to_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for InterfaceIndex {
    fn from(value: u32) -> InterfaceIndex {
        InterfaceIndex::new(value)
    }
}

impl From<InterfaceIndex> for u32 {
    fn from(value: InterfaceIndex) -> Self {
        value.to_u32()
    }
}
