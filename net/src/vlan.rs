// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VLAN validation and manipulation.

use core::num::NonZero;

use thiserror;

use tracing::instrument;

/// A VLAN Identifier.
///
/// This type is marked `#[repr(transparent)]` to ensure that it has the same memory layout
/// as a [`NonZero<u16>`].
/// This means that [`Option<Vid>`] should always have the same size and alignment as
/// [`Option<NonZero<u16>>`], and thus the same size and alignment as `u16`.
/// The memory / compute overhead of using this type as opposed to a `u16` is then strictly
/// limited to the price of checking that the represented value is in fact a legal [`Vid`]
/// (which we should generally be doing anyway).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Vid(NonZero<u16>);

/// A Priority Code Point.
pub struct Pcp(pub u8);

/// Errors which can occur when converting a `u16` to a validated [`Vid`]
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[must_use]
pub enum InvalidVid {
    /// 0 is a reserved [`Vid`] which basically means "the native vlan."
    /// 0 is not a legal [`Vid`] for Hedgehog's purposes.
    #[error("Zero is a reserved Vid")]
    Zero,
    /// 4095 is a reserved [`Vid`] per the spec.
    #[error("4095 is a reserved Vid")]
    Reserved,
    /// The value is too large to be a legal VID (max is 2^12).
    #[error("{0:?} is too large to be a legal Vid (max is 2^12)")]
    TooLarge(u16),
}

impl Vid {
    /// The minimum legal VID value (1).
    pub const MIN: u16 = 1;
    /// The maximum legal VID value (2^12 - 2).
    pub const MAX: u16 = 4094;
    /// The legal range of VID values.
    pub const LEGAL_RANGE: core::ops::RangeInclusive<u16> = Vid::MIN..=Vid::MAX;

    /// Create a new [`Vid`] from a `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is 0, 4095 (reserved), or greater than [`Vid::MAX`].
    #[instrument(level = "trace", ret)]
    pub fn new(vid: u16) -> Result<Self, InvalidVid> {
        match vid {
            4095 => Err(InvalidVid::Reserved),
            _ => match NonZero::<u16>::new(vid) {
                None => Err(InvalidVid::Zero),
                Some(val) => {
                    if val.get() > Vid::MAX {
                        Err(InvalidVid::TooLarge(val.get()))
                    } else {
                        Ok(Vid(val))
                    }
                }
            },
        }
    }

    /// Get the value of the [`Vid`] as a `u16`.
    #[instrument(level = "trace", ret)]
    #[must_use]
    pub fn as_u16(self) -> u16 {
        self.0.get()
    }
}

impl From<Vid> for u16 {
    #[instrument(level = "trace", ret)]
    fn from(vid: Vid) -> u16 {
        vid.as_u16()
    }
}

impl TryFrom<u16> for Vid {
    type Error = InvalidVid;

    #[instrument(level = "trace", ret)]
    fn try_from(vid: u16) -> Result<Vid, Self::Error> {
        Vid::new(vid)
    }
}

impl core::fmt::Display for Vid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_u16())
    }
}
