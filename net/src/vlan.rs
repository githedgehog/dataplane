// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VLAN validation and manipulation.

use core::num::NonZero;

use thiserror;

use tracing::instrument;

#[cfg(feature = "_no-panic")]
use no_panic::no_panic;

/// A VLAN Identifier.
///
/// This type is marked `#[repr(transparent)]` to ensure that it has the same memory layout
/// as a [`NonZero<u16>`].
/// This means that [`Option<Vid>`] should always have the same size and alignment as
/// [`Option<NonZero<u16>>`], and thus the same size and alignment as `u16`.
/// The memory / compute overhead of using this type as opposed to a `u16` is then strictly
/// limited to the price of checking that the represented value is in fact a legal [`Vid`]
/// (which we should generally be doing anyway).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(any(feature = "bolero", test, kani), derive(bolero::TypeGenerator))]
#[cfg_attr(kani, derive(kani::Arbitrary))]
// SAFETY: only use of unsafe is unrelated to deserialize logic
#[allow(clippy::unsafe_derive_deserialize)] 
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u16", into = "u16"))]
pub struct Vid(NonZero<u16>);

/// A Priority Code Point.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(any(test, kani), derive(bolero::TypeGenerator))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Pcp(pub u8);

/// Errors which can occur when converting a `u16` to a validated [`Vid`]
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[cfg_attr(any(test, kani), derive(bolero::TypeGenerator))]
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
    /// The value is too large to be a legal [`Vid`] (12-bit max).
    #[error("{0} is too large to be a legal Vid ({MAX} is max legal value)", MAX = Vid::MAX)]
    TooLarge(u16),
}

impl InvalidVid {
    /// The raw `u16` value of the reserved (4095) [`Vid`]
    pub const RESERVED: u16 = 4095;
    /// The raw `u16` value of the first truly nonsensical [`Vid`] (4096)
    pub const TOO_LARGE: u16 = Self::RESERVED + 1;
}

impl Vid {
    /// The minimum legal [`Vid`] value (1).
    #[allow(unsafe_code)] // safe due to const eval
    pub const MIN: Vid = Vid(unsafe { NonZero::new_unchecked(1) });

    /// The maximum legal [`Vid`] value (2^12 - 2).
    #[allow(unsafe_code)] // safe due to const eval
    pub const MAX: Vid = Vid(unsafe { NonZero::new_unchecked(4094) });

    /// Create a new [`Vid`] from a `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is 0, 4095 (reserved), or greater than [`Vid::MAX`].
    #[cfg_attr(feature = "_no-panic", no_panic)]
    #[instrument(level = "trace")]
    pub fn new(vid: u16) -> Result<Self, InvalidVid> {
        match NonZero::new(vid) {
            None => Err(InvalidVid::Zero),
            Some(val) if val.get() == InvalidVid::RESERVED => Err(InvalidVid::Reserved),
            Some(val) if val.get() > InvalidVid::RESERVED => Err(InvalidVid::TooLarge(val.get())),
            Some(val) => Ok(Vid(val)),
        }
    }

    /// Get the value of the [`Vid`] as a `u16`.
    #[cfg_attr(feature = "_no-panic", no_panic)]
    #[instrument(level = "trace")]
    #[must_use]
    pub fn to_u16(self) -> u16 {
        self.0.get()
    }
}

impl AsRef<NonZero<u16>> for Vid {
    #[cfg_attr(feature = "_no-panic", no_panic)]
    #[instrument(level = "trace")]
    fn as_ref(&self) -> &NonZero<u16> {
        &self.0
    }
}

impl From<Vid> for u16 {
    #[cfg_attr(feature = "_no-panic", no_panic)]
    #[instrument(level = "trace")]
    fn from(vid: Vid) -> u16 {
        vid.to_u16()
    }
}

impl TryFrom<u16> for Vid {
    type Error = InvalidVid;

    #[cfg_attr(feature = "_no-panic", no_panic)]
    #[instrument(level = "trace")]
    fn try_from(vid: u16) -> Result<Vid, Self::Error> {
        Vid::new(vid)
    }
}

impl core::fmt::Display for Vid {
    #[instrument(level = "trace", skip(f))]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_u16())
    }
}

#[cfg(any(test, kani))]
mod test {
    use super::*;
    use crate::vlan::Vid;
    #[cfg(any(kani, feature = "_proof"))]
    use kani::proof;

    #[test]
    #[cfg_attr(any(kani, feature = "_proof"), proof)]
    fn vlan_parse_contract() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|raw: u16| match Vid::new(raw) {
                Ok(vid) => {
                    assert_eq!(vid.to_u16(), raw);
                    assert!(vid >= Vid::MIN);
                    assert!(vid <= Vid::MAX);
                    assert!(vid.to_u16() >= Vid::MIN.to_u16());
                    assert!(vid.to_u16() <= Vid::MAX.to_u16());
                }
                Err(InvalidVid::Zero) => assert_eq!(raw, 0),
                Err(InvalidVid::Reserved) => assert_eq!(raw, 4095),
                Err(InvalidVid::TooLarge(x)) => {
                    assert_eq!(x, raw);
                    assert!(raw >= InvalidVid::TOO_LARGE);
                }
            });
    }
}
