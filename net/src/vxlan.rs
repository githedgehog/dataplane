// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! VXLAN validation and manipulation.

use core::num::NonZero;
use tracing::instrument;

/// A VXLAN Network Identifier.
///
/// The [`Vni`] is a 24-bit value that identifies a VXLAN network.
///
/// Value 0 is reserved and should not be used.
/// The maximum legal value is 2^24 - 1 (16,777,215).
///
/// It is deliberately not possible to create a [`Vni`] from a `u32` directly, as this would
/// allow the creation of illegal values.
/// Instead, use [`Vni::new`] to create a [`Vni`] from a `u32`.
///
/// # Note
///
/// This type is marked `#[repr(transparent)]` to ensure that it has the same memory layout
/// as a [`NonZero<u32>`].
/// This means that [`Option<Vni>`] will always have the same size and alignment as
/// [`Option<NonZero<u32>>`], and thus the same size and alignment as `u32`.
/// The memory / compute overhead of using this type as opposed to a `u32` is then strictly
/// limited to the price of checking that the represented value is in fact a legal [`Vni`], (which
/// we should generally be doing anyway).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Vni(NonZero<u32>);

#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[must_use]
/// Errors that can occur when converting a `u32` to a [`Vni`]
pub enum InvalidVni {
    /// Zero is not a legal [`Vni`] per the spec.
    ReservedZero,
    /// The value is too large to be a [`Vni`] (max is 2^24 - 1, see [`Vni::MAX`]).
    TooLarge(u32),
}

impl core::fmt::Display for InvalidVni {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            InvalidVni::ReservedZero => {
                write!(f, "Zero is not a legal Vni")
            }
            InvalidVni::TooLarge(val) => {
                write!(f, "{val} is too large to be a legal Vni (max is 2^24)")
            }
        }
    }
}

impl Vni {
    /// The minimum legal [`Vni`] value (1).
    pub const MIN: u32 = 1;
    /// The maximum legal [`Vni`] value (2^24 - 1).
    pub const MAX: u32 = 0x00_FF_FF_FF;
    /// The (inclusive legal range of [`Vni`] values.
    pub const LEGAL_RANGE: core::ops::RangeInclusive<u32> = Vni::MIN..=Vni::MAX;

    #[instrument(level = "trace")]
    /// Create a new [`Vni`] from a `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is 0 or greater than [`Vni::MAX`].
    pub fn new(vni: u32) -> Result<Vni, InvalidVni> {
        match NonZero::<u32>::new(vni) {
            None => Err(InvalidVni::ReservedZero),
            Some(vni) => {
                if vni.get() > Vni::MAX {
                    Err(InvalidVni::TooLarge(vni.get()))
                } else {
                    Ok(Vni(vni))
                }
            }
        }
    }

    #[must_use]
    /// Get the value of the [`Vni`] as a `u32`.
    pub const fn as_u32(self) -> u32 {
        self.0.get()
    }
}

impl From<Vni> for u32 {
    #[instrument(level = "trace")]
    fn from(vni: Vni) -> u32 {
        vni.as_u32()
    }
}

impl TryFrom<u32> for Vni {
    type Error = InvalidVni;

    #[instrument(level = "trace")]
    fn try_from(vni: u32) -> Result<Vni, Self::Error> {
        Vni::new(vni)
    }
}

impl core::fmt::Display for Vni {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}", self.as_u32())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod test {

    use super::*;

    #[test]
    fn fuzz_test() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|val: u32| match val {
                0 => {
                    assert_eq!(Vni::new(val).unwrap_err(), InvalidVni::ReservedZero);
                }
                val if val > Vni::MAX => {
                    assert_eq!(Vni::new(val).unwrap_err(), InvalidVni::TooLarge(val));
                }
                _ => {
                    assert_eq!(Vni::new(val).unwrap().as_u32(), val);
                }
            });
    }
}
