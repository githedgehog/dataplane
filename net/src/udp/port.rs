// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! UDP port type and parsing logic.

use std::num::NonZero;

/// Transparent wrapper type for udp ports.
///
/// Zero overhead beyond that imposed by `NonZero<u16>`, i.e., only the non-zero check, which is
/// required anyway.
#[repr(transparent)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[allow(clippy::unsafe_derive_deserialize)] // both try_from and into u16 are safe for this type
#[derive(
    Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "u16", into = "u16")]
pub struct UdpPort(NonZero<u16>);

/// Errors which may occur in the creation or parsing of a [`UdpPort`].
#[repr(transparent)]
#[derive(
    Debug,
    thiserror::Error,
    serde::Serialize,
    serde::Deserialize,
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
)]
pub enum UdpPortError {
    /// The spec reserves zero to mean "any port."  It isn't valid in the context of a packet parser.
    #[error("port must be non-zero")]
    Zero,
}

impl UdpPort {
    /// Create a [`UdpPort`].
    #[must_use]
    pub const fn new(port: NonZero<u16>) -> UdpPort {
        UdpPort(port)
    }

    /// Create a [`UdpPort`].
    ///
    /// # Errors
    ///
    /// Will return an error if the submitted raw port number is zero.
    pub const fn new_checked(port: u16) -> Result<UdpPort, UdpPortError> {
        match NonZero::new(port) {
            None => Err(UdpPortError::Zero),
            Some(port) => Ok(UdpPort(port)),
        }
    }

    /// Create a [`UdpPort`] without checking that the port is non-zero
    ///
    /// # Safety
    ///
    /// It is the caller's responsibility to ensure the port is non-zero.
    /// It is undefined behavior to submit a zero value here.
    #[must_use]
    #[allow(unsafe_code)] // safety requirements documented
    pub const unsafe fn new_unchecked(port: u16) -> UdpPort {
        UdpPort(unsafe { NonZero::new_unchecked(port) })
    }

    /// Get the value of a [`UdpPort`] as a u16
    #[must_use]
    pub fn as_u16(self) -> u16 {
        self.0.get()
    }
}

impl From<UdpPort> for u16 {
    fn from(port: UdpPort) -> Self {
        port.0.get()
    }
}

impl TryFrom<u16> for UdpPort {
    type Error = UdpPortError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new_checked(value)
    }
}

impl From<UdpPort> for NonZero<u16> {
    fn from(port: UdpPort) -> Self {
        port.0
    }
}
