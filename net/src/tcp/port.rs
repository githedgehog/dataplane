// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::num::NonZero;

#[repr(transparent)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[allow(clippy::unsafe_derive_deserialize)] // both try_from and into u16 are safe for this type
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u16", into = "u16")]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct TcpPort(NonZero<u16>);

#[repr(transparent)]
#[derive(
    Copy,
    Clone,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Debug,
    thiserror::Error,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum TcpPortError {
    #[error("port must be non-zero")]
    Zero,
}

impl TcpPort {
    /// Create a [`TcpPort`].
    pub const fn new(port: NonZero<u16>) -> TcpPort {
        TcpPort(port)
    }

    /// Create a [`TcpPort`].
    ///
    /// # Error
    ///
    /// Will return an error if the submitted raw port number is zero.
    pub const fn new_checked(port: u16) -> Result<TcpPort, TcpPortError> {
        match NonZero::new(port) {
            None => Err(TcpPortError::Zero),
            Some(port) => Ok(TcpPort(port)),
        }
    }

    /// Create a [`TcpPort`] without checking that the port is non-zero
    ///
    /// # Safety
    ///
    /// It is the caller's responsibility to ensure that the port is non-zero.
    /// Submitting a zero value as port is undefined behavior.
    #[allow(unsafe_code)]
    pub const unsafe fn new_unchecked(port: u16) -> TcpPort {
        TcpPort(unsafe { NonZero::new_unchecked(port) })
    }

    /// Get the value of a [`TcpPort`] as a u16
    #[must_use]
    pub fn as_u16(self) -> u16 {
        self.0.get()
    }
}

impl From<TcpPort> for u16 {
    fn from(port: TcpPort) -> Self {
        port.0.get()
    }
}

impl TryFrom<u16> for TcpPort {
    type Error = TcpPortError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new_checked(value)
    }
}
