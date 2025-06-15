// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! TCP checksum type and methods

use core::fmt::{Display, Formatter};

/// A [`Tcp`] [checksum]
///
/// [checksum]: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct TcpChecksum(pub(crate) u16);

impl Display for TcpChecksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#04x}", self.0)
    }
}

impl TcpChecksum {
    /// Map a raw value to a [`TcpChecksum`]
    #[must_use]
    pub const fn new(raw: u16) -> TcpChecksum {
        TcpChecksum(raw)
    }
}

impl AsRef<u16> for TcpChecksum {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for TcpChecksum {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for TcpChecksum {
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<TcpChecksum> for u16 {
    fn from(checksum: TcpChecksum) -> Self {
        checksum.0
    }
}
