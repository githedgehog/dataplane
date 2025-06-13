// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! UDP checksum type and methods

use core::fmt::{Display, Formatter};

/// A [`Udp`] [checksum]
///
/// [checksum]: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
/// [`Udp`]: crate::udp::Udp
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct UdpChecksum(pub(crate) u16);

impl Display for UdpChecksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#04x}", self.0)
    }
}

impl UdpChecksum {
    /// Map a raw value to a [`UdpChecksum`]
    #[must_use]
    pub const fn new(raw: u16) -> UdpChecksum {
        UdpChecksum(raw)
    }
}

impl AsRef<u16> for UdpChecksum {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for UdpChecksum {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for UdpChecksum {
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<UdpChecksum> for u16 {
    fn from(checksum: UdpChecksum) -> Self {
        checksum.0
    }
}
