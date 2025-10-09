// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv4` checksum type and methods

use crate::checksum::Checksum;
use crate::icmp4::Icmp4;
use core::fmt::{Display, Formatter};
use std::fmt::Debug;

/// A icmp [checksum]
///
/// [checksum]: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Icmp4Checksum(pub(crate) u16);

impl Display for Icmp4Checksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06X}", self.0)
    }
}

impl Icmp4Checksum {
    /// Map a raw value to a [`Icmp4Checksum`]
    #[must_use]
    pub const fn new(raw: u16) -> Icmp4Checksum {
        Icmp4Checksum(raw)
    }
}

impl AsRef<u16> for Icmp4Checksum {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for Icmp4Checksum {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for Icmp4Checksum {
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<Icmp4Checksum> for u16 {
    fn from(checksum: Icmp4Checksum) -> Self {
        checksum.0
    }
}

impl Checksum for Icmp4 {
    type Payload<'a> = [u8];
    type Checksum = Icmp4Checksum;

    /// Get the [`Icmp4`] checksum of the header
    fn checksum(&self) -> Icmp4Checksum {
        Icmp4Checksum(self.0.checksum)
    }

    /// Compute the icmp v4 header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    fn compute_checksum(&self, payload: &[u8]) -> Icmp4Checksum {
        Icmp4Checksum(self.0.icmp_type.calc_checksum(payload))
    }

    /// Set the checksum field of the header
    fn set_checksum(&mut self, checksum: Icmp4Checksum) -> &mut Self {
        self.0.checksum = checksum.0;
        self
    }
}
