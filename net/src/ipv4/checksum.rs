// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::checksum::Checksum;
use crate::ipv4::Ipv4;
use std::fmt::{Display, Formatter};

/// A [`Ipv4`] checksum
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Ipv4Checksum(u16);

impl Display for Ipv4Checksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06X}", self.0)
    }
}

impl Ipv4Checksum {
    /// Map a raw value to a [`Ipv4Checksum`]
    #[must_use]
    pub const fn new(raw: u16) -> Ipv4Checksum {
        Ipv4Checksum(raw)
    }
}

impl AsRef<u16> for Ipv4Checksum {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for Ipv4Checksum {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for Ipv4Checksum {
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<Ipv4Checksum> for u16 {
    fn from(checksum: Ipv4Checksum) -> Self {
        checksum.0
    }
}

impl Checksum for Ipv4 {
    type Error = ();
    type Payload<'a>
        = ()
    where
        Self: 'a;
    type Checksum = Ipv4Checksum;

    /// Get the [`Ipv4`] checksum of the header
    ///
    /// # Returns
    ///
    /// Always returns `Some`.
    fn checksum(&self) -> Option<Ipv4Checksum> {
        Some(Ipv4Checksum(self.0.header_checksum))
    }

    /// Compute the ipv4 header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// Always returns `Ok`.
    fn compute_checksum(
        &self,
        _payload: &Self::Payload<'_>,
    ) -> Result<Self::Checksum, Self::Error> {
        Ok(Ipv4Checksum(self.0.calc_header_checksum()))
    }

    /// Set the checksum field of the header.
    ///
    /// The validity of the checksum is not checked.
    ///
    /// # Errors
    ///
    /// Always returns `Ok`.
    fn set_checksum(&mut self, checksum: Self::Checksum) -> Result<&mut Self, Self::Error> {
        self.0.header_checksum = checksum.0;
        Ok(self)
    }
}
