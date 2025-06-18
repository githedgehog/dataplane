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
    type Payload<'a>
        = ()
    where
        Self: 'a;
    type Checksum = Ipv4Checksum;

    fn checksum(&self) -> Self::Checksum {
        Ipv4Checksum(self.0.header_checksum)
    }

    fn compute_checksum(&self, _payload: &Self::Payload<'_>) -> Self::Checksum {
        Ipv4Checksum(self.0.calc_header_checksum())
    }

    fn set_checksum(&mut self, checksum: Self::Checksum) -> &mut Self {
        self.0.header_checksum = checksum.0;
        self
    }
}
