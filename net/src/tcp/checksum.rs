// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! TCP checksum type and methods

use crate::checksum::Checksum;
use crate::headers::Net;
use crate::tcp::Tcp;
use core::fmt::{Display, Formatter};
use std::fmt::Debug;

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
        write!(f, "{:#06X}", self.0)
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

/// The payload over which a [`Tcp`] checksum is computed
pub struct TcpChecksumPayload<'a> {
    net: &'a Net,
    contents: &'a [u8],
}

impl<'a> TcpChecksumPayload<'a> {
    /// Assemble a new [`TcpChecksumPayload`]
    #[must_use]
    pub const fn new(net: &'a Net, contents: &'a [u8]) -> Self {
        Self { net, contents }
    }
}

impl Checksum for Tcp {
    type Payload<'a>
        = TcpChecksumPayload<'a>
    where
        Self: 'a;
    type Checksum = TcpChecksum;

    fn checksum(&self) -> Self::Checksum {
        TcpChecksum(self.0.checksum)
    }

    fn compute_checksum(&self, payload: &Self::Payload<'_>) -> Self::Checksum {
        match payload.net {
            Net::Ipv4(ip) => self.compute_checksum_ipv4(ip, payload.contents),
            Net::Ipv6(ip) => self.compute_checksum_ipv6(ip, payload.contents),
        }
    }

    fn set_checksum(&mut self, checksum: Self::Checksum) -> &mut Self {
        self.0.checksum = checksum.0;
        self
    }
}
