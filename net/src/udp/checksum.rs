// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! UDP checksum type and methods

use crate::checksum::Checksum;
use crate::headers::Net;
use crate::udp::{TruncatedUdp, Udp};
use core::fmt::{Display, Formatter};
use std::fmt::Debug;

/// A [`Udp`] [checksum]
///
/// [checksum]: https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Checksum_computation
/// [`Udp`]: crate::udp::Udp
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct UdpChecksum(pub(crate) u16);

impl UdpChecksum {
    /// Commonly used as the checksum for a VXLAN packet.
    pub const ZERO: Self = Self(0);
}

impl Display for UdpChecksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06X}", self.0)
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

/// The payload over which a UDP checksum is computed.
pub struct UdpChecksumPayload<'a> {
    net: &'a Net,
    contents: &'a [u8],
}

impl<'a> UdpChecksumPayload<'a> {
    /// Assemble a new UDP checksum payload.
    #[must_use]
    pub fn new(net: &'a Net, contents: &'a [u8]) -> Self {
        Self { net, contents }
    }
}

impl Checksum for Udp {
    type Error = ();
    type Payload<'a>
        = UdpChecksumPayload<'a>
    where
        Self: 'a;
    type Checksum = UdpChecksum;

    /// Get the [`Udp`] checksum of the header
    ///
    /// # Returns
    ///
    /// Always returns `Some`.
    fn checksum(&self) -> Option<Self::Checksum> {
        Some(UdpChecksum(self.0.checksum))
    }

    /// Compute the UDP header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// Always returns `Ok`.
    fn compute_checksum(&self, payload: &Self::Payload<'_>) -> Result<Self::Checksum, Self::Error> {
        match payload.net {
            Net::Ipv4(ip) => Ok(self.compute_checksum_ipv4(ip, payload.contents)),
            Net::Ipv6(ip) => Ok(self.compute_checksum_ipv6(ip, payload.contents)),
        }
    }

    /// Set the checksum field of the header.
    ///
    /// The validity of the checksum is not checked.
    ///
    /// # Errors
    ///
    /// Always returns `Ok`.
    fn set_checksum(&mut self, checksum: Self::Checksum) -> Result<&mut Self, Self::Error> {
        self.0.checksum = checksum.0;
        Ok(self)
    }
}

/// Errors which can occur when attempting to compute a UDP checksum for a truncated UDP header.
#[derive(Debug, thiserror::Error)]
pub enum TruncatedUdpChecksumError {
    /// The header is truncated, checksum operations are not available.
    #[error("header is truncated")]
    Truncated,
}

impl Checksum for TruncatedUdp {
    type Error = TruncatedUdpChecksumError;
    type Payload<'a>
        = UdpChecksumPayload<'a>
    where
        Self: 'a;
    type Checksum = UdpChecksum;

    /// Get the [`Udp`] checksum of the header
    ///
    /// # Returns
    ///
    /// * `Some` if the header is a full header
    /// * `None` if the header is a truncated header
    fn checksum(&self) -> Option<Self::Checksum> {
        match self {
            TruncatedUdp::FullHeader(udp) => udp.checksum(),
            TruncatedUdp::PartialHeader(_) => None,
        }
    }

    /// Compute the UDP header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// * [`TruncatedUdpChecksumError::Truncated`] if the header is a truncated header
    ///
    /// <div class="warning">
    /// If the header is full, we perform the computation although there is no guarantee that the
    /// UDP _payload_ is full. It is the responsibility of the caller to ensure that the UDP payload
    /// is full, _and_ that the payload passed as an argument is exempt from ICMP Extension
    /// Structures and padding.
    /// </div>
    fn compute_checksum(&self, payload: &Self::Payload<'_>) -> Result<Self::Checksum, Self::Error> {
        match self {
            TruncatedUdp::FullHeader(udp) => Ok(udp
                .compute_checksum(payload)
                .unwrap_or_else(|()| unreachable!())), // UDP checksum computation never fails
            TruncatedUdp::PartialHeader(_) => Err(TruncatedUdpChecksumError::Truncated),
        }
    }

    /// Set the checksum field of the header.
    ///
    /// The validity of the checksum is not checked.
    ///
    /// # Errors
    ///
    /// * [`TruncatedUdpChecksumError::Truncated`] if the header is a truncated header
    fn set_checksum(&mut self, checksum: Self::Checksum) -> Result<&mut Self, Self::Error> {
        match self {
            TruncatedUdp::FullHeader(udp) => {
                udp.set_checksum(checksum)
                    .unwrap_or_else(|()| unreachable!()); // Setting the UDP checksum never fails
                Ok(self)
            }
            TruncatedUdp::PartialHeader(_) => Err(TruncatedUdpChecksumError::Truncated),
        }
    }
}
