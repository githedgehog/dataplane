// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! TCP checksum type and methods

use crate::checksum::Checksum;
use crate::headers::Net;
use crate::tcp::{Tcp, TruncatedTcp};
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
    type Error = ();
    type Payload<'a>
        = TcpChecksumPayload<'a>
    where
        Self: 'a;
    type Checksum = TcpChecksum;

    /// Get the [`Tcp`] checksum of the header
    ///
    /// # Returns
    ///
    /// Always returns `Some`.
    fn checksum(&self) -> Option<Self::Checksum> {
        Some(TcpChecksum(self.0.checksum))
    }

    /// Compute the TCP header's checksum based on the supplied payload.
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

/// Errors which can occur when attempting to compute a TCP checksum for a truncated TCP header.
#[derive(Debug, thiserror::Error)]
pub enum TruncatedTcpChecksumError {
    /// The header is truncated, checksum operations are not available.
    #[error("header is truncated")]
    Truncated,
}

impl Checksum for TruncatedTcp {
    type Error = TruncatedTcpChecksumError;
    type Payload<'a>
        = TcpChecksumPayload<'a>
    where
        Self: 'a;
    type Checksum = TcpChecksum;

    /// Get the [`Tcp`] checksum of the header
    ///
    /// # Returns
    ///
    /// * `Some` if the header is a full header. The TCP payload may be truncated, so it may be
    ///   impossible to compute the checksum.
    /// * `None` if the header is a truncated header. Note that the checksum may be present in the
    ///   truncated header, but given that the header is truncated, it is irrelevant because there
    ///   is no way to validate it, so we return `None` in that case.
    fn checksum(&self) -> Option<Self::Checksum> {
        match self {
            TruncatedTcp::FullHeader(tcp) => tcp.checksum(),
            TruncatedTcp::PartialHeader(_) => None,
        }
    }

    /// Compute the TCP header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// * [`TruncatedTcpChecksumError::Truncated`] if the header is a truncated header
    ///
    /// <div class="warning">
    /// If the header is full, we perform the computation although there is no guarantee that the
    /// TCP _payload_ is full. It is the responsibility of the caller to ensure that the TCP payload
    /// is full, _and_ that the payload passed as an argument is exempt from ICMP Extension
    /// Structures and padding.
    /// </div>
    fn compute_checksum(&self, payload: &Self::Payload<'_>) -> Result<Self::Checksum, Self::Error> {
        match self {
            TruncatedTcp::FullHeader(tcp) => Ok(tcp
                .compute_checksum(payload)
                .unwrap_or_else(|()| unreachable!())), // TCP checksum computation never fails
            TruncatedTcp::PartialHeader(_) => Err(TruncatedTcpChecksumError::Truncated),
        }
    }

    /// Set the checksum field of the header.
    ///
    /// The validity of the checksum is not checked.
    ///
    /// # Errors
    ///
    /// * [`TruncatedTcpChecksumError::Truncated`] if the header is a truncated header
    fn set_checksum(&mut self, checksum: Self::Checksum) -> Result<&mut Self, Self::Error> {
        match self {
            TruncatedTcp::FullHeader(tcp) => {
                tcp.set_checksum(checksum)
                    .unwrap_or_else(|()| unreachable!()); // Setting the TCP checksum never fails
                Ok(self)
            }
            TruncatedTcp::PartialHeader(_) => Err(TruncatedTcpChecksumError::Truncated),
        }
    }
}
