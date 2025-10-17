// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ICMP (v4/v6) checksum type and methods

use super::{IcmpAny, IcmpAnyMut};
use crate::checksum::{Checksum, ChecksumError};
use crate::headers::{AbstractEmbeddedHeaders, Net};
use crate::icmp4::Icmp4Checksum;
use crate::icmp6::{Icmp6Checksum, Icmp6ChecksumPayload};
use crate::parse::DeParse;
use core::fmt::{Display, Formatter};
use std::fmt::Debug;

/// An ICMP [checksum]
///
/// [checksum]: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Header
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IcmpAnyChecksum(pub(crate) u16);

impl Display for IcmpAnyChecksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:#06X}", self.0)
    }
}

impl IcmpAnyChecksum {
    /// Map a raw value to a [`IcmpAnyChecksum`]
    #[must_use]
    pub const fn new(raw: u16) -> IcmpAnyChecksum {
        IcmpAnyChecksum(raw)
    }
}

impl AsRef<u16> for IcmpAnyChecksum {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl AsMut<u16> for IcmpAnyChecksum {
    fn as_mut(&mut self) -> &mut u16 {
        &mut self.0
    }
}

impl From<u16> for IcmpAnyChecksum {
    fn from(raw: u16) -> Self {
        Self::new(raw)
    }
}

impl From<IcmpAnyChecksum> for u16 {
    fn from(checksum: IcmpAnyChecksum) -> Self {
        checksum.0
    }
}

impl From<Icmp4Checksum> for IcmpAnyChecksum {
    fn from(checksum: Icmp4Checksum) -> Self {
        Self::new(checksum.0)
    }
}

impl From<Icmp6Checksum> for IcmpAnyChecksum {
    fn from(checksum: Icmp6Checksum) -> Self {
        Self::new(checksum.0)
    }
}

/// The payload over which to compute and validate [`IcmpAny`] checksums.
pub enum IcmpAnyChecksumPayload<'a> {
    /// Payload for [`IcmpAny::V4`]
    V4(&'a [u8]),
    /// Payload for [`IcmpAny::V6`]
    V6(Icmp6ChecksumPayload<'a>),
}

impl<'a> IcmpAnyChecksumPayload<'a> {
    /// Create a new [`IcmpAnyChecksumPayload`] from a [`Net`] header and provided payload.
    #[must_use]
    pub fn from_net<'b>(net: &'b Net, payload: &'a [u8]) -> Self {
        match net {
            Net::Ipv4(_) => IcmpAnyChecksumPayload::V4(payload),
            Net::Ipv6(ipv6) => {
                let source = ipv6.source().into();
                let destination = ipv6.destination();
                IcmpAnyChecksumPayload::V6(Icmp6ChecksumPayload::new(source, destination, payload))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IcmpAnyError {
    #[error("object is immutable")]
    Immutable,
    #[error("payload type mismatch")]
    WrongPayloadType,
}

impl Checksum for IcmpAny<'_> {
    type Error = IcmpAnyError;
    type Payload<'a>
        = IcmpAnyChecksumPayload<'a>
    where
        Self: 'a;
    type Checksum = IcmpAnyChecksum;

    /// Get the [`IcmpAny`] checksum of the header
    ///
    /// # Returns
    ///
    /// Always returns `Some`.
    fn checksum(&self) -> Option<IcmpAnyChecksum> {
        match self {
            IcmpAny::V4(v4) => Some(IcmpAnyChecksum::from(v4.checksum()?)),
            IcmpAny::V6(v6) => Some(IcmpAnyChecksum::from(v6.checksum()?)),
        }
    }

    /// Compute the icmp header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// Returns an `IcmpAnyError::WrongPayloadType` if the payload type does not match the
    /// [`IcmpAny`] variant.
    fn compute_checksum(
        &self,
        payload: &IcmpAnyChecksumPayload<'_>,
    ) -> Result<IcmpAnyChecksum, IcmpAnyError> {
        match (self, payload) {
            (IcmpAny::V4(v4), IcmpAnyChecksumPayload::V4(payload)) => Ok(IcmpAnyChecksum::from(
                v4.compute_checksum(payload)
                    .unwrap_or_else(|()| unreachable!()), // IPv4 checksum computation never fails
            )),
            (IcmpAny::V6(v6), IcmpAnyChecksumPayload::V6(payload)) => Ok(IcmpAnyChecksum::from(
                v6.compute_checksum(payload)
                    .unwrap_or_else(|()| unreachable!()), // IPv6 checksum computation never fails
            )),
            _ => Err(IcmpAnyError::WrongPayloadType),
        }
    }

    /// The pointers in [`IcmpAny`] are not mutable, we cannot implement
    /// [`set_checksum()`](Checksum::set_checksum) correctly for this type.
    ///
    /// # Errors
    ///
    /// Always returns `IcmpAnyError::Immutable`.
    fn set_checksum(&mut self, _checksum: IcmpAnyChecksum) -> Result<&mut Self, IcmpAnyError> {
        Err(IcmpAnyError::Immutable)
    }
}

impl Checksum for IcmpAnyMut<'_> {
    type Error = IcmpAnyError;
    type Payload<'a>
        = IcmpAnyChecksumPayload<'a>
    where
        Self: 'a;
    type Checksum = IcmpAnyChecksum;

    /// Get the [`IcmpAny`] checksum of the header
    ///
    /// # Returns
    ///
    /// Always returns `Some`.
    fn checksum(&self) -> Option<IcmpAnyChecksum> {
        match self {
            IcmpAnyMut::V4(v4) => Some(IcmpAnyChecksum::from(v4.checksum()?)),
            IcmpAnyMut::V6(v6) => Some(IcmpAnyChecksum::from(v6.checksum()?)),
        }
    }

    /// Compute the ICMP header's checksum based on the supplied payload.
    ///
    /// This method _does not_ update the checksum field.
    ///
    /// # Errors
    ///
    /// Returns an `IcmpAnyError::WrongPayloadType` if the payload type does not match the
    /// [`IcmpAnyMut`] variant.
    fn compute_checksum(
        &self,
        payload: &IcmpAnyChecksumPayload<'_>,
    ) -> Result<IcmpAnyChecksum, IcmpAnyError> {
        match (self, payload) {
            (IcmpAnyMut::V4(v4), IcmpAnyChecksumPayload::V4(payload)) => Ok(IcmpAnyChecksum::from(
                v4.compute_checksum(payload)
                    .unwrap_or_else(|()| unreachable!()), // IPv4 checksum computation never fails
            )),
            (IcmpAnyMut::V6(v6), IcmpAnyChecksumPayload::V6(payload)) => Ok(IcmpAnyChecksum::from(
                v6.compute_checksum(payload)
                    .unwrap_or_else(|()| unreachable!()), // IPv6 checksum computation never fails
            )),
            _ => Err(IcmpAnyError::WrongPayloadType),
        }
    }

    /// Set the checksum field of the header
    ///
    /// # Errors
    ///
    /// This method never fails.
    fn set_checksum(&mut self, checksum: IcmpAnyChecksum) -> Result<&mut Self, IcmpAnyError> {
        match self {
            IcmpAnyMut::V4(icmp4) => {
                icmp4
                    .set_checksum(Icmp4Checksum(checksum.0))
                    .unwrap_or_else(|()| unreachable!()); // IPv4 checksum computation never fails
            }
            IcmpAnyMut::V6(icmp6) => {
                icmp6
                    .set_checksum(Icmp6Checksum(checksum.0))
                    .unwrap_or_else(|()| unreachable!()); // IPv6 checksum computation never fails
            }
        }
        Ok(self)
    }
}

pub(crate) fn get_payload_for_checksum(
    embedded_headers: Option<&impl AbstractEmbeddedHeaders>,
    payload: &[u8],
) -> Vec<u8> {
    let Some(embedded_headers) = embedded_headers else {
        return payload.to_vec();
    };
    let Some(embedded_ip_header) = embedded_headers.try_inner_ip() else {
        return payload.to_vec();
    };
    let embedded_transport_header = embedded_headers.try_embedded_transport();

    let inner_ip_header_length = embedded_ip_header.size().get() as usize;
    let inner_transport_header_length =
        embedded_transport_header.map_or(0, |header| header.size().get() as usize);

    let mut offset = 0;
    let mut icmp_payload =
        vec![0; payload.len() + inner_ip_header_length + inner_transport_header_length];
    // Write inner IP header
    offset += embedded_ip_header
        .deparse(&mut icmp_payload[offset..])
        .unwrap_or_else(|_| unreachable!())
        .get() as usize;
    // Write inner transport header
    if let Some(transport) = embedded_transport_header {
        offset += transport
            .deparse(&mut icmp_payload[offset..])
            .unwrap_or_else(|_| unreachable!())
            .get() as usize;
    }
    // Write payload (including ICMP padding/extensions, if any)
    icmp_payload[offset..].copy_from_slice(payload);

    icmp_payload
}

/// A placeholder type for passing checksum errors, without a lifetime.
/// Do not use, other than for converting the `ChecksumError` generic parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpAnyChecksumErrorPlaceholder {}

impl Checksum for IcmpAnyChecksumErrorPlaceholder {
    type Error = IcmpAnyError;
    type Payload<'a>
        = IcmpAnyChecksumPayload<'a>
    where
        Self: 'a;
    type Checksum = IcmpAnyChecksum;

    fn checksum(&self) -> Option<IcmpAnyChecksum> {
        unreachable!(
            "IcmpAnyChecksumErrorPlaceholder does not have a checksum. Do not call this method."
        )
    }
    fn compute_checksum(
        &self,
        _: &IcmpAnyChecksumPayload<'_>,
    ) -> Result<IcmpAnyChecksum, IcmpAnyError> {
        unreachable!(
            "IcmpAnyChecksumErrorPlaceholder does not have a checksum. Do not call this method."
        )
    }
    fn set_checksum(&mut self, _: IcmpAnyChecksum) -> Result<&mut Self, IcmpAnyError> {
        unreachable!(
            "IcmpAnyChecksumErrorPlaceholder does not have a checksum. Do not call this method."
        )
    }
}

impl From<ChecksumError<IcmpAny<'_>>> for ChecksumError<IcmpAnyChecksumErrorPlaceholder> {
    fn from(value: ChecksumError<IcmpAny<'_>>) -> Self {
        match value {
            ChecksumError::Compute { error } => ChecksumError::Compute { error },
            ChecksumError::Mismatch { expected, actual } => {
                ChecksumError::Mismatch { expected, actual }
            }
            ChecksumError::NotPresent => ChecksumError::NotPresent,
        }
    }
}
