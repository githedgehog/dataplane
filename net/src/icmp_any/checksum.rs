// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ICMP (v4/v6) checksum type and methods

use super::{IcmpAny, IcmpAnyMut};
use crate::checksum::{Checksum, ChecksumError};
use crate::headers::{AbstractEmbeddedHeaders, Net};
use crate::icmp4::Icmp4Checksum;
use crate::icmp6::{Icmp6Checksum, Icmp6ChecksumPayload};
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
    if embedded_headers.try_inner_ip().is_none() {
        return payload.to_vec();
    }
    // The quoted headers, extension headers included, then the rest of the quote (including ICMP
    // padding/extensions, if any)
    let headers_length = embedded_headers.size().get() as usize;
    let mut icmp_payload = vec![0; headers_length + payload.len()];
    embedded_headers
        .deparse(&mut icmp_payload)
        .unwrap_or_else(|_| unreachable!());
    icmp_payload[headers_length..].copy_from_slice(payload);

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

#[cfg(test)]
mod tests {
    use crate::headers::Headers;
    use crate::parse::{DeParse, Parse};

    const ETH: usize = 14;
    const IPV6: usize = 40;

    /// An IPv6 header from `fe80::1` to `fe80::2`, `next` header next, `rest` octets of payload.
    fn ipv6(next: u8, rest: usize) -> Vec<u8> {
        let mut out = vec![0x60, 0, 0, 0];
        out.extend_from_slice(&u16::try_from(rest).unwrap().to_be_bytes());
        out.extend_from_slice(&[next, 64]);
        out.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        out.extend_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        out
    }

    /// One's-complement sum of `bytes` as 16-bit words, with both zeros read as `0xffff`.
    fn ones_complement_sum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|word| u32::from(u16::from_be_bytes(*word)))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        match u16::try_from(sum).unwrap() {
            0 => 0xffff,
            sum => sum,
        }
    }

    /// The quoted datagram's extension headers sit between its IP and transport headers, and are as
    /// much a part of the ICMP message as either.
    #[test]
    fn a_refreshed_checksum_covers_quoted_extension_headers() {
        // UDP from port 12345 to 12346, then four octets of payload, after a destination options
        // header holding a 4-octet PadN option.
        let mut quoted = ipv6(60, 8 + 12);
        quoted.extend_from_slice(&[17, 0, 1, 4, 0, 0, 0, 0]);
        quoted.extend_from_slice(&[0x30, 0x39, 0x30, 0x3a, 0, 12, 0, 0, 1, 2, 3, 4]);
        let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x86, 0xdd];
        frame.append(&mut ipv6(58, 8 + quoted.len()));
        frame.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]); // destination unreachable: no route
        frame.append(&mut quoted);

        let (mut headers, consumed) = Headers::parse(&frame).unwrap();
        let consumed = usize::from(consumed.get());
        assert_eq!(
            headers.embedded_ip().map(|quoted| quoted.net_ext().len()),
            Some(1)
        );
        headers.refresh_transport_checksum(&frame[consumed..]);
        let mut out = frame.clone();
        headers.deparse(&mut out[..consumed]).unwrap();

        let message = &out[ETH + IPV6..];
        let mut covered = out[ETH + 8..ETH + IPV6].to_vec(); // source and destination
        covered.extend_from_slice(&u32::try_from(message.len()).unwrap().to_be_bytes());
        covered.extend_from_slice(&[0, 0, 0, 58]);
        covered.extend_from_slice(message);
        assert_eq!(
            ones_complement_sum(&covered),
            0xffff,
            "the checksum does not cover the message as written: {out:02x?}"
        );
    }
}
