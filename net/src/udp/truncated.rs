// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! UDP header type and logic, for potentially truncated datagrams.

use std::num::NonZero;

use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError};
use crate::udp::{Udp, UdpParseError, UdpPort};

/// A truncated UDP header.
///
/// This truncated header is built from the start of a regular UDP header, down to the last byte of
/// the packet, but does not contain a full header. The only fields that are guaranteed to be
/// present are the source and destination ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncatedUdpHeader {
    source_port: UdpPort,
    destination_port: UdpPort,
    // The rest of the header, as a byte vector, for de-parsing
    everything_else: Vec<u8>,
}

impl TruncatedUdpHeader {
    const MIN_HEADER_LEN: usize = 4;

    fn new(source_port: UdpPort, destination_port: UdpPort, everything_else: Vec<u8>) -> Self {
        Self {
            source_port,
            destination_port,
            everything_else,
        }
    }

    /// Get the length of the truncated header
    #[must_use]
    pub fn header_len(&self) -> NonZero<usize> {
        let len = self.everything_else.len() + Self::MIN_HEADER_LEN;
        NonZero::new(len).unwrap_or_else(|| unreachable!())
    }

    /// Get the source port
    #[must_use]
    pub const fn source(&self) -> UdpPort {
        self.source_port
    }

    /// Get the destination port
    #[must_use]
    pub const fn destination(&self) -> UdpPort {
        self.destination_port
    }

    /// Set the source port
    pub fn set_source(&mut self, source_port: UdpPort) -> &mut Self {
        self.source_port = source_port;
        self
    }

    /// Set the destination port
    pub fn set_destination(&mut self, destination_port: UdpPort) -> &mut Self {
        self.destination_port = destination_port;
        self
    }
}

impl Parse for TruncatedUdpHeader {
    type Error = TruncatedUdpError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        // We need at least four bytes to form our truncated header.
        // RFC 792 (ICMP) says embedded packets in ICMP Error messages contain the IP header plus at
        // least the first 64 bits from the datagram, so we should have these 4 bytes. Otherwise,
        // it's an error.
        if buf.len() < TruncatedUdpHeader::MIN_HEADER_LEN {
            return Err(ParseError::Length(LengthError {
                expected: NonZero::new(TruncatedUdpHeader::MIN_HEADER_LEN)
                    .unwrap_or_else(|| unreachable!()),
                actual: buf.len(),
            }));
        }

        let parsed_source_port = u16::from_be_bytes([buf[0], buf[1]]);
        let parsed_destination_port = u16::from_be_bytes([buf[2], buf[3]]);

        // buf.len() is always non-zero and lower than u16::MAX
        #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
        let consumed = NonZero::new(buf.len() as u16).unwrap();

        let source_port = UdpPort::new_checked(parsed_source_port).map_err(|_| {
            ParseError::Invalid(TruncatedUdpError::UdpParseError(
                UdpParseError::ZeroSourcePort,
            ))
        })?;
        let destination_port = UdpPort::new_checked(parsed_destination_port).map_err(|_| {
            ParseError::Invalid(TruncatedUdpError::UdpParseError(
                UdpParseError::ZeroDestinationPort,
            ))
        })?;
        let parsed = Self::new(source_port, destination_port, buf[4..].to_vec());
        Ok((parsed, consumed))
    }
}

impl DeParse for TruncatedUdpHeader {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        let size_u16 = u16::try_from(self.header_len().get()).unwrap_or_else(|_| unreachable!());
        NonZero::new(size_u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let buf_len = buf.len();
        let header_len = self.header_len().get();
        if buf_len < header_len {
            return Err(DeParseError::Length(LengthError {
                expected: NonZero::new(header_len).unwrap_or_else(|| unreachable!()),
                actual: buf_len,
            }));
        }
        buf[0..2].copy_from_slice(&self.source_port.as_u16().to_be_bytes());
        buf[2..4].copy_from_slice(&self.destination_port.as_u16().to_be_bytes());
        buf[4..header_len].copy_from_slice(&self.everything_else);

        let header_len_u16 = u16::try_from(header_len).unwrap_or_else(|_| unreachable!());
        let written = NonZero::new(header_len_u16).unwrap_or_else(|| unreachable!());
        Ok(written)
    }
}

/// A UDP header, possibly truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TruncatedUdp {
    /// A full UDP header, whether payload is full or not
    FullHeader(Udp),
    /// A truncated UDP header (< 8 bytes)
    PartialHeader(TruncatedUdpHeader),
}

/// Errors which can occur when attempting to parse arbitrary bytes into a `TruncatedUdp` header.
#[derive(Debug, thiserror::Error)]
pub enum TruncatedUdpError {
    /// A transparent error from [`Udp::parse`].
    #[error("transparent")]
    UdpParseError(UdpParseError),
}

impl Parse for TruncatedUdp {
    type Error = TruncatedUdpError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let parse_attempt = Udp::parse(buf);
        match parse_attempt {
            // If we can parse the full header, return it
            Ok((udp, consumed)) => Ok((TruncatedUdp::FullHeader(udp), consumed)),
            // If we encounter an unexpected issue, return the error
            Err(ParseError::BufferTooLong(len)) => Err(ParseError::BufferTooLong(len)),
            Err(ParseError::Invalid(e)) => {
                Err(ParseError::Invalid(TruncatedUdpError::UdpParseError(e)))
            }
            // If we failed to parse because the header is too short, carry on and build a truncated
            // header
            Err(ParseError::Length(_)) => {
                let (header, consumed) = TruncatedUdpHeader::parse(buf)?;
                Ok((TruncatedUdp::PartialHeader(header), consumed))
            }
        }
    }
}

impl DeParse for TruncatedUdp {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            TruncatedUdp::FullHeader(udp) => udp.size(),
            TruncatedUdp::PartialHeader(udp) => udp.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            TruncatedUdp::FullHeader(udp) => udp.deparse(buf),
            TruncatedUdp::PartialHeader(udp) => udp.deparse(buf),
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::TruncatedUdp;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for TruncatedUdp {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            // Generate either full or partial UDP header
            let udp = if driver.produce::<bool>()? {
                TruncatedUdp::FullHeader(driver.produce()?)
            } else {
                let source_port = driver.produce()?;
                let dest_port = driver.produce()?;
                // We can have up to 3 extra byte for the header, in addition to the 4 bytes for
                // the ports. Beyond that, we'd have at least 8 bytes and that would make our
                // header a full UDP header.
                let extra_bytes: Vec<u8> = driver.produce::<[u8; 3]>()?
                    [..driver.produce::<u8>()? as usize % 3] // 0-3 bytes, total 4-7 bytes
                    .to_vec();
                TruncatedUdp::PartialHeader(crate::udp::TruncatedUdpHeader::new(
                    source_port,
                    dest_port,
                    extra_bytes,
                ))
            };
            Some(udp)
        }
    }
}
