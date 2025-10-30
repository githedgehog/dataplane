// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv6` header type and logic, for potentially truncated datagrams.

use std::num::NonZero;

use crate::icmp_any::TruncatedIcmpAny;
use crate::icmp6::Icmp6;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError};

/// A truncated `ICMPv6` header.
///
/// This truncated header is built from the start of a regular `ICMPv6` header, down to the last byte of
/// the packet, but does not contain a full header. The only fields that are guaranteed to be
/// present are the type and code values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncatedIcmp6Header {
    icmp_type: u8,
    code: u8,
    // The rest of the header, as a byte vector, for de-parsing
    everything_else: Vec<u8>,
}

impl TruncatedIcmp6Header {
    const MIN_HEADER_LEN: usize = 2;

    fn new(icmp_type: u8, code: u8, everything_else: Vec<u8>) -> Self {
        Self {
            icmp_type,
            code,
            everything_else,
        }
    }

    /// Get the length of the truncated header
    #[must_use]
    pub fn header_len(&self) -> NonZero<usize> {
        let len = self.everything_else.len() + Self::MIN_HEADER_LEN;
        NonZero::new(len).unwrap_or_else(|| unreachable!())
    }

    fn is_query_message(&self) -> bool {
        match self.icmp_type {
            128 | 129 => true, // Echo Request, Echo Reply
            _ => false,
        }
    }

    fn identifier(&self) -> Option<u16> {
        if !self.is_query_message() {
            return None;
        }
        if self.everything_else.len() < 4 {
            return None;
        }
        Some(u16::from_be_bytes([
            self.everything_else[2],
            self.everything_else[3],
        ]))
    }

    fn try_set_identifier(&mut self, identifier: u16) -> Result<(), TruncatedIcmp6Error> {
        if !self.is_query_message() {
            return Err(TruncatedIcmp6Error::NoIdentifier);
        }
        if self.everything_else.len() < 4 {
            return Err(TruncatedIcmp6Error::NoIdentifier);
        }
        self.everything_else[2] = identifier.to_be_bytes()[0];
        self.everything_else[3] = identifier.to_be_bytes()[1];
        Ok(())
    }
}

impl Parse for TruncatedIcmp6Header {
    type Error = TruncatedIcmp6Error;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        // We need at least two bytes to form our truncated header.
        // RFC 792 (ICMP) says embedded packets in ICMP Error messages contain the IP header plus at
        // least the first 64 bits from the datagram, so we should have these 2 bytes. Otherwise,
        // it's an error.
        if buf.len() < TruncatedIcmp6Header::MIN_HEADER_LEN {
            return Err(ParseError::Length(LengthError {
                expected: NonZero::new(TruncatedIcmp6Header::MIN_HEADER_LEN)
                    .unwrap_or_else(|| unreachable!()),
                actual: buf.len(),
            }));
        }

        let parsed_icmp_type = u8::from_be_bytes([buf[0]]);
        let parsed_code = u8::from_be_bytes([buf[1]]);

        // buf.len() is always non-zero and lower than u16::MAX
        #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
        let consumed = NonZero::new(buf.len() as u16).unwrap();

        let parsed = Self::new(parsed_icmp_type, parsed_code, buf[2..].to_vec());
        Ok((parsed, consumed))
    }
}

impl DeParse for TruncatedIcmp6Header {
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
        buf[0] = self.icmp_type;
        buf[1] = self.code;
        buf[2..header_len].copy_from_slice(&self.everything_else);

        let header_len_u16 = u16::try_from(header_len).unwrap_or_else(|_| unreachable!());
        let written = NonZero::new(header_len_u16).unwrap_or_else(|| unreachable!());
        Ok(written)
    }
}

/// An `ICMPv6` header, possibly truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TruncatedIcmp6 {
    /// A full `ICMPv6` header, whether payload is full or not
    FullHeader(Icmp6),
    /// A truncated `ICMPv6` header
    PartialHeader(TruncatedIcmp6Header),
}

impl TruncatedIcmp6 {
    /// Returns true if the ICMP type is a query message
    #[must_use]
    pub fn is_query_message(&self) -> bool {
        match self {
            TruncatedIcmp6::FullHeader(icmp) => icmp.is_query_message(),
            TruncatedIcmp6::PartialHeader(header) => header.is_query_message(),
        }
    }
}

impl TruncatedIcmpAny for TruncatedIcmp6 {
    type Error = TruncatedIcmp6Error;

    /// Get the identifier of the ICMP message, if relevant and if doable
    ///
    /// # Returns
    ///
    /// * `Some(u16)` for ICMP messages that have an identifier and if the identifier is available
    /// * `None` otherwise
    fn identifier(&self) -> Option<u16> {
        match self {
            TruncatedIcmp6::FullHeader(icmp) => icmp.identifier(),
            TruncatedIcmp6::PartialHeader(header) => header.identifier(),
        }
    }

    /// Set the identifier of the ICMP message, if relevant and if doable
    ///
    /// # Errors
    ///
    /// This method returns [`TruncatedIcmp6Error::NoIdentifier`] if the ICMP type does not allow setting
    /// an identifier, or is not long enough.
    fn try_set_identifier(&mut self, identifier: u16) -> Result<(), TruncatedIcmp6Error> {
        match self {
            TruncatedIcmp6::FullHeader(icmp) => icmp
                .try_set_identifier(identifier)
                .map_err(|_| TruncatedIcmp6Error::NoIdentifier),
            TruncatedIcmp6::PartialHeader(header) => header
                .try_set_identifier(identifier)
                .map_err(|_| TruncatedIcmp6Error::NoIdentifier),
        }
    }
}

/// Errors which can occur when attempting to parse arbitrary bytes into a `TruncatedIcmp6` header.
#[derive(Debug, thiserror::Error)]
pub enum TruncatedIcmp6Error {
    /// A transparent error from [`Icmp6::parse`].
    #[error("transparent")]
    Icmp6ParseError(LengthError),
    /// The ICMP header does not allow setting an identifier.
    #[error("no identifier to set for ICMP packet (wrong type or truncated header)")]
    NoIdentifier,
}

impl Parse for TruncatedIcmp6 {
    type Error = TruncatedIcmp6Error;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let parse_attempt = Icmp6::parse(buf);
        match parse_attempt {
            // If we can parse the full header, return it
            Ok((icmp, consumed)) => Ok((TruncatedIcmp6::FullHeader(icmp), consumed)),
            // If we encounter an unexpected issue, return the error
            Err(ParseError::BufferTooLong(len)) => Err(ParseError::BufferTooLong(len)),
            Err(ParseError::Invalid(e)) => {
                Err(ParseError::Invalid(TruncatedIcmp6Error::Icmp6ParseError(e)))
            }
            // If we failed to parse because the header is too short, carry on and build a truncated
            // header
            Err(ParseError::Length(_)) => {
                let (header, consumed) = TruncatedIcmp6Header::parse(buf)?;
                Ok((TruncatedIcmp6::PartialHeader(header), consumed))
            }
        }
    }
}

impl DeParse for TruncatedIcmp6 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            TruncatedIcmp6::FullHeader(icmp) => icmp.size(),
            TruncatedIcmp6::PartialHeader(icmp) => icmp.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            TruncatedIcmp6::FullHeader(icmp) => icmp.deparse(buf),
            TruncatedIcmp6::PartialHeader(icmp) => icmp.deparse(buf),
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::TruncatedIcmp6;
    use crate::icmp6::TruncatedIcmp6Header;
    use crate::parse::{DeParse, Parse};
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for TruncatedIcmp6 {
        // Generate either full or partial ICMPv6 header
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let full_header = TruncatedIcmp6::FullHeader(driver.produce()?);
            if driver.produce::<bool>()? {
                Some(full_header)
            } else {
                // The size for ICMPv6 headers (at least as considered in etherparse) is always 8 bytes
                let mut buffer = driver.produce::<[u8; 8]>()?;
                #[allow(clippy::unwrap_used)] // We want to catch errors when deparsing, if any
                full_header.deparse(&mut buffer).unwrap();

                // We can have up to 6 extra bytes for the header, in addition to the 2 bytes for
                // the type and code. Beyond that, we'd have at least 8 bytes and that would make
                // our header a full ICMPv6 header.
                let size = driver.produce::<u8>()? % 6 + 2;
                let truncated_buffer = &buffer[..size as usize];
                #[allow(clippy::unwrap_used)] // We want to catch errors when parsing, if any
                let icmp = TruncatedIcmp6Header::parse(truncated_buffer)
                    .ok()
                    .unwrap()
                    .0;

                Some(TruncatedIcmp6::PartialHeader(icmp))
            }
        }
    }
}
