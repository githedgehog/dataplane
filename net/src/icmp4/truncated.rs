// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv4` header type and logic, for potentially truncated datagrams.

use std::num::NonZero;

use crate::icmp4::Icmp4;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError};

/// A truncated `ICMPv4` header.
///
/// This truncated header is built from the start of a regular `ICMPv4` header, down to the last byte of
/// the packet, but does not contain a full header. The only fields that are guaranteed to be
/// present are the type and code values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncatedIcmp4Header {
    icmp_type: u8,
    code: u8,
    // The rest of the header, as a byte vector, for de-parsing
    everything_else: Vec<u8>,
}

impl TruncatedIcmp4Header {
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
            0 | 8 | 13 | 14 => true, // Echo Request, Echo Reply, Timestamp Request, Timestamp Reply
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
}

impl Parse for TruncatedIcmp4Header {
    type Error = TruncatedIcmp4Error;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        // We need at least two bytes to form our truncated header.
        // RFC 792 (ICMP) says embedded packets in ICMP Error messages contain the IP header plus at
        // least the first 64 bits from the datagram, so we should have these 2 bytes. Otherwise,
        // it's an error.
        if buf.len() < TruncatedIcmp4Header::MIN_HEADER_LEN {
            return Err(ParseError::Length(LengthError {
                expected: NonZero::new(TruncatedIcmp4Header::MIN_HEADER_LEN)
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

impl DeParse for TruncatedIcmp4Header {
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

/// An `ICMPv4` header, possibly truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TruncatedIcmp4 {
    /// A full `ICMPv4` header, whether payload is full or not
    FullHeader(Icmp4),
    /// A truncated `ICMPv4` header
    PartialHeader(TruncatedIcmp4Header),
}

impl TruncatedIcmp4 {
    /// Get the identifier of the ICMP message, if relevant and if doable
    ///
    /// # Returns
    ///
    /// * `Some(u16)` for ICMP messages that have an identifier and if the identifier is available
    /// * `None` otherwise
    #[must_use]
    pub fn identifier(&self) -> Option<u16> {
        match self {
            TruncatedIcmp4::FullHeader(icmp) => icmp.identifier(),
            TruncatedIcmp4::PartialHeader(header) => header.identifier(),
        }
    }
}

/// Errors which can occur when attempting to parse arbitrary bytes into a `TruncatedIcmp4` header.
#[derive(Debug, thiserror::Error)]
pub enum TruncatedIcmp4Error {
    /// A transparent error from [`Icmp4::parse`].
    #[error("transparent")]
    Icmp4ParseError(LengthError),
}

impl Parse for TruncatedIcmp4 {
    type Error = TruncatedIcmp4Error;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let parse_attempt = Icmp4::parse(buf);
        match parse_attempt {
            // If we can parse the full header, return it
            Ok((icmp, consumed)) => Ok((TruncatedIcmp4::FullHeader(icmp), consumed)),
            // If we encounter an unexpected issue, return the error
            Err(ParseError::BufferTooLong(len)) => Err(ParseError::BufferTooLong(len)),
            Err(ParseError::Invalid(e)) => {
                Err(ParseError::Invalid(TruncatedIcmp4Error::Icmp4ParseError(e)))
            }
            // If we failed to parse because the header is too short, carry on and build a truncated
            // header
            Err(ParseError::Length(_)) => {
                let (header, consumed) = TruncatedIcmp4Header::parse(buf)?;
                Ok((TruncatedIcmp4::PartialHeader(header), consumed))
            }
        }
    }
}

impl DeParse for TruncatedIcmp4 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            TruncatedIcmp4::FullHeader(icmp) => icmp.size(),
            TruncatedIcmp4::PartialHeader(icmp) => icmp.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            TruncatedIcmp4::FullHeader(icmp) => icmp.deparse(buf),
            TruncatedIcmp4::PartialHeader(icmp) => icmp.deparse(buf),
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::TruncatedIcmp4;
    use crate::icmp4::TruncatedIcmp4Header;
    use crate::parse::{DeParse, Parse};
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for TruncatedIcmp4 {
        // Generate either full or partial ICMPv4 header
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let full_header = TruncatedIcmp4::FullHeader(driver.produce()?);
            if driver.produce::<bool>()? {
                Some(full_header)
            } else {
                // Max ICMP header size is 20 bytes for timestamp requests/replies; but for all
                // other types it's 8 bytes.
                let mut buffer = driver.produce::<[u8; 20]>()?;
                #[allow(clippy::unwrap_used)] // We want to catch errors when deparsing, if any
                full_header.deparse(&mut buffer).unwrap();
                // If header size was lower than 20 (everything other than timestamp
                // requests/replies), zero the rest of the buffer
                buffer[full_header.size().get() as usize..20].fill(0);

                // We can have up to 6 extra bytes for the header, in addition to the 2 bytes for
                // the type and code. Beyond that, we'd have at least 8 bytes and that would make
                // our header a full ICMPv4 header (except for timestamp requests/replies. Oh,
                // well.).
                let size = driver.produce::<u8>()? % 6 + 2;
                let truncated_buffer = &buffer[..size as usize];
                #[allow(clippy::unwrap_used)] // We want to catch errors when parsing, if any
                let icmp = TruncatedIcmp4Header::parse(truncated_buffer)
                    .ok()
                    .unwrap()
                    .0;

                Some(TruncatedIcmp4::PartialHeader(icmp))
            }
        }
    }
}
