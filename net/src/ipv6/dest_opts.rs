// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv6 Destination Options header ([RFC 8200 section 4.6]).
//!
//! Destination Options carry optional information examined only by the
//! packet's destination node(s).  Per [RFC 8200 section 4.1], Destination Options
//! may appear in **two** positions:
//!
//! 1. Before the Routing header -- examined by the first destination plus
//!    subsequent destinations listed in the Routing header.
//! 2. After the Routing / Fragment / AH headers -- examined only by the
//!    final destination.
//!
//! Both positions use the same wire format and the same [`DestOpts`] type.
//!
//! [RFC 8200 section 4.1]: https://datatracker.ietf.org/doc/html/rfc8200#section-4.1
//! [RFC 8200 section 4.6]: https://datatracker.ietf.org/doc/html/rfc8200#section-4.6

use crate::ip::NextHeader;
use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError};
use etherparse::Ipv6RawExtHeader;
use std::num::NonZero;

/// IPv6 Destination Options header.
///
/// Wraps an [`Ipv6RawExtHeader`] from etherparse.  The inner type is boxed
/// because `Ipv6RawExtHeader` is ~2 KiB (variable-length payload buffer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestOpts(Box<Ipv6RawExtHeader>);

impl DestOpts {
    /// The minimum header length in bytes.
    #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
    pub const MIN_LEN: NonZero<u16> = NonZero::new(Ipv6RawExtHeader::MIN_LEN as u16).unwrap();

    /// Get the next-header protocol number.
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        NextHeader::from(self.0.next_header)
    }

    /// Set the next-header protocol number.
    pub fn set_next_header(&mut self, nh: NextHeader) {
        self.0.next_header = nh.into();
    }

    /// The raw TLV payload (excluding next-header and length fields).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.0.payload()
    }
}

impl From<Box<Ipv6RawExtHeader>> for DestOpts {
    fn from(inner: Box<Ipv6RawExtHeader>) -> Self {
        Self(inner)
    }
}

impl Parse for DestOpts {
    type Error = etherparse::err::LenError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        if buf.len() < Self::MIN_LEN.get() as usize {
            return Err(ParseError::Length(LengthError {
                expected: Self::MIN_LEN.into_non_zero_usize(),
                actual: buf.len(),
            }));
        }
        let (inner, rest) = Ipv6RawExtHeader::from_slice(buf).map_err(ParseError::Invalid)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)]
        let consumed = NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!());
        Ok((Self(Box::new(inner)), consumed?))
    }
}

impl DeParse for DestOpts {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)]
        NonZero::new(self.0.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let size = self.size();
        if buf.len() < size.into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: size.into_non_zero_usize(),
                actual: buf.len(),
            }));
        }
        let bytes = self.0.to_bytes();
        buf[..size.get() as usize].copy_from_slice(&bytes[..size.get() as usize]);
        Ok(size)
    }
}
