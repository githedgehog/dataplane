// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv6 Hop-by-Hop Options header ([RFC 8200 section 4.3]).
//!
//! The Hop-by-Hop Options header carries optional information that **must** be
//! examined by every node along a packet's delivery path.  Per [RFC 8200 section 4.1],
//! it **must** immediately follow the IPv6 header when present -- the builder
//! enforces this via [`Within`] bounds.
//!
//! [RFC 8200 section 4.1]: https://datatracker.ietf.org/doc/html/rfc8200#section-4.1
//! [RFC 8200 section 4.3]: https://datatracker.ietf.org/doc/html/rfc8200#section-4.3

use crate::ip::NextHeader;
use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError};
use etherparse::Ipv6RawExtHeader;
use std::num::NonZero;

/// IPv6 Hop-by-Hop Options header.
///
/// Wraps an [`Ipv6RawExtHeader`] from etherparse.  The inner type is boxed
/// because `Ipv6RawExtHeader` is ~2 KiB (variable-length payload buffer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopByHop(Box<Ipv6RawExtHeader>);

impl HopByHop {
    /// The minimum header length in bytes.
    #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
    pub const MIN_LEN: NonZero<u16> = NonZero::new(Ipv6RawExtHeader::MIN_LEN as u16).unwrap();

    /// Get the next-header protocol number.
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        NextHeader::from_ip_number(self.0.next_header)
    }

    /// Set the next-header protocol number.
    pub fn set_next_header(&mut self, nh: NextHeader) {
        self.0.next_header = nh.to_ip_number();
    }

    /// The raw TLV payload (excluding next-header and length fields).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.0.payload()
    }

    /// Parse the next header after this one.
    pub(crate) fn parse_payload(
        &self,
        cursor: &mut crate::parse::Reader,
    ) -> Option<crate::headers::Header> {
        super::ext_parse::parse_ext_payload(self.next_header(), cursor)
    }

    /// Parse the next header in an ICMP-embedded context.
    pub(crate) fn parse_embedded_payload(
        &self,
        cursor: &mut crate::parse::Reader,
    ) -> Option<crate::headers::EmbeddedHeader> {
        super::ext_parse::parse_ext_embedded_payload(self.next_header(), cursor)
    }
}

impl HopByHop {
    /// Wrap a raw extension header as a `HopByHop`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `inner` was reached via a preceding
    /// header whose `next_header` field was 0 (`IPV6_HEADER_HOP_BY_HOP`),
    /// confirming these bytes are a Hop-by-Hop Options header and not
    /// some other extension header sharing the [`Ipv6RawExtHeader`] format.
    #[allow(unsafe_code, dead_code)] // only called from test/builder cfg
    pub(crate) unsafe fn from_raw_unchecked(inner: Box<Ipv6RawExtHeader>) -> Self {
        Self(inner)
    }
}

impl Parse for HopByHop {
    type Error = std::convert::Infallible;

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
        let (inner, rest) = Ipv6RawExtHeader::from_slice(buf).map_err(|e| {
            ParseError::Length(LengthError {
                expected: NonZero::new(e.required_len).unwrap_or_else(|| unreachable!()),
                actual: e.len,
            })
        })?;
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

impl DeParse for HopByHop {
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

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::HopByHop;
    use crate::ipv6::raw_ext_gen::gen_raw_ext_header;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for HopByHop {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            #[allow(unsafe_code)]
            // SAFETY: gen_raw_ext_header produces a valid raw header and we are
            // declaring it to be a HopByHop, which is the type we're generating.
            Some(unsafe { HopByHop::from_raw_unchecked(gen_raw_ext_header(driver)?) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::HopByHop;
    use crate::parse::{DeParse, IntoNonZeroUSize, Parse};

    #[test]
    fn parse_back() {
        bolero::check!().with_type().for_each(|header: &HopByHop| {
            let mut buf = [0u8; 2048];
            let len = header.deparse(&mut buf).unwrap();
            let (header2, consumed) =
                HopByHop::parse(&buf[..len.into_non_zero_usize().get()]).unwrap();
            assert_eq!(consumed, len);
            assert_eq!(header, &header2);
        });
    }
}
