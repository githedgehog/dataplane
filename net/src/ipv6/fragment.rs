// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv6 Fragment header ([RFC 8200 section 4.5]).
//!
//! The Fragment header is used by an IPv6 source to send a packet larger
//! than would fit in the path MTU.  Unlike the other extension headers,
//! the Fragment header has a fixed 8-byte wire format and is small enough
//! to store inline (no boxing required).
//!
//! [RFC 8200 section 4.5]: https://datatracker.ietf.org/doc/html/rfc8200#section-4.5

use crate::ip::NextHeader;
use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError};
use etherparse::Ipv6FragmentHeader;
use std::num::NonZero;

/// IPv6 Fragment header.
///
/// Wraps an [`Ipv6FragmentHeader`] from etherparse.  At 8 bytes this is
/// small enough to store inline -- no heap allocation needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment(Ipv6FragmentHeader);

impl Fragment {
    /// The fixed header length in bytes.
    #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
    pub const LEN: NonZero<u16> = NonZero::new(Ipv6FragmentHeader::LEN as u16).unwrap();

    /// Get the next-header protocol number.
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        NextHeader::from(self.0.next_header)
    }

    /// Set the next-header protocol number.
    pub fn set_next_header(&mut self, nh: NextHeader) {
        self.0.next_header = nh.into();
    }

    /// The 13-bit fragment offset in 8-octet units.
    #[must_use]
    pub fn fragment_offset(&self) -> etherparse::IpFragOffset {
        self.0.fragment_offset
    }

    /// Whether more fragments follow this one.
    #[must_use]
    pub fn more_fragments(&self) -> bool {
        self.0.more_fragments
    }

    /// The identification value for fragment reassembly.
    #[must_use]
    pub fn identification(&self) -> u32 {
        self.0.identification
    }

    /// Returns `true` if this fragment header actually fragments the payload.
    ///
    /// A fragment header with offset 0 and `more_fragments == false` does not
    /// fragment -- it represents a whole datagram (see [RFC 6946]).
    ///
    /// [RFC 6946]: https://datatracker.ietf.org/doc/html/rfc6946
    #[must_use]
    pub fn is_fragmenting_payload(&self) -> bool {
        self.0.is_fragmenting_payload()
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

impl From<Ipv6FragmentHeader> for Fragment {
    fn from(inner: Ipv6FragmentHeader) -> Self {
        Self(inner)
    }
}

impl Parse for Fragment {
    type Error = etherparse::err::LenError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        if buf.len() < Self::LEN.get() as usize {
            return Err(ParseError::Length(LengthError {
                expected: Self::LEN.into_non_zero_usize(),
                actual: buf.len(),
            }));
        }
        let (inner, rest) = Ipv6FragmentHeader::from_slice(buf).map_err(ParseError::Invalid)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)]
        let consumed = NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!());
        Ok((Self(inner), consumed?))
    }
}

impl DeParse for Fragment {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        Self::LEN
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let size = self.size();
        if buf.len() < size.into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: size.into_non_zero_usize(),
                actual: buf.len(),
            }));
        }
        buf[..size.get() as usize].copy_from_slice(&self.0.to_bytes());
        Ok(size)
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::Fragment;
    use bolero::{Driver, TypeGenerator};
    use etherparse::{IpFragOffset, IpNumber, Ipv6FragmentHeader};

    impl TypeGenerator for Fragment {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let next_header: u8 = driver.produce()?;
            let offset_raw: u16 = driver.gen_u16(
                std::ops::Bound::Included(&0),
                std::ops::Bound::Included(&IpFragOffset::MAX_U16),
            )?;
            #[allow(unsafe_code)]
            // SAFETY: offset_raw is bounded to <= MAX_U16 by gen_u16 above.
            let offset = unsafe { IpFragOffset::new_unchecked(offset_raw) };
            let more_fragments: bool = driver.produce()?;
            let identification: u32 = driver.produce()?;
            Some(Fragment::from(Ipv6FragmentHeader::new(
                IpNumber(next_header),
                offset,
                more_fragments,
                identification,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Fragment;
    use crate::parse::{DeParse, IntoNonZeroUSize, Parse};

    #[test]
    fn parse_back() {
        bolero::check!().with_type().for_each(|header: &Fragment| {
            let mut buf = [0u8; 8];
            let len = header.deparse(&mut buf).unwrap();
            let (header2, consumed) =
                Fragment::parse(&buf[..len.into_non_zero_usize().get()]).unwrap();
            assert_eq!(consumed, len);
            assert_eq!(header, &header2);
        });
    }
}
