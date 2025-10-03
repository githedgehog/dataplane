// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `Icmp6` header type and logic.

mod checksum;

pub use checksum::*;

use crate::headers::{EmbeddedHeaders, EmbeddedIpVersion};
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParseWith, Reader,
};
use etherparse::{Icmpv6Header, Icmpv6Type};
use std::num::NonZero;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// An `Icmp6` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp6(pub(crate) Icmpv6Header);

impl Icmp6 {
    /// Returns the type of the `Icmp6` message.
    #[must_use]
    pub const fn icmp_type(&self) -> Icmpv6Type {
        self.0.icmp_type
    }

    /// Returns a mutable reference to the type of the `Icmp6` message.
    #[must_use]
    pub const fn icmp_type_mut(&mut self) -> &mut Icmpv6Type {
        &mut self.0.icmp_type
    }

    /// Returns true if the ICMP type is an error message
    #[must_use]
    pub fn is_error_message(&self) -> bool {
        // List all types to make it sure we catch any new addition to the enum
        match self.icmp_type() {
            Icmpv6Type::DestinationUnreachable(_)
            | Icmpv6Type::PacketTooBig { .. }
            | Icmpv6Type::TimeExceeded(_)
            | Icmpv6Type::ParameterProblem(_) => true,
            Icmpv6Type::Unknown { .. }
            | Icmpv6Type::EchoRequest(_)
            | Icmpv6Type::EchoReply(_)
            | Icmpv6Type::RouterSolicitation
            | Icmpv6Type::RouterAdvertisement(_)
            | Icmpv6Type::NeighborSolicitation
            | Icmpv6Type::NeighborAdvertisement(_)
            | Icmpv6Type::Redirect => false,
        }
    }

    /// Creates a new `Icmp6` with the given type.
    ///
    /// The checksum will be set to zero.
    #[must_use]
    pub const fn with_type(icmp_type: Icmpv6Type) -> Self {
        Self(Icmpv6Header {
            icmp_type,
            checksum: 0,
        })
    }

    fn payload_length(&self, buf: &[u8]) -> usize {
        // See RFC 4884.
        match self.icmp_type() {
            Icmpv6Type::DestinationUnreachable(_)
            | Icmpv6Type::TimeExceeded(_)
            | Icmpv6Type::ParameterProblem(_) => {
                let payload_length = buf[3];
                payload_length as usize * 8
            }
            _ => 0,
        }
    }

    pub(crate) fn parse_payload(&self, cursor: &mut Reader) -> Option<EmbeddedHeaders> {
        if !self.is_error_message() {
            return None;
        }
        let (mut headers, consumed) =
            EmbeddedHeaders::parse_with(EmbeddedIpVersion::Ipv6, cursor.inner).ok()?;
        cursor.consume(consumed).ok()?;

        // Mark whether the payload of the embedded IP packet is full
        headers.check_full_payload(
            &cursor.inner[cursor.inner.len() - cursor.remaining as usize..],
            cursor.remaining as usize,
            consumed.get() as usize,
            self.payload_length(cursor.inner),
        );

        Some(headers)
    }
}

impl Parse for Icmp6 {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = Icmpv6Header::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::Length(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Icmp6 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // header size bounded
        NonZero::new(self.0.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        buf[..self.size().into_non_zero_usize().get()].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::icmp6::Icmp6;
    use crate::parse::Parse;
    use bolero::{Driver, TypeGenerator};

    /// The number of bytes to use in parsing arbitrary test values for [`Icmp6`]
    pub const BYTE_SLICE_SIZE: usize = 128;

    impl TypeGenerator for Icmp6 {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let buf: [u8; BYTE_SLICE_SIZE] = driver.produce()?;
            let header = match Icmp6::parse(&buf) {
                Ok((h, _)) => h,
                Err(e) => unreachable!("{e:?}", e = e),
            };
            Some(header)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::icmp6::Icmp6;
    use crate::parse::{DeParse, Parse};

    fn parse_back_test_helper(header: &Icmp6) {
        let mut buf = [0; super::contract::BYTE_SLICE_SIZE];
        let bytes_written = header
            .deparse(&mut buf)
            .unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        let (parsed, bytes_read) =
            Icmp6::parse(&buf).unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        assert_eq!(header, &parsed);
        assert_eq!(bytes_written, bytes_read);
        assert_eq!(header.size(), bytes_read);
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!()
            .with_type()
            .for_each(parse_back_test_helper);
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(|buffer: &[u8; super::contract::BYTE_SLICE_SIZE]| {
                let (parsed, bytes_read) =
                    Icmp6::parse(buffer).unwrap_or_else(|e| unreachable!("{e:?}", e = e));
                assert_eq!(parsed.size(), bytes_read);
                parse_back_test_helper(&parsed);
            });
    }
}
