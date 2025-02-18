// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv6` header type and logic.

use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload, Reader,
};
use etherparse::Icmpv6Header;
use std::num::NonZero;

#[cfg(any(test, feature = "arbitrary"))]
pub use contract::*;

/// An `ICMPv6` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp6(Icmpv6Header);

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

impl ParsePayload for Icmp6 {
    type Next = ();

    /// We don't currently support parsing below the Icmp6 layer
    fn parse_payload(&self, _cursor: &mut Reader) -> Option<Self::Next> {
        None
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

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::icmp6::Icmp6;
    use crate::parse::Parse;
    use bolero::{Driver, TypeGenerator};

    /// The number of bytes to use in parsing arbitrary test values for [`Icmp6`]
    pub const BYTE_SLICE_SIZE: usize = 128;

    impl TypeGenerator for Icmp6 {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let buf: [u8; BYTE_SLICE_SIZE] = driver.gen()?;
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
