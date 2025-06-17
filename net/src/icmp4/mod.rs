// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv4` header type and logic.

use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload, Reader,
};
use etherparse::{Icmpv4Header, Icmpv4Type};

mod checksum;

pub use checksum::*;

use std::num::NonZero;

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// An `ICMPv4` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp4(pub(crate) Icmpv4Header);

impl Icmp4 {
    /// Get the icmp type (reference) field value
    #[must_use]
    pub const fn icmp_type(&self) -> &Icmpv4Type {
        &self.0.icmp_type
    }

    /// Return a mutable reference to the icmp type field value
    #[must_use]
    pub const fn icmp_type_mut(&mut self) -> &mut Icmpv4Type {
        &mut self.0.icmp_type
    }

    /// Create a new `Icmp4` with the given icmp type.
    /// The checksum will be set to 0.
    #[must_use]
    pub const fn with_type(icmp_type: Icmpv4Type) -> Self {
        Icmp4(Icmpv4Header {
            icmp_type,
            checksum: 0,
        })
    }
}

impl Parse for Icmp4 {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = Icmpv4Header::from_slice(buf).map_err(|e| {
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
        #[allow(clippy::cast_possible_truncation)] // checked above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Icmp4 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // header length bounded
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

impl ParsePayload for Icmp4 {
    type Next = ();

    /// We don't currently support parsing below the Icmp4 layer
    fn parse_payload(&self, _cursor: &mut Reader) -> Option<Self::Next> {
        None
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::icmp4::Icmp4;
    use crate::parse::{Parse, ParseError};
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for Icmp4 {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            // TODO: 20 bytes is far too small to properly test the space of `Icmp4`
            // We will need better error handling if we want to bump it up tho.
            let buffer: [u8; 20] = driver.produce()?;
            let icmp4 = match Icmp4::parse(&buffer) {
                Ok((icmp4, _)) => icmp4,
                Err(ParseError::Length(l)) => unreachable!("{:?}", l),
                Err(ParseError::Invalid(e)) => unreachable!("{:?}", e),
                Err(ParseError::BufferTooLong(_)) => {
                    unreachable!()
                }
            };
            Some(icmp4)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::icmp4::Icmp4;
    use crate::parse::{DeParse, DeParseError, Parse, ParseError};

    #[test]
    fn parse_back() {
        bolero::check!().with_type().for_each(|input: &Icmp4| {
            // TODO: 20 bytes is far too small to properly test the space of `Icmp4`
            // We will need better error handling if we want to bump it up tho.
            let mut buffer = [0u8; 20];
            let bytes_written = match input.deparse(&mut buffer) {
                Ok(bytes_written) => bytes_written,
                Err(DeParseError::Length(l)) => unreachable!("{:?}", l),
                Err(DeParseError::Invalid(())) => {
                    unreachable!()
                }
                Err(DeParseError::BufferTooLong(_)) => unreachable!(),
            };
            let (parsed, bytes_read) = match Icmp4::parse(&buffer) {
                Ok((parsed, bytes_read)) => (parsed, bytes_read),
                Err(ParseError::Invalid(e)) => unreachable!("{e:?}"),
                Err(ParseError::Length(l)) => unreachable!("{l:?}"),
                Err(ParseError::BufferTooLong(_)) => unreachable!(),
            };
            assert_eq!(input, &parsed);
            assert_eq!(bytes_written, bytes_read);
        });
    }
}
