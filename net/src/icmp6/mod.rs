// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv6` header type and logic.

use crate::parse::{
    DeParse, DeParseError, LengthError, NonZeroUnSizedNumericUpcast, Parse, ParseError,
    ParsePayload, Reader,
};
use etherparse::Icmpv6Header;
use std::num::NonZero;

/// An `ICMPv6` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp6(Icmpv6Header);

impl Parse for Icmp6 {
    type Error = LengthError;

    fn parse<T: AsRef<[u8]>>(buf: T) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let buf = buf.as_ref();
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

    fn deparse<T: AsMut<[u8]>>(
        &self,
        mut buf: T,
    ) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let buf = buf.as_mut();
        let len = buf.len();
        if len < self.size().cast().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().cast(),
                actual: len,
            }));
        }
        buf[..self.size().cast().get()].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}
