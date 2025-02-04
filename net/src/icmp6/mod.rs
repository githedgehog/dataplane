// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv6` header type and logic.

use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError};
use etherparse::Icmpv6Header;
use std::num::NonZero;

/// An `ICMPv6` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp6(Icmpv6Header);

impl Parse for Icmp6 {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
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
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Icmp6 {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.0.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        buf[..self.size().get()].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}
