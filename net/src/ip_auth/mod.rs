// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP authentication header type and logic.

use crate::headers::Header;
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::ipv4::Ipv4;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload, Reader,
};
use crate::tcp::Tcp;
use crate::udp::Udp;
use arrayvec::ArrayVec;
use etherparse::err::ip_auth::{HeaderError, HeaderSliceError};
use etherparse::{IpAuthHeader, IpNumber};
use std::cmp::min;
use std::num::NonZero;
use tracing::{debug, trace};

/// An Ip authentication header.
///
/// This may appear in IPv4 and IPv6 headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAuth {
    pub(crate) header: Box<IpAuthHeader>,
}

impl IpAuth {
    /// The maximum length of n `IpAuth` header.
    pub const MAX_LEN: usize = IpAuthHeader::MAX_LEN;
}

/// Errors which may occur when parsing an [`IpAuth`] header
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpAuthError {
    /// zero is not a valid payload length
    #[error("zero is not a valid payload length for IP authentication")]
    ZeroPayloadLength,
    /// [`IpAuth`] headers must be zero padded to multiples of 4 bytes
    #[error("ip auth padding failure")]
    InvalidPadding,
}

impl Parse for IpAuth {
    type Error = IpAuthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = IpAuthHeader::from_slice(buf).map_err(|e| match e {
            HeaderSliceError::Len(e) => ParseError::Length(LengthError {
                expected: NonZero::new(e.required_len).unwrap_or_else(|| unreachable!()),
                actual: buf.len(),
            }),
            HeaderSliceError::Content(e) => match e {
                HeaderError::ZeroPayloadLen => ParseError::Invalid(IpAuthError::ZeroPayloadLength),
            },
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed = buf.len() - rest.len();
        if consumed % 4 != 0 {
            return Err(ParseError::Invalid(IpAuthError::InvalidPadding));
        }
        let consumed = NonZero::new(u16::try_from(consumed).unwrap_or_else(|_| unreachable!()))
            .unwrap_or_else(|| unreachable!());
        Ok((
            Self {
                header: Box::new(inner),
            },
            consumed,
        ))
    }
}

impl DeParse for IpAuth {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        NonZero::new(
            u16::try_from(12 + self.header.raw_icv().len()).unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(DeParseError::BufferTooLong(buf.len()));
        }
        let buf_len = buf.len();
        let self_size = self.size().get() as usize;
        if buf_len < self_size {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: buf_len,
            }));
        }
        buf[..self_size].copy_from_slice(&self.header.to_bytes());
        Ok(self.size())
    }
}
