// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP authentication header type and logic.

use std::cmp::min;
use crate::headers::Header;
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload, Reader};
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::{IpAuthHeader, IpNumber};
use std::num::NonZero;
use arrayvec::ArrayVec;
use tracing::{debug, trace};
use crate::ipv4::Ipv4;

/// An Ip authentication header.
///
/// This may appear in IPv4 and IPv6 headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAuth(pub(crate) Box<IpAuthHeader>);

impl IpAuth {
    /// The maximum length of n `IpAuth` header.
    pub const MAX_LEN: usize = IpAuthHeader::MAX_LEN;

}


impl Parse for IpAuth {
    type Error = etherparse::err::ip_auth::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = IpAuthHeader::from_slice(buf).map_err(ParseError::Invalid)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed = buf.len() - rest.len();
        let remainder = consumed % 4;
        if consumed + remainder > buf.len() {
            return Err(ParseError::Length(LengthError {
                expected: consumed + remainder,
                actual: buf.len(),
            }));
        }
        if remainder != 0 {
            let adjusted = min(consumed + remainder, buf.len());

        }
        Ok((Self(Box::new(inner)), consumed))
    }
}

impl DeParse for IpAuth {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        NonZero::new(u16::try_from(self.0.header_len()).unwrap_or_else(|_| unreachable!()))
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
        buf[..self_size].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}
