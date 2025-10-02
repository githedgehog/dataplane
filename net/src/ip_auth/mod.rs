// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP authentication header type and logic.

use crate::headers::Header;
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::impl_from_for_enum;
use crate::parse::{Parse, ParseError, ParseHeader, Reader};
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::{IpAuthHeader, IpNumber};
use std::num::NonZero;
use tracing::{debug, trace};

/// An Ip authentication header.
///
/// This may appear in IPv4 and IPv6 headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAuth(Box<IpAuthHeader>);

impl IpAuth {
    /// Parse the payload of the IP authentication header.
    ///
    /// # Returns
    ///
    /// * `Some(IpAuthNext)`: the parsed next header, if supported.
    /// * `None`: if parsing the next header is not supported.
    pub(crate) fn parse_payload(&self, cursor: &mut Reader) -> Option<IpAuthNext> {
        match self.0.next_header {
            IpNumber::TCP => cursor.parse_header::<Tcp, IpAuthNext>(),
            IpNumber::UDP => cursor.parse_header::<Udp, IpAuthNext>(),
            IpNumber::ICMP => cursor.parse_header::<Icmp4, IpAuthNext>(),
            IpNumber::IPV6_ICMP => cursor.parse_header::<Icmp6, IpAuthNext>(),
            IpNumber::AUTHENTICATION_HEADER => {
                debug!("nested ip auth header");
                cursor.parse_header::<IpAuth, IpAuthNext>()
            }
            _ => {
                trace!("unsupported protocol: {:?}", self.0.next_header);
                None
            }
        }
    }
}

impl Parse for IpAuth {
    type Error = etherparse::err::ip_auth::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = IpAuthHeader::from_slice(buf)
            .map(|(h, rest)| (Box::new(h), rest))
            .map_err(ParseError::Invalid)?;
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

pub(crate) enum IpAuthNext {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
}

impl_from_for_enum![
    IpAuthNext,
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
    IpAuth(IpAuth)
];

impl From<IpAuthNext> for Header {
    fn from(value: IpAuthNext) -> Self {
        match value {
            IpAuthNext::Tcp(x) => Header::Tcp(x),
            IpAuthNext::Udp(x) => Header::Udp(x),
            IpAuthNext::Icmp4(x) => Header::Icmp4(x),
            IpAuthNext::Icmp6(x) => Header::Icmp6(x),
            IpAuthNext::IpAuth(x) => Header::IpAuth(x),
        }
    }
}
