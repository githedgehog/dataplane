// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IP authentication header type and logic.

use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::packet::Header;
use crate::parse::{Parse, ParseError, ParsePayload, Reader};
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::{IpAuthHeader, IpNumber};
use std::num::NonZero;
use tracing::{debug, trace};

/// An Ip authentication header.
///
/// This may appear in IPv4 and IPv6 headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAuth {
    inner: Box<IpAuthHeader>,
}

impl Parse for IpAuth {
    type Error = etherparse::err::ip_auth::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = IpAuthHeader::from_slice(buf)
            .map(|(h, rest)| (Box::new(h), rest))
            .map_err(ParseError::Invalid)?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

pub(crate) enum IpAuthNext {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
}

impl ParsePayload for IpAuth {
    type Next = IpAuthNext;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<Self::Next> {
        match self.inner.next_header {
            IpNumber::TCP => cursor
                .parse::<Tcp>()
                .map_err(|e| {
                    debug!("failed to parse tcp: {e:?}");
                })
                .map(|(val, _)| Self::Next::Tcp(val))
                .ok(),
            IpNumber::UDP => cursor
                .parse::<Udp>()
                .map_err(|e| {
                    debug!("failed to parse udp: {e:?}");
                })
                .map(|(val, _)| Self::Next::Udp(val))
                .ok(),
            IpNumber::ICMP => cursor
                .parse::<Icmp4>()
                .map_err(|e| {
                    debug!("failed to parse icmp4: {e:?}");
                })
                .map(|(val, _)| Self::Next::Icmp4(val))
                .ok(),
            IpNumber::IPV6_ICMP => cursor
                .parse::<Icmp6>()
                .map_err(|e| {
                    debug!("failed to parse icmp6: {e:?}");
                })
                .map(|(val, _)| Self::Next::Icmp6(val))
                .ok(),
            IpNumber::AUTHENTICATION_HEADER => {
                debug!("nested ip auth header");
                cursor
                    .parse::<IpAuth>()
                    .map_err(|e| {
                        debug!("failed to parse ip auth header: {e:?}");
                    })
                    .map(|(val, _)| Self::Next::IpAuth(val))
                    .ok()
            }
            _ => {
                trace!("unsupported protocol: {:?}", self.inner.next_header);
                None
            }
        }
    }
}

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
