//! Ipv4 Address type and manipulation

use crate::icmp4::Icmp4;
use crate::ip_auth::IpAuth;
use crate::packet::Header;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, Reader, Step};
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::{IpNumber, Ipv4Header};
use std::num::NonZero;
use tracing::{debug, trace};

pub mod addr;

/// An IPv4 header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    inner: Ipv4Header,
}

impl Parse for Ipv4 {
    type Error = etherparse::err::ipv4::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Ipv4Header::from_slice(buf).map_err(ParseError::FailedToParse)?;
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

impl DeParse for Ipv4 {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.inner.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::LengthError(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        buf[..self.size().get()].copy_from_slice(&self.inner.to_bytes());
        Ok(self.size())
    }
}

pub(crate) enum Ipv4Next {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    IpAuth(IpAuth),
}

impl Step for Ipv4 {
    type Next = Ipv4Next;

    fn step(&self, cursor: &mut Reader) -> Option<Self::Next> {
        match self.inner.protocol {
            IpNumber::TCP => cursor
                .parse::<Tcp>()
                .map_err(|e| {
                    debug!("failed to parse tcp: {e:?}");
                })
                .map(|(val, _)| Ipv4Next::Tcp(val))
                .ok(),
            IpNumber::UDP => cursor
                .parse::<Udp>()
                .map_err(|e| {
                    debug!("failed to parse udp: {e:?}");
                })
                .map(|(val, _)| Ipv4Next::Udp(val))
                .ok(),
            IpNumber::ICMP => cursor
                .parse::<Icmp4>()
                .map_err(|e| {
                    debug!("failed to parse icmp4: {e:?}");
                })
                .map(|(val, _)| Ipv4Next::Icmp4(val))
                .ok(),
            IpNumber::AUTHENTICATION_HEADER => cursor
                .parse::<IpAuth>()
                .map_err(|e| {
                    debug!("failed to parse IpAuth: {e:?}");
                })
                .map(|(val, _)| Ipv4Next::IpAuth(val))
                .ok(),
            _ => {
                trace!("unsupported protocol: {:?}", self.inner.protocol);
                None
            }
        }
    }
}

impl From<Ipv4Next> for Header {
    fn from(value: Ipv4Next) -> Self {
        match value {
            Ipv4Next::Tcp(x) => Header::Tcp(x),
            Ipv4Next::Udp(x) => Header::Udp(x),
            Ipv4Next::Icmp4(x) => Header::Icmp4(x),
            Ipv4Next::IpAuth(x) => Header::IpAuth(x),
        }
    }
}
