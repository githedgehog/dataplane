//! Ipv6 Address type and manipulation

use crate::icmp6::Icmp6;
use crate::ip_auth::IpAuth;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, ParseWith, Reader, Step, StepWith};
use crate::tcp::Tcp;
use crate::udp::Udp;
#[cfg(any(test, feature = "bolero", kani))]
use bolero::Driver;
use etherparse::ip_number::{
    AUTHENTICATION_HEADER, IPV6_DESTINATION_OPTIONS, IPV6_FRAGMENTATION_HEADER,
    IPV6_HEADER_HOP_BY_HOP, IPV6_ICMP, IPV6_ROUTE_HEADER, TCP, UDP,
};
use etherparse::{IpNumber, Ipv6Extensions, Ipv6Header};
use std::num::NonZero;
use tracing::{debug, trace};
use crate::packet::Header;

pub mod addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    inner: Ipv6Header,
}

impl Ipv6 {
    pub fn next_header(&self) -> IpNumber {
        self.inner.next_header
    }
}

impl Parse for Ipv6 {
    type Error = etherparse::err::ipv6::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Ipv6Header::from_slice(buf).map_err(ParseError::FailedToParse)?;
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

impl DeParse for Ipv6 {
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

pub enum Ipv6Next {
    Tcp(Tcp),
    Udp(Udp),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
    Ipv6Ext(Ipv6Ext),
}

impl Step for Ipv6 {
    type Next = Ipv6Next;

    fn step(&self, cursor: &mut Reader) -> Option<Self::Next> {
        match self.inner.next_header {
            IpNumber::TCP => cursor
                .parse::<Tcp>()
                .map_err(|e| {
                    debug!("failed to parse tcp: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::Tcp(val))
                .ok(),
            IpNumber::UDP => cursor
                .parse::<Udp>()
                .map_err(|e| {
                    debug!("failed to parse udp: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::Udp(val))
                .ok(),
            IpNumber::ICMP => cursor
                .parse::<Icmp6>()
                .map_err(|e| {
                    debug!("failed to parse icmp4: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::Icmp6(val))
                .ok(),
            IpNumber::AUTHENTICATION_HEADER => cursor
                .parse::<IpAuth>()
                .map_err(|e| {
                    debug!("failed to parse IpAuth: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::IpAuth(val))
                .ok(),
            IpNumber::IPV6_HEADER_HOP_BY_HOP
            | IpNumber::IPV6_ROUTE_HEADER
            | IpNumber::IPV6_FRAGMENTATION_HEADER
            | IpNumber::IPV6_DESTINATION_OPTIONS => cursor
                .parse_with::<Ipv6Ext>(self.inner.next_header)
                .map_err(|e| {
                    debug!("failed to parse ipv6 extension header: {e:?}");
                })
                .map(|(val, _)| Self::Next::Ipv6Ext(val))
                .ok(),
            _ => {
                trace!("unsupported protocol: {:?}", self.inner.next_header);
                None
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Ext {
    inner: Box<Ipv6Extensions>,
}

impl ParseWith for Ipv6Ext {
    type Error = etherparse::err::ipv6_exts::HeaderSliceError;
    type Param = IpNumber;

    fn parse_with(
        ip_number: IpNumber,
        buf: &[u8],
    ) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = Ipv6Extensions::from_slice(ip_number, buf)
            .map(|(h, _, rest)| (Box::new(h), rest))
            .map_err(ParseError::FailedToParse)?;
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

pub enum Ipv6ExtNext {
    Tcp(Tcp),
    Udp(Udp),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
    Ipv6Ext(Ipv6Ext),
}

impl From<Ipv6Next> for Header {
    fn from(value: Ipv6Next) -> Self {
        match value {
            Ipv6Next::Tcp(x) => Header::Tcp(x),
            Ipv6Next::Udp(x) => Header::Udp(x),
            Ipv6Next::Icmp6(x) => Header::Icmp6(x),
            Ipv6Next::IpAuth(x) => Header::IpAuth(x),
            Ipv6Next::Ipv6Ext(x) => Header::IpV6Ext(x),
        }
    }
}

impl StepWith for Ipv6Ext {
    type Param = IpNumber;
    type Next = Ipv6ExtNext;

    fn step_with(&self, first_ip_number: &IpNumber, cursor: &mut Reader) -> Option<Self::Next> {
        use etherparse::ip_number::{
            AUTHENTICATION_HEADER, IPV6_DESTINATION_OPTIONS, IPV6_FRAGMENTATION_HEADER,
            IPV6_HEADER_HOP_BY_HOP, IPV6_ICMP, IPV6_ROUTE_HEADER, TCP, UDP,
        };
        let next_header = self
            .inner
            .next_header(*first_ip_number)
            .map_err(|e| debug!("failed to parse: {e:?}"))
            .ok()?;
        match next_header {
            TCP => cursor
                .parse::<Tcp>()
                .map_err(|e| {
                    debug!("failed to parse tcp: {e:?}");
                })
                .map(|(val, _)| Self::Next::Tcp(val))
                .ok(),
            UDP => cursor
                .parse::<Udp>()
                .map_err(|e| {
                    debug!("failed to parse udp: {e:?}");
                })
                .map(|(val, _)| Self::Next::Udp(val))
                .ok(),
            IPV6_ICMP => cursor
                .parse::<Icmp6>()
                .map_err(|e| {
                    debug!("failed to parse icmp4: {e:?}");
                })
                .map(|(val, _)| Self::Next::Icmp6(val))
                .ok(),
            AUTHENTICATION_HEADER => {
                debug!("nested ip auth header");
                cursor
                    .parse::<IpAuth>()
                    .map_err(|e| {
                        debug!("failed to parse ip auth header: {e:?}");
                    })
                    .map(|(val, _)| Self::Next::IpAuth(val))
                    .ok()
            }
            IPV6_HEADER_HOP_BY_HOP
            | IPV6_ROUTE_HEADER
            | IPV6_FRAGMENTATION_HEADER
            | IPV6_DESTINATION_OPTIONS => cursor
                .parse_with::<Ipv6Ext>(next_header)
                .map_err(|e| {
                    debug!("failed to parse ipv6 extension header: {e:?}");
                })
                .map(|(val, _)| Self::Next::Ipv6Ext(val))
                .ok(),
            _ => {
                trace!("unsupported protocol: {next_header:?}");
                None
            }
        }
    }
}

impl From<Ipv6ExtNext> for Header {
    fn from(value: Ipv6ExtNext) -> Self {
        match value {
            Ipv6ExtNext::Tcp(x) => Header::Tcp(x),
            Ipv6ExtNext::Udp(x) => Header::Udp(x),
            Ipv6ExtNext::Icmp6(x) => Header::Icmp6(x),
            Ipv6ExtNext::IpAuth(x) => Header::IpAuth(x),
            Ipv6ExtNext::Ipv6Ext(x) => Header::IpV6Ext(x),
        }
    }
}
