// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ipv6 Address type and manipulation

use crate::icmp6::Icmp6;
use crate::ip::NextHeader;
use crate::ip_auth::IpAuth;
use crate::ipv6::addr::UnicastIpv6Addr;
use crate::ipv6::flow_label::FlowLabel;
use crate::packet::Header;
use crate::parse::{
    DeParse, DeParseError, LengthError, Parse, ParseError, ParsePayload, ParsePayloadWith,
    ParseWith, Reader,
};
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::{IpNumber, Ipv6Extensions, Ipv6Header};
use std::net::Ipv6Addr;
use std::num::NonZero;
use tracing::{debug, trace};

pub mod addr;
pub mod flow_label;

/// An IPv6 header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6(Ipv6Header);
impl Ipv6 {
    /// The minimum length (in bytes) of an [`Ipv6`] header.
    #[allow(clippy::unwrap_used)] // safe due to const eval
    pub const MIN_LEN: NonZero<usize> = NonZero::new(40).unwrap();

    /// Create a new [`Ipv6`] header
    ///
    /// # Errors
    ///
    /// Returns an [`Ipv6Error::InvalidSourceAddr`] error if the source address is invalid.
    pub fn new(header: Ipv6Header) -> Result<Self, Ipv6Error> {
        UnicastIpv6Addr::new(Ipv6Addr::from(header.source))
            .map_err(Ipv6Error::InvalidSourceAddr)?;
        Ok(Self(header))
    }

    /// Get the source [`Ipv6Addr`] for this header
    #[must_use]
    pub fn source(&self) -> UnicastIpv6Addr {
        UnicastIpv6Addr::new(Ipv6Addr::from(self.0.source)).unwrap_or_else(|_| unreachable!())
    }

    /// Get the destination [`Ipv6Addr`] for this header
    #[must_use]
    pub fn destination(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.0.destination)
    }

    /// Get the [`IpNumber`] type of the next header.
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        NextHeader::new(self.0.next_header.0)
    }

    /// Get the hop limit for this header (analogous to [`crate::ipv4::Ipv4::ttl`])
    #[must_use]
    pub fn hop_limit(&self) -> u8 {
        self.0.hop_limit
    }

    // TODO: proper wrapper type (low priority)
    /// Get the [traffic class] for this header
    ///
    /// [traffic class]: https://datatracker.ietf.org/doc/html/rfc8200#section-7
    #[must_use]
    pub fn traffic_class(&self) -> u8 {
        self.0.traffic_class
    }

    // TODO: proper wrapper type (low priority)
    /// Get this header's [flow label].
    ///
    /// [flow label]: https://datatracker.ietf.org/doc/html/rfc6437
    #[must_use]
    pub fn flow_label(&self) -> FlowLabel {
        FlowLabel::new(self.0.flow_label.value()).unwrap_or_else(|_| unreachable!())
    }

    /// Set the source ip address of this header
    pub fn set_source(&mut self, source: UnicastIpv6Addr) -> &mut Self {
        self.0.source = source.inner().octets();
        self
    }

    /// Set the source ip address of this header (confirming that this is a legal source ip).
    ///
    /// # Safety
    ///
    /// This method does not check to ensure that the source is valid.
    /// For example, a multicast source can be assigned to a packet with this method.
    ///
    /// Note(manish) Why do we even have this function?
    #[allow(unsafe_code)]
    pub unsafe fn set_source_unchecked(&mut self, source: Ipv6Addr) -> &mut Self {
        self.0.source = source.octets();
        self
    }

    /// Set the destination ip address of this header
    ///
    /// # Safety
    ///
    /// This method does not check that the supplied destination address is non-zero.
    ///
    /// Arguably, this method should be `unsafe` on those grounds.
    /// That said, it is unlikely that networking equipment will malfunction in the presence of a
    /// zero destination (unlike a multicast-source).
    /// I judged it to be ok to skip the check.
    pub fn set_destination(&mut self, destination: Ipv6Addr) -> &mut Self {
        self.0.destination = destination.octets();
        self
    }

    /// Set the hop limit for this header (analogous to [`crate::ipv4::Ipv4::set_ttl`])
    pub fn set_hop_limit(&mut self, hop_limit: u8) -> &mut Self {
        self.0.hop_limit = hop_limit;
        self
    }

    /// Set the hop limit for this header (analogous to [`crate::ipv4::Ipv4::set_ttl`])
    ///
    /// # Errors
    ///
    /// Will return a [`HopLimitAlreadyZeroError`] error if the hop limit is already zero :)
    pub fn decrement_hop_limit(&mut self) -> Result<(), HopLimitAlreadyZeroError> {
        if self.0.hop_limit == 0 {
            return Err(HopLimitAlreadyZeroError);
        }
        self.0.hop_limit -= 1;
        Ok(())
    }

    // TODO: wrapper type (low priority)
    /// Set the [traffic class] for this header
    ///
    /// [traffic class]: https://datatracker.ietf.org/doc/html/rfc8200#section-7
    pub fn set_traffic_class(&mut self, traffic_class: u8) -> &mut Self {
        self.0.traffic_class = traffic_class;
        self
    }

    /// Set this header's [flow label].
    ///
    /// [flow label]: https://datatracker.ietf.org/doc/html/rfc6437
    pub fn set_flow_label(&mut self, flow_label: FlowLabel) -> &mut Self {
        self.0.flow_label = flow_label.0;
        self
    }

    /// Set the next header [`IpNumber`]
    ///
    /// # Safety
    ///
    /// This method makes no attempt to ensure that the supplied [`next_header`] value is valid for
    /// the packet to which this header belongs (if any).
    ///
    /// [`next_header`]: NextHeader
    pub fn set_next_header(&mut self, next_header: NextHeader) -> &mut Self {
        self.0.next_header = next_header.0;
        self
    }
}

/// An error which occurs if you attempt to decrement the hop limit of an [`Ipv6`] header when the
/// hop limit is already zero.
#[repr(transparent)]
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("hop limit already zero")]
pub struct HopLimitAlreadyZeroError;

/// Error which is triggered during construction of an [`Ipv6`] object.
#[derive(thiserror::Error, Debug)]
pub enum Ipv6Error {
    /// source-address is invalid because it is a multicast address
    #[error("multicast source forbidden (received {0})")]
    InvalidSourceAddr(Ipv6Addr),
    /// error triggered when etherparse fails to parse the header
    #[error(transparent)]
    Invalid(etherparse::err::ipv6::HeaderSliceError),
}

impl Parse for Ipv6 {
    type Error = Ipv6Error;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        if buf.len() < Ipv6::MIN_LEN.get() {
            return Err(ParseError::Length(LengthError {
                expected: Ipv6::MIN_LEN,
                actual: buf.len(),
            }));
        }
        let (header, rest) =
            Ipv6Header::from_slice(buf).map_err(|e| ParseError::Invalid(Ipv6Error::Invalid(e)))?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self::new(header).map_err(ParseError::Invalid)?, consumed))
    }
}

impl DeParse for Ipv6 {
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
        }
        buf[..self.size().get()].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}

pub(crate) enum Ipv6Next {
    Tcp(Tcp),
    Udp(Udp),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
    Ipv6Ext(Ipv6Ext),
}

impl ParsePayload for Ipv6 {
    type Next = Ipv6Next;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<Self::Next> {
        match self.0.next_header {
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
                .parse_with::<Ipv6Ext>(self.0.next_header)
                .map_err(|e| {
                    debug!("failed to parse ipv6 extension header: {e:?}");
                })
                .map(|(val, _)| Self::Next::Ipv6Ext(val))
                .ok(),
            _ => {
                trace!("unsupported protocol: {:?}", self.0.next_header);
                None
            }
        }
    }
}

/// An IPv6 extension header.
///
/// TODO: break this into multiple types (one per each header type).
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

pub(crate) enum Ipv6ExtNext {
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

impl ParsePayloadWith for Ipv6Ext {
    type Param = NextHeader;
    type Next = Ipv6ExtNext;

    fn parse_payload_with(
        &self,
        first_ip_number: &NextHeader,
        cursor: &mut Reader,
    ) -> Option<Self::Next> {
        use etherparse::ip_number::{
            AUTHENTICATION_HEADER, IPV6_DESTINATION_OPTIONS, IPV6_FRAGMENTATION_HEADER,
            IPV6_HEADER_HOP_BY_HOP, IPV6_ICMP, IPV6_ROUTE_HEADER, TCP, UDP,
        };
        let next_header = self
            .inner
            .next_header(first_ip_number.inner())
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

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ipv6::Ipv6;
    use bolero::{Driver, TypeGenerator};
    use etherparse::Ipv6Header;
    use std::net::Ipv6Addr;

    impl TypeGenerator for Ipv6 {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let mut header = Ipv6(Ipv6Header::default());
            header
                .set_source(u.gen()?)
                .set_destination(Ipv6Addr::from(u.gen::<u128>()?))
                .set_next_header(u.gen()?)
                .set_flow_label(u.gen()?)
                .set_traffic_class(u.gen()?)
                .set_hop_limit(u.gen()?);
            Some(header)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test {
    use crate::ipv6::{Ipv6, Ipv6Error};
    use crate::parse::{DeParse, Parse, ParseError};
    use etherparse::err::ipv6::{HeaderError, HeaderSliceError};

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!().with_type().for_each(|header: &Ipv6| {
            let mut buf = [0u8; Ipv6::MIN_LEN.get()];
            let len = header.deparse(&mut buf).unwrap().get();
            let (header2, consumed) = crate::ipv6::Ipv6::parse(&buf[..len]).unwrap();
            assert_eq!(consumed.get(), len);
            assert_eq!(header, &header2);
        });
    }

    #[test]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; Ipv6::MIN_LEN.get()]| {
                let (header, bytes_read) = match Ipv6::parse(slice) {
                    Ok((header, bytes_read)) => (header, bytes_read),
                    Err(ParseError::Invalid(Ipv6Error::InvalidSourceAddr(source))) => {
                        assert!(source.is_multicast());
                        return;
                    }
                    Err(ParseError::Invalid(Ipv6Error::Invalid(HeaderSliceError::Content(
                        HeaderError::UnexpectedVersion { version_number },
                    )))) => {
                        assert_ne!(version_number, 6);
                        return;
                    }
                    _ => unreachable!(),
                };
                assert_eq!(bytes_read.get(), slice.len());
                let mut slice2 = [0u8; Ipv6::MIN_LEN.get()];
                header
                    .deparse(&mut slice2)
                    .unwrap_or_else(|e| unreachable!("{e:?}"));
                let (parse_back, bytes_read2) =
                    Ipv6::parse(&slice2).unwrap_or_else(|e| unreachable!("{e:?}"));
                assert_eq!(bytes_read2.get(), slice2.len());
                assert_eq!(header, parse_back);
                assert_eq!(slice, &slice2);
            });
    }

    #[test]
    fn parse_arbitrary_bytes_too_short() {
        bolero::check!()
            .with_type()
            .for_each(
                |slice: &[u8; Ipv6::MIN_LEN.get() - 1]| match Ipv6::parse(slice) {
                    Err(ParseError::Length(e)) => {
                        assert_eq!(e.expected, Ipv6::MIN_LEN);
                        assert_eq!(e.actual, Ipv6::MIN_LEN.get() - 1);
                    }
                    _ => unreachable!(),
                },
            );
    }

    #[test]
    fn parse_arbitrary_bytes_above_minimum() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; 4 * Ipv6::MIN_LEN.get()]| {
                let (header, bytes_read) = match Ipv6::parse(slice) {
                    Ok((header, bytes_read)) => (header, bytes_read),
                    Err(ParseError::Invalid(Ipv6Error::InvalidSourceAddr(source))) => {
                        assert!(source.is_multicast());
                        return;
                    }
                    Err(ParseError::Invalid(Ipv6Error::Invalid(HeaderSliceError::Content(
                        HeaderError::UnexpectedVersion { version_number },
                    )))) => {
                        assert_ne!(version_number, 6);
                        return;
                    }
                    _ => unreachable!(),
                };
                assert!(bytes_read >= Ipv6::MIN_LEN);
                let mut slice2 = [0u8; Ipv6::MIN_LEN.get()];
                header
                    .deparse(&mut slice2)
                    .unwrap_or_else(|e| unreachable!("{e:?}"));
                let (parse_back, bytes_read2) =
                    Ipv6::parse(&slice2).unwrap_or_else(|e| unreachable!("{e:?}"));
                assert_eq!(bytes_read2.get(), slice2.len());
                assert_eq!(header, parse_back);
                assert_eq!(&slice[..Ipv6::MIN_LEN.get()], &slice2);
            });
    }
}
