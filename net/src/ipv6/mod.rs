// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ipv6 Address type and manipulation

use crate::headers::Header;
use crate::icmp6::Icmp6;
use crate::ip::NextHeader;
use crate::ip_auth::IpAuth;
pub use crate::ipv6::addr::UnicastIpv6Addr;
use crate::ipv6::flow_label::FlowLabel;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParseHeader,
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

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// An IPv6 header
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv6(pub(crate) Ipv6Header);

impl Ipv6 {
    /// The minimum length (in bytes) of an [`Ipv6`] header.
    #[allow(clippy::unwrap_used)] // safe due to const eval
    pub const MIN_LEN: NonZero<u16> = NonZero::new(40).unwrap();

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

    /// Set the payload length.
    ///
    /// # Safety
    ///
    /// This method does not (and cannot) check that the length is correct in the context of the
    /// packet as a whole.
    pub fn set_payload_length(&mut self, length: u16) -> &mut Self {
        self.0
            .set_payload_length(length as usize)
            .unwrap_or_else(|_| unreachable!());
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

    /// Parse the payload of this header.
    ///
    /// # Returns
    ///
    /// * `Some(Ipv6Next)` variant if the payload was successfully parsed as a next header.
    /// * `None` if the next header is not supported.
    pub(crate) fn parse_payload(&self, cursor: &mut Reader) -> Option<Ipv6Next> {
        match self.0.next_header {
            IpNumber::TCP => cursor.parse_header::<Tcp, Ipv6Next>(),
            IpNumber::UDP => cursor.parse_header::<Udp, Ipv6Next>(),
            IpNumber::IPV6_ICMP => cursor.parse_header::<Icmp6, Ipv6Next>(),
            IpNumber::AUTHENTICATION_HEADER => cursor.parse_header::<IpAuth, Ipv6Next>(),
            IpNumber::IPV6_HEADER_HOP_BY_HOP
            | IpNumber::IPV6_ROUTE_HEADER
            | IpNumber::IPV6_FRAGMENTATION_HEADER
            | IpNumber::IPV6_DESTINATION_OPTIONS => {
                cursor.parse_header_with::<Ipv6Ext, Ipv6Next>(self.0.next_header)
            }
            _ => {
                trace!("unsupported protocol: {:?}", self.0.next_header);
                None
            }
        }
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

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        if buf.len() < Ipv6::MIN_LEN.get() as usize {
            return Err(ParseError::Length(LengthError {
                expected: Ipv6::MIN_LEN.into_non_zero_usize(),
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
        #[allow(clippy::cast_possible_truncation)]
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((Self::new(header).map_err(ParseError::Invalid)?, consumed))
    }
}

impl DeParse for Ipv6 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // header has bounded size
        NonZero::new(self.0.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() as usize {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        buf[..self.size().into_non_zero_usize().get()].copy_from_slice(&self.0.to_bytes());
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

impl From<Tcp> for Ipv6Next {
    fn from(value: Tcp) -> Self {
        Ipv6Next::Tcp(value)
    }
}

impl From<Udp> for Ipv6Next {
    fn from(value: Udp) -> Self {
        Ipv6Next::Udp(value)
    }
}

impl From<Icmp6> for Ipv6Next {
    fn from(value: Icmp6) -> Self {
        Ipv6Next::Icmp6(value)
    }
}

impl From<IpAuth> for Ipv6Next {
    fn from(value: IpAuth) -> Self {
        Ipv6Next::IpAuth(value)
    }
}

impl From<Ipv6Ext> for Ipv6Next {
    fn from(value: Ipv6Ext) -> Self {
        Ipv6Next::Ipv6Ext(value)
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
    ) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = Ipv6Extensions::from_slice(ip_number, buf)
            .map(|(h, _, rest)| (Box::new(h), rest))
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
        Ok((Self { inner }, consumed))
    }
}

impl Ipv6Ext {
    /// Parse the payload of this extension header.
    ///
    /// # Returns
    ///
    /// * `Some(Ipv6ExtNext)` variant if the payload was successfully parsed as a next header.
    /// * `None` if the next header is not supported.
    pub(crate) fn parse_payload(
        &self,
        first_ip_number: NextHeader,
        cursor: &mut Reader,
    ) -> Option<Ipv6ExtNext> {
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
            TCP => cursor.parse_header::<Tcp, Ipv6ExtNext>(),
            UDP => cursor.parse_header::<Udp, Ipv6ExtNext>(),
            IPV6_ICMP => cursor.parse_header::<Icmp6, Ipv6ExtNext>(),
            AUTHENTICATION_HEADER => {
                debug!("nested ip auth header");
                cursor.parse_header::<IpAuth, Ipv6ExtNext>()
            }
            IPV6_HEADER_HOP_BY_HOP
            | IPV6_ROUTE_HEADER
            | IPV6_FRAGMENTATION_HEADER
            | IPV6_DESTINATION_OPTIONS => {
                cursor.parse_header_with::<Ipv6Ext, Ipv6ExtNext>(next_header)
            }
            _ => {
                trace!("unsupported protocol: {next_header:?}");
                None
            }
        }
    }
}

pub(crate) enum Ipv6ExtNext {
    Tcp(Tcp),
    Udp(Udp),
    Icmp6(Icmp6),
    IpAuth(IpAuth),
    Ipv6Ext(Ipv6Ext),
}

impl From<Tcp> for Ipv6ExtNext {
    fn from(value: Tcp) -> Self {
        Ipv6ExtNext::Tcp(value)
    }
}

impl From<Udp> for Ipv6ExtNext {
    fn from(value: Udp) -> Self {
        Ipv6ExtNext::Udp(value)
    }
}

impl From<Icmp6> for Ipv6ExtNext {
    fn from(value: Icmp6) -> Self {
        Ipv6ExtNext::Icmp6(value)
    }
}

impl From<IpAuth> for Ipv6ExtNext {
    fn from(value: IpAuth) -> Self {
        Ipv6ExtNext::IpAuth(value)
    }
}

impl From<Ipv6Ext> for Ipv6ExtNext {
    fn from(value: Ipv6Ext) -> Self {
        Ipv6ExtNext::Ipv6Ext(value)
    }
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

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ip::NextHeader;
    use crate::ipv6::Ipv6;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use etherparse::Ipv6Header;
    use std::net::Ipv6Addr;

    /// A [`bolero::TypeGenerator`] for common (and supported) [`NextHeader`] values
    #[derive(Copy, Clone, Debug, bolero::TypeGenerator)]
    pub enum CommonNextHeader {
        /// TCP next header (see [`NextHeader::TCP`]
        Tcp,
        /// UDP next header (see [`NextHeader::UDP`]
        Udp,
        /// ICMP v6 next header (see [`NextHeader::ICMP6`]
        Icmp6,
    }

    impl From<CommonNextHeader> for NextHeader {
        fn from(value: CommonNextHeader) -> Self {
            match value {
                CommonNextHeader::Tcp => NextHeader::TCP,
                CommonNextHeader::Udp => NextHeader::UDP,
                CommonNextHeader::Icmp6 => NextHeader::ICMP6,
            }
        }
    }

    /// [`ValueGenerator`] for an (otherwise) arbitrary [`Ipv6`] with a specified [`NextHeader`].
    pub struct GenWithNextHeader(pub NextHeader);

    impl ValueGenerator for GenWithNextHeader {
        type Output = Ipv6;

        fn generate<D: Driver>(&self, u: &mut D) -> Option<Ipv6> {
            let mut header = Ipv6(Ipv6Header::default());
            header
                .set_source(u.produce()?)
                .set_destination(Ipv6Addr::from(u.produce::<u128>()?))
                .set_next_header(self.0)
                .set_payload_length(u.produce()?)
                .set_hop_limit(u.produce()?)
                .set_flow_label(u.produce()?)
                .set_traffic_class(u.produce()?)
                .set_hop_limit(u.produce()?);
            Some(header)
        }
    }

    impl TypeGenerator for Ipv6 {
        /// Generate a completely arbitrary [`Ipv6`] header.
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            GenWithNextHeader(u.produce()?).generate(u)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ipv6::{Ipv6, Ipv6Error};
    use crate::parse::{DeParse, IntoNonZeroUSize, Parse, ParseError};
    use etherparse::err::ipv6::{HeaderError, HeaderSliceError};

    const MIN_LEN: usize = Ipv6::MIN_LEN.get() as usize;

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!().with_type().for_each(|header: &Ipv6| {
            let mut buf = [0u8; MIN_LEN];
            let len = header.deparse(&mut buf).unwrap();
            let (header2, consumed) =
                crate::ipv6::Ipv6::parse(&buf[..len.into_non_zero_usize().get()]).unwrap();
            assert_eq!(consumed, len);
            assert_eq!(header, &header2);
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; MIN_LEN]| {
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
                assert_eq!(bytes_read.into_non_zero_usize().get(), slice.len());
                let mut slice2 = [0u8; MIN_LEN];
                header
                    .deparse(&mut slice2)
                    .unwrap_or_else(|e| unreachable!("{e:?}"));
                let (parse_back, bytes_read2) =
                    Ipv6::parse(&slice2).unwrap_or_else(|e| unreachable!("{e:?}"));
                assert_eq!(bytes_read2.into_non_zero_usize().get(), slice2.len());
                assert_eq!(header, parse_back);
                assert_eq!(slice, &slice2);
            });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_arbitrary_bytes_too_short() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; MIN_LEN - 1]| match Ipv6::parse(slice) {
                Err(ParseError::Length(e)) => {
                    assert_eq!(e.expected, Ipv6::MIN_LEN.into_non_zero_usize());
                    assert_eq!(e.actual, Ipv6::MIN_LEN.into_non_zero_usize().get() - 1);
                }
                _ => unreachable!(),
            });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_arbitrary_bytes_above_minimum() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; 4 * MIN_LEN]| {
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
                let mut slice2 = [0u8; MIN_LEN];
                header
                    .deparse(&mut slice2)
                    .unwrap_or_else(|e| unreachable!("{e:?}"));
                let (parse_back, bytes_read2) =
                    Ipv6::parse(&slice2).unwrap_or_else(|e| unreachable!("{e:?}"));
                assert_eq!(bytes_read2.into_non_zero_usize().get(), slice2.len());
                assert_eq!(header, parse_back);
                assert_eq!(&slice[..MIN_LEN], &slice2);
            });
    }
}
