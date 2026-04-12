// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ipv6 Address type and manipulation

use crate::headers::{EmbeddedHeader, Header};
use crate::icmp6::{Icmp6, TruncatedIcmp6};
use crate::impl_from_for_enum;
use crate::ip::NextHeader;
use crate::ip::dscp::Dscp;
use crate::ip::ecn::Ecn;
pub use crate::ipv6::addr::UnicastIpv6Addr;
use crate::ipv6::flow_label::FlowLabel;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParseHeader, Reader,
};
use crate::tcp::{Tcp, TruncatedTcp};
use crate::udp::{TruncatedUdp, Udp};
use etherparse::{IpNumber, Ipv6Header};
use std::net::Ipv6Addr;
use std::num::NonZero;
use tracing::trace;

pub mod addr;
pub mod dest_opts;
pub(crate) mod ext_parse;
pub mod flow_label;
pub mod fragment;
pub mod hop_by_hop;
#[cfg(any(test, feature = "bolero"))]
pub(crate) mod raw_ext_gen;
pub mod routing;

pub use dest_opts::DestOpts;
pub use fragment::Fragment;
pub use hop_by_hop::HopByHop;
pub use routing::Routing;

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
    pub(crate) fn new(header: Ipv6Header) -> Result<Self, Ipv6Error> {
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

    /// Get the next header protocol number.
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        NextHeader::from_ip_number(self.0.next_header)
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

    /// Get the header's [differentiated services code point].
    ///
    /// [differentiated services code point]: https://en.wikipedia.org/wiki/Differentiated_services
    #[must_use]
    pub fn dscp(&self) -> Dscp {
        Dscp(self.0.dscp())
    }

    /// Get the header's [explicit congestion notification]
    ///
    /// [explicit congestion notification]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
    #[must_use]
    pub fn ecn(&self) -> Ecn {
        Ecn(self.0.ecn())
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

    /// Set the header's [explicit congestion notification]
    ///
    /// [explicit congestion notification]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
    pub fn set_ecn(&mut self, ecn: Ecn) -> &mut Self {
        self.0.set_ecn(ecn.0);
        self
    }

    /// Set the header's [differentiated services code point].
    ///
    /// [differentiated services code point]: https://en.wikipedia.org/wiki/Differentiated_services
    pub fn set_dscp(&mut self, dscp: Dscp) -> &mut Self {
        self.0.set_dscp(dscp.0);
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
        self.0.next_header = next_header.to_ip_number();
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
            IpNumber::AUTHENTICATION_HEADER => {
                cursor.parse_header::<crate::ip_auth::Ipv6Auth, Ipv6Next>()
            }
            IpNumber::IPV6_HEADER_HOP_BY_HOP => cursor.parse_header::<HopByHop, Ipv6Next>(),
            IpNumber::IPV6_ROUTE_HEADER => cursor.parse_header::<Routing, Ipv6Next>(),
            IpNumber::IPV6_FRAGMENTATION_HEADER => cursor.parse_header::<Fragment, Ipv6Next>(),
            IpNumber::IPV6_DESTINATION_OPTIONS => cursor.parse_header::<DestOpts, Ipv6Next>(),
            _ => {
                trace!("unsupported protocol: {:?}", self.0.next_header);
                None
            }
        }
    }

    /// Parse the payload of an IPv6 packet embedded in an ICMP Error message.
    ///
    /// # Returns
    ///
    /// * `Some(EmbeddedIpv6Next)` variant if the payload was successfully parsed as a next header.
    /// * `None` if the next header is not supported.
    pub(crate) fn parse_embedded_payload(&self, cursor: &mut Reader) -> Option<EmbeddedIpv6Next> {
        match self.0.next_header {
            IpNumber::TCP => cursor.parse_header::<TruncatedTcp, EmbeddedIpv6Next>(),
            IpNumber::UDP => cursor.parse_header::<TruncatedUdp, EmbeddedIpv6Next>(),
            IpNumber::IPV6_ICMP => cursor.parse_header::<TruncatedIcmp6, EmbeddedIpv6Next>(),
            IpNumber::AUTHENTICATION_HEADER => {
                cursor.parse_header::<crate::ip_auth::Ipv6Auth, EmbeddedIpv6Next>()
            }
            IpNumber::IPV6_HEADER_HOP_BY_HOP => cursor.parse_header::<HopByHop, EmbeddedIpv6Next>(),
            IpNumber::IPV6_ROUTE_HEADER => cursor.parse_header::<Routing, EmbeddedIpv6Next>(),
            IpNumber::IPV6_FRAGMENTATION_HEADER => {
                cursor.parse_header::<Fragment, EmbeddedIpv6Next>()
            }
            IpNumber::IPV6_DESTINATION_OPTIONS => {
                cursor.parse_header::<DestOpts, EmbeddedIpv6Next>()
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

/// Errors which can occur when parsing an [`Ipv6`] header.
#[derive(thiserror::Error, Debug)]
pub enum Ipv6Error {
    /// Source address is invalid because it is a multicast address.
    #[error("multicast source forbidden (received {0})")]
    InvalidSourceAddr(Ipv6Addr),
    /// The version field is not 6.
    #[error("unexpected IP version: {version_number} (expected 6)")]
    UnexpectedVersion {
        /// The version number found in the header.
        version_number: u8,
    },
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
        let (header, rest) = Ipv6Header::from_slice(buf).map_err(|e| {
            use etherparse::err::ipv6::{HeaderError, HeaderSliceError};
            match e {
                HeaderSliceError::Len(len) => ParseError::Length(LengthError {
                    expected: NonZero::new(len.required_len).unwrap_or_else(|| unreachable!()),
                    actual: buf.len(),
                }),
                HeaderSliceError::Content(HeaderError::UnexpectedVersion { version_number }) => {
                    ParseError::Invalid(Ipv6Error::UnexpectedVersion { version_number })
                }
            }
        })?;
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
    Ipv6Auth(crate::ip_auth::Ipv6Auth),
    HopByHop(HopByHop),
    DestOpts(DestOpts),
    Routing(Routing),
    Fragment(Fragment),
}

impl_from_for_enum![
    Ipv6Next,
    Tcp(Tcp),
    Udp(Udp),
    Icmp6(Icmp6),
    Ipv6Auth(crate::ip_auth::Ipv6Auth),
    HopByHop(HopByHop),
    DestOpts(DestOpts),
    Routing(Routing),
    Fragment(Fragment)
];

pub(crate) enum EmbeddedIpv6Next {
    Tcp(TruncatedTcp),
    Udp(TruncatedUdp),
    Icmp6(TruncatedIcmp6),
    Ipv6Auth(crate::ip_auth::Ipv6Auth),
    HopByHop(HopByHop),
    DestOpts(DestOpts),
    Routing(Routing),
    Fragment(Fragment),
}

impl_from_for_enum![
    EmbeddedIpv6Next,
    Tcp(TruncatedTcp),
    Udp(TruncatedUdp),
    Icmp6(TruncatedIcmp6),
    Ipv6Auth(crate::ip_auth::Ipv6Auth),
    HopByHop(HopByHop),
    DestOpts(DestOpts),
    Routing(Routing),
    Fragment(Fragment)
];

impl From<Ipv6Next> for Header {
    fn from(value: Ipv6Next) -> Self {
        match value {
            Ipv6Next::Tcp(x) => Header::Tcp(x),
            Ipv6Next::Udp(x) => Header::Udp(x),
            Ipv6Next::Icmp6(x) => Header::Icmp6(x),
            Ipv6Next::Ipv6Auth(x) => Header::Ipv6Auth(x),
            Ipv6Next::HopByHop(x) => Header::HopByHop(x),
            Ipv6Next::DestOpts(x) => Header::DestOpts(x),
            Ipv6Next::Routing(x) => Header::Routing(x),
            Ipv6Next::Fragment(x) => Header::Fragment(x),
        }
    }
}

impl From<EmbeddedIpv6Next> for EmbeddedHeader {
    fn from(value: EmbeddedIpv6Next) -> Self {
        match value {
            EmbeddedIpv6Next::Tcp(x) => EmbeddedHeader::Tcp(x),
            EmbeddedIpv6Next::Udp(x) => EmbeddedHeader::Udp(x),
            EmbeddedIpv6Next::Icmp6(x) => EmbeddedHeader::Icmp6(x),
            EmbeddedIpv6Next::Ipv6Auth(x) => EmbeddedHeader::Ipv6Auth(x),
            EmbeddedIpv6Next::HopByHop(x) => EmbeddedHeader::HopByHop(x),
            EmbeddedIpv6Next::DestOpts(x) => EmbeddedHeader::DestOpts(x),
            EmbeddedIpv6Next::Routing(x) => EmbeddedHeader::Routing(x),
            EmbeddedIpv6Next::Fragment(x) => EmbeddedHeader::Fragment(x),
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

            let src = u.produce()?;
            let dst = Ipv6Addr::from(u.produce::<u128>()?);
            let payload_len = u.produce()?;
            let hop_limit = u.produce()?;
            let flow_label = u.produce()?;
            let traffic_class = u.produce()?;

            header
                .set_source(src)
                .set_destination(dst)
                .set_next_header(self.0)
                .set_payload_length(payload_len)
                .set_hop_limit(hop_limit)
                .set_flow_label(flow_label)
                .set_traffic_class(traffic_class);

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

    const MIN_LEN: usize = Ipv6::MIN_LEN.get() as usize;

    #[test]
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
                    Err(ParseError::Invalid(Ipv6Error::UnexpectedVersion { version_number })) => {
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
                    Err(ParseError::Invalid(Ipv6Error::UnexpectedVersion { version_number })) => {
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
