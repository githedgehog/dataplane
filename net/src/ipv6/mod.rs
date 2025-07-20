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
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload,
    ParseWith, Reader,
};
use crate::tcp::Tcp;
use crate::udp::Udp;
use arrayvec::ArrayVec;
use etherparse::err::ip_auth;
use etherparse::err::ip_auth::HeaderError;
use etherparse::{IpAuthHeader, IpNumber, Ipv6Header, Ipv6RawExtHeader};
use std::net::Ipv6Addr;
use std::num::{NonZero, NonZeroUsize};
use tracing::{debug, trace};

pub mod addr;
pub mod flow_label;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// An array of extension headers for the IPv6 protocol
pub type Ipv6Extensions = ArrayVec<Ipv6Ext, { Ipv6::MAX_EXTENSIONS }>;

/// An IPv6 header
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv6 {
    pub(crate) header: Ipv6Header,
    pub(crate) ext: Ipv6Extensions,
}

impl Ipv6 {
    /// The maximum number of IPv6 extension headers which may be attached before the packet will be
    /// dropped as invalid.
    pub const MAX_EXTENSIONS: usize = 2;

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
        Ok(Self {
            header,
            ext: ArrayVec::new(),
        })
    }

    /// Get the source [`Ipv6Addr`] for this header
    #[must_use]
    pub fn source(&self) -> UnicastIpv6Addr {
        UnicastIpv6Addr::new(Ipv6Addr::from(self.header.source)).unwrap_or_else(|_| unreachable!())
    }

    /// Get the destination [`Ipv6Addr`] for this header
    #[must_use]
    pub fn destination(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.header.destination)
    }

    /// Get the [`IpNumber`] type of the next header.
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        NextHeader::new(self.header.next_header.0)
    }

    /// Get the hop limit for this header (analogous to [`crate::ipv4::Ipv4::ttl`])
    #[must_use]
    pub fn hop_limit(&self) -> u8 {
        self.header.hop_limit
    }

    // TODO: proper wrapper type (low priority)
    /// Get the [traffic class] for this header
    ///
    /// [traffic class]: https://datatracker.ietf.org/doc/html/rfc8200#section-7
    #[must_use]
    pub fn traffic_class(&self) -> u8 {
        self.header.traffic_class
    }

    // TODO: proper wrapper type (low priority)
    /// Get this header's [flow label].
    ///
    /// [flow label]: https://datatracker.ietf.org/doc/html/rfc6437
    #[must_use]
    pub fn flow_label(&self) -> FlowLabel {
        FlowLabel::new(self.header.flow_label.value()).unwrap_or_else(|_| unreachable!())
    }

    /// Set the source ip address of this header
    pub fn set_source(&mut self, source: UnicastIpv6Addr) -> &mut Self {
        self.header.source = source.inner().octets();
        self
    }

    /// Set the payload length.
    ///
    /// # Safety
    ///
    /// This method does not (and cannot) check that the length is correct in the context of the
    /// packet as a whole.
    pub fn set_payload_length(&mut self, length: u16) -> &mut Self {
        self.header
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
        self.header.destination = destination.octets();
        self
    }

    /// Set the hop limit for this header (analogous to [`crate::ipv4::Ipv4::set_ttl`])
    pub fn set_hop_limit(&mut self, hop_limit: u8) -> &mut Self {
        self.header.hop_limit = hop_limit;
        self
    }

    /// Set the hop limit for this header (analogous to [`crate::ipv4::Ipv4::set_ttl`])
    ///
    /// # Errors
    ///
    /// Will return a [`HopLimitAlreadyZeroError`] error if the hop limit is already zero :)
    pub fn decrement_hop_limit(&mut self) -> Result<(), HopLimitAlreadyZeroError> {
        if self.header.hop_limit == 0 {
            return Err(HopLimitAlreadyZeroError);
        }
        self.header.hop_limit -= 1;
        Ok(())
    }

    // TODO: wrapper type (low priority)
    /// Set the [traffic class] for this header
    ///
    /// [traffic class]: https://datatracker.ietf.org/doc/html/rfc8200#section-7
    pub fn set_traffic_class(&mut self, traffic_class: u8) -> &mut Self {
        self.header.traffic_class = traffic_class;
        self
    }

    /// Set this header's [flow label].
    ///
    /// [flow label]: https://datatracker.ietf.org/doc/html/rfc6437
    pub fn set_flow_label(&mut self, flow_label: FlowLabel) -> &mut Self {
        self.header.flow_label = flow_label.0;
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
        self.header.next_header = next_header.0;
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
        #[allow(clippy::cast_possible_truncation)] // wrap and underflow impossible
        let consumed = (buf.len() - rest.len()) as u16;
        if header.next_header.is_ipv6_ext_header_value() {
            match Ipv6Extensions::parse_with(NextHeader(header.next_header), rest) {
                Ok((ext, jump)) => {
                    let consumed =
                        NonZero::new(consumed + jump.get()).unwrap_or_else(|| unreachable!());
                    Ok((Self { header, ext }, consumed))
                }
                Err(err) => {
                    debug!("{err}");
                    let consumed = NonZero::new(consumed).unwrap_or_else(|| unreachable!());
                    Ok((
                        Self {
                            header,
                            ext: Ipv6Extensions::new(),
                        },
                        consumed,
                    ))
                }
            }
        } else {
            let consumed = NonZero::new(consumed).unwrap_or_else(|| unreachable!());
            Ok((
                Self {
                    header,
                    ext: Ipv6Extensions::new(),
                },
                consumed,
            ))
        }
    }
}

impl DeParse for Ipv6 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        let ext_len: u16 = self.ext.iter().map(|x| x.header_len().get()).sum();
        #[allow(clippy::cast_possible_truncation)] // header has bounded size
        NonZero::new(ext_len + self.header.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() as usize {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        buf[..Ipv6Header::LEN].copy_from_slice(&self.header.to_bytes());
        if !self.ext.is_empty() {
            let mut offset = Ipv6Header::LEN;
            for ext in &self.ext {
                // panic should be impossible here as we have already checked that the size of the
                // buffer is large enough above
                let ext_len = ext.header_len().get() as usize;
                buf[offset..(offset + ext_len)].copy_from_slice(ext.to_bytes().as_slice());
                offset += ext_len;
            }
        }
        Ok(self.size())
    }
}

pub(crate) enum Ipv6Next {
    Tcp(Tcp),
    Udp(Udp),
    Icmp6(Icmp6),
}

impl ParsePayload for Ipv6 {
    type Next = Ipv6Next;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<Self::Next> {
        match self.header.next_header {
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
            IpNumber::IPV6_ICMP => cursor
                .parse::<Icmp6>()
                .map_err(|e| {
                    debug!("failed to parse icmp6: {e:?}");
                })
                .map(|(val, _)| Ipv6Next::Icmp6(val))
                .ok(),
            _ => {
                trace!("unsupported protocol: {:?}", self.header.next_header);
                None
            }
        }
    }
}

/// An IPv6 extension header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ipv6Ext {
    /// An IP auth header, as is used in ipsec
    Auth(IpAuth),
    /// A not (yet) supported IPv6 extension header
    Other(OtherIpv6Ext),
}

impl Ipv6Ext {
    /// Get the length of the header in bytes
    #[must_use]
    pub fn header_len(&self) -> NonZero<u16> {
        let len_usize = match self {
            Ipv6Ext::Auth(x) => x.0.header_len(),
            Ipv6Ext::Other(x) => x.0.header_len(),
        };
        NonZero::new(match u16::try_from(len_usize) {
            Ok(len) => len,
            Err(err) => {
                unreachable!(
                    "header_len() returned an invalid length (above 2^16 bytes): {}",
                    err
                );
            }
        })
        .unwrap_or_else(|| unreachable!())
    }

    /// TODO: this is very hacky and likely quite slow
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let expected_len = self.header_len().get() as usize;
        let mut rvec = Vec::with_capacity(expected_len);
        match self {
            Ipv6Ext::Auth(x) => rvec.extend(x.0.to_bytes()),
            Ipv6Ext::Other(x) => rvec.extend(x.0.to_bytes()),
        }
        rvec
    }
}

/// An IPv6 extension header of a not (yet) supported type
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct OtherIpv6Ext(Box<Ipv6RawExtHeader>);

impl OtherIpv6Ext {
    /// Create a new [`OtherIpv6Ext`] from a [`Ipv6RawExtHeader`]
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        NextHeader(self.0.next_header)
    }
}

impl Ipv6Ext {
    /// Get the next header of the ipv6 extension
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        match self {
            Ipv6Ext::Auth(x) => NextHeader(x.0.next_header),
            Ipv6Ext::Other(x) => NextHeader(x.0.next_header),
        }
    }
}

/// Errors which may occur when parsing a collection of IPv6 extension headers
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum Ipv6ExtError {
    /// The IPv6 extension header failed to parse
    #[error("invalid ipv6 extension header found")]
    Invalid,
}

/// Outcomes which may occur when parsing a series of ipv6 extension headers
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[error("invalid ipv6 extension header")]
pub enum Ipv6ScalarExtError {
    /// The IPv6 extension header is invalid
    #[error("invalid ipv6 extension header found")]
    Invalid,
    /// There are no further IPv6 extension headers to parse
    #[error("there are no further IPv6 extension headers to parse")]
    NoFurtherExtensions,
}

impl ParseWith for Ipv6Ext {
    type Error = Ipv6ScalarExtError;
    type Param = NextHeader;

    fn parse_with(
        ip_number: NextHeader,
        buf: &[u8],
    ) -> Result<(Self, NonZero<u16>), ParseError<Ipv6ScalarExtError>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (output, rest) = match ip_number {
            NextHeader::IP_AUTH => IpAuthHeader::from_slice(buf)
                .map_err(|e| match e {
                    ip_auth::HeaderSliceError::Len(l) => ParseError::Length(LengthError {
                        expected: NonZeroUsize::new(l.required_len)
                            .unwrap_or_else(|| unreachable!()),
                        actual: buf.len(),
                    }),
                    ip_auth::HeaderSliceError::Content(e) => match e {
                        HeaderError::ZeroPayloadLen => ParseError::Length(LengthError {
                            expected: NonZero::new(16).unwrap_or_else(|| unreachable!()),
                            actual: 0,
                        }),
                    },
                })
                .map(|(h, rest)| (Self::Auth(IpAuth(Box::new(h))), rest))?,
            nhdr if nhdr.0.is_ipv6_ext_header_value() => Ipv6RawExtHeader::from_slice(buf)
                .map_err(|e| {
                    ParseError::Length(LengthError {
                        expected: NonZeroUsize::new(e.required_len)
                            .unwrap_or_else(|| unreachable!()),
                        actual: buf.len(),
                    })
                })
                .map(|(h, rest)| (Self::Other(OtherIpv6Ext(Box::new(h))), rest))?,
            NextHeader(_) => Err(ParseError::Invalid(Ipv6ScalarExtError::NoFurtherExtensions))?,
        };
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((output, consumed))
    }
}

impl ParseWith for ArrayVec<Ipv6Ext, { Ipv6::MAX_EXTENSIONS }> {
    type Error = Ipv6ExtError;
    type Param = NextHeader;

    fn parse_with(
        ip_number: NextHeader,
        buf: &[u8],
    ) -> Result<(Self, NonZero<u16>), ParseError<Ipv6ExtError>> {
        let mut output = Ipv6Extensions::new();
        let mut consumed: u16 = 0;
        let mut ip_number = ip_number;
        loop {
            match Ipv6Ext::parse_with(ip_number, &buf[(consumed as usize)..]) {
                Ok((ext, jump)) => {
                    if output.len() >= Ipv6::MAX_EXTENSIONS {
                        Err(ParseError::Invalid(Ipv6ExtError::Invalid))?;
                    }
                    ip_number = ext.next_header();
                    output.push(ext);
                    consumed += jump.get();
                }
                Err(err) => match err {
                    ParseError::Invalid(Ipv6ScalarExtError::NoFurtherExtensions) => {
                        break;
                    }
                    ParseError::Invalid(Ipv6ScalarExtError::Invalid) => {
                        Err(ParseError::Invalid(Ipv6ExtError::Invalid))?;
                    }
                    ParseError::BufferTooLong(e) => Err(ParseError::BufferTooLong(e))?,
                    ParseError::Length(e) => Err(ParseError::Length(e))?,
                },
            }
        }
        let consumed = match NonZero::new(consumed) {
            None => Err(ParseError::Length(LengthError {
                expected: NonZeroUsize::new(2).unwrap_or_else(|| unreachable!()),
                actual: buf.len(),
            }))?,
            Some(consumed) => consumed,
        };
        Ok((output, consumed))
    }
}

impl From<Ipv6Next> for Header {
    fn from(value: Ipv6Next) -> Self {
        match value {
            Ipv6Next::Tcp(x) => Header::Tcp(x),
            Ipv6Next::Udp(x) => Header::Udp(x),
            Ipv6Next::Icmp6(x) => Header::Icmp6(x),
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
            let mut header =
                Ipv6::new(Ipv6Header::default()).unwrap_or_else(|e| unreachable!("{}", e));
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
    use etherparse::Ipv6Header;
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
        const TEST_SLICE_LEN: usize = 4096;
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; TEST_SLICE_LEN]| {
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
                assert!(bytes_read.into_non_zero_usize().get() <= TEST_SLICE_LEN);
                let mut slice2 = [0u8; TEST_SLICE_LEN];
                header
                    .deparse(&mut slice2)
                    .unwrap_or_else(|e| unreachable!("{e:?}"));
                let (parse_back, bytes_read2) =
                    Ipv6::parse(&slice2).unwrap_or_else(|e| unreachable!("{e:?}"));
                assert_eq!(
                    bytes_read, bytes_read2,
                    "header: {header:#?}, parse_back: {parse_back:#?}"
                );
                assert_eq!(header, parse_back);
                assert_eq!(
                    &slice[..Ipv6Header::LEN],
                    &slice2[..Ipv6Header::LEN],
                    "header: {header:#?}"
                );
            });
    }
}
