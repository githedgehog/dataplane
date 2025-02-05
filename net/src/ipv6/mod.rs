// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ipv6 Address type and manipulation

use crate::icmp6::Icmp6;
use crate::ip_auth::IpAuth;
use crate::ipv6::addr::UnicastIpv6Addr;
use crate::packet::Header;
use crate::parse::{
    DeParse, DeParseError, LengthError, Parse, ParseError, ParsePayload, ParsePayloadWith,
    ParseWith, Reader,
};
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::{IpNumber, Ipv6Extensions, Ipv6FlowLabel, Ipv6Header};
use std::net::Ipv6Addr;
use std::num::NonZero;
use tracing::{debug, trace};

pub mod addr;

/// An IPv6 header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    inner: Ipv6Header,
}

impl Ipv6 {
    /// The minimum length (in bytes) of an [`Ipv6`] header.
    // Safety: const-evaluated and trivially safe.
    #[allow(unsafe_code)]
    pub const MIN_LEN: NonZero<usize> = unsafe { NonZero::new_unchecked(40) };

    /// Get the source [`Ipv6Addr`] for this header
    #[must_use]
    pub fn source(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.inner.source)
    }

    /// Get the destination [`Ipv6Addr`] for this header
    #[must_use]
    pub fn destination(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.inner.destination)
    }

    /// Get the [`IpNumber`] type of the next header.
    #[must_use]
    pub fn next_header(&self) -> IpNumber {
        self.inner.next_header
    }

    /// Get the hop limit for this header (analogous to [`crate::ipv4::Ipv4::ttl`])
    #[must_use]
    pub fn hop_limit(&self) -> u8 {
        self.inner.hop_limit
    }

    // TODO: proper wrapper type (low priority)
    /// Get the [traffic class] for this header
    ///
    /// [traffic class]: https://datatracker.ietf.org/doc/html/rfc8200#section-7
    #[must_use]
    pub fn traffic_class(&self) -> u8 {
        self.inner.traffic_class
    }

    // TODO: proper wrapper type (low priority)
    /// Get this header's [flow label].
    ///
    /// [flow label]: https://datatracker.ietf.org/doc/html/rfc6437
    #[must_use]
    pub fn flow_label(&self) -> Ipv6FlowLabel {
        self.inner.flow_label
    }

    /// Set the source ip address of this header
    pub fn set_source(&mut self, source: UnicastIpv6Addr) -> &mut Self {
        self.inner.source = source.inner().octets();
        self
    }

    /// Set the source ip address of this header (confirming that this is a legal source ip).
    ///
    /// # Errors
    ///
    /// Will return a [`MulticastSourceForbidden`] error if you supply a multicast ip as the source.
    pub fn set_source_checked(&mut self, source: Ipv6Addr) -> Result<(), MulticastSourceForbidden> {
        if source.is_multicast() {
            return Err(MulticastSourceForbidden);
        }
        self.inner.source = source.octets();
        Ok(())
    }

    /// Set the source ip address of this header
    ///
    /// # Safety
    ///
    /// Does not confirm that the header's ip is unicast
    #[allow(unsafe_code)]
    pub unsafe fn set_source_unchecked(&mut self, source: Ipv6Addr) -> &mut Self {
        self.inner.source = source.octets();
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
        self.inner.destination = destination.octets();
        self
    }

    /// Set the hop limit for this header (analogous to [`crate::ipv4::Ipv4::set_ttl`])
    pub fn set_hop_limit(&mut self, hop_limit: u8) -> &mut Self {
        self.inner.hop_limit = hop_limit;
        self
    }

    /// Set the hop limit for this header (analogous to [`crate::ipv4::Ipv4::set_ttl`])
    ///
    /// # Errors
    ///
    /// Will return a [`HopLimitAlreadyZero`] error if the hop limit is already zero :)
    pub fn decrement_hop_limit(&mut self) -> Result<(), HopLimitAlreadyZeroError> {
        if self.inner.hop_limit == 0 {
            return Err(HopLimitAlreadyZeroError);
        }
        self.inner.hop_limit -= 1;
        Ok(())
    }

    // TODO: wrapper type (low priority)
    /// Set the [traffic class] for this header
    ///
    /// [traffic class]: https://datatracker.ietf.org/doc/html/rfc8200#section-7
    pub fn set_traffic_class(&mut self, traffic_class: u8) -> &mut Self {
        self.inner.traffic_class = traffic_class;
        self
    }

    /// Set this header's [flow label].
    ///
    /// [flow label]: https://datatracker.ietf.org/doc/html/rfc6437
    pub fn set_flow_label(&mut self, flow_label: Ipv6FlowLabel) -> &mut Self {
        self.inner.flow_label = flow_label;
        self
    }

    /// Set the next header [`IpNumber`]
    ///
    /// # Safety
    ///
    /// This method makes no attempt to ensure that the supplied [`next_header`] value is valid for
    /// the packet to which this header belongs (if any).
    pub fn set_next_header(&mut self, next_header: IpNumber) -> &mut Self {
        self.inner.next_header = next_header;
        self
    }
}

/// An error which occurs if you attempt to set the source ip address of an [`Ipv6`] header to a
/// multicast address.
#[repr(transparent)]
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("multicast source forbidden")]
pub struct MulticastSourceForbidden;

/// An error which occurs if you attempt to decrement the hop limit of an [`Ipv6`] header when the
/// hop limit is already zero.
#[repr(transparent)]
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("hop limit already zero")]
pub struct HopLimitAlreadyZeroError;

impl Parse for Ipv6 {
    type Error = etherparse::err::ipv6::HeaderSliceError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        if buf.len() < Ipv6::MIN_LEN.get() {
            return Err(ParseError::Length(LengthError {
                expected: Ipv6::MIN_LEN,
                actual: buf.len(),
            }));
        }
        let (inner, rest) = Ipv6Header::from_slice(buf).map_err(ParseError::Invalid)?;
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

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        buf[..self.size().get()].copy_from_slice(&self.inner.to_bytes());
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
    type Param = IpNumber;
    type Next = Ipv6ExtNext;

    fn parse_payload_with(
        &self,
        first_ip_number: &IpNumber,
        cursor: &mut Reader,
    ) -> Option<Self::Next> {
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

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ip::NextHeader;
    use crate::ipv6::Ipv6;
    use arbitrary::{Arbitrary, Unstructured};
    use etherparse::{Ipv6FlowLabel, Ipv6Header};

    impl<'a> Arbitrary<'a> for Ipv6 {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            let mut header = Ipv6 {
                inner: Ipv6Header::default(),
            };
            header.set_source(u.arbitrary()?);
            header.set_destination(u.arbitrary()?);
            header.set_next_header(NextHeader::arbitrary(u)?.into());
            // [`Ipv6FlowLabel`] is a 20-bit field so `&` the excess bits to zero
            let flow_label = Ipv6FlowLabel::try_new(u.arbitrary::<u32>()? & 0xfffff)
                .unwrap_or_else(|e| unreachable!("{e}"));
            header.set_flow_label(flow_label);
            header.set_traffic_class(u.arbitrary()?);
            header.set_hop_limit(u.arbitrary()?);
            Ok(header)
        }

        fn size_hint(_depth: usize) -> (usize, Option<usize>) {
            (Ipv6::MIN_LEN.get(), Some(Ipv6::MIN_LEN.get()))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod test {
    use crate::ipv6::Ipv6;
    use crate::parse::{DeParse, Parse, ParseError};
    use etherparse::err::ipv6::{HeaderError, HeaderSliceError};

    #[test]
    fn parse_back() {
        bolero::check!().with_arbitrary().for_each(|header: &Ipv6| {
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
            .with_arbitrary()
            .for_each(|slice: &[u8; Ipv6::MIN_LEN.get()]| {
                let (header, bytes_read) = match Ipv6::parse(slice) {
                    Ok((header, bytes_read)) => (header, bytes_read),
                    Err(ParseError::Invalid(HeaderSliceError::Content(
                        HeaderError::UnexpectedVersion { version_number },
                    ))) => {
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
            .with_arbitrary()
            .for_each(|slice: &[u8; Ipv6::MIN_LEN.get() - 1]| {
                match Ipv6::parse(slice) {
                    Err(ParseError::Length(e)) => {
                        assert_eq!(e.expected, Ipv6::MIN_LEN);
                        assert_eq!(e.actual, Ipv6::MIN_LEN.get() - 1);
                    }
                    _ => unreachable!(),
                };
            });
    }

    #[test]
    fn parse_arbitrary_bytes_above_minimum() {
        bolero::check!()
            .with_arbitrary()
            .for_each(|slice: &[u8; 4 * Ipv6::MIN_LEN.get()]| {
                let (header, bytes_read) = match Ipv6::parse(slice) {
                    Ok((header, bytes_read)) => (header, bytes_read),
                    Err(ParseError::Invalid(HeaderSliceError::Content(
                        HeaderError::UnexpectedVersion { version_number },
                    ))) => {
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
