// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ipv4 Address type and manipulation

use crate::headers::Header;
use crate::icmp4::Icmp4;
use crate::ip::NextHeader;
use crate::ip_auth::IpAuth;
pub use crate::ipv4::addr::UnicastIpv4Addr;
use crate::ipv4::dscp::Dscp;
use crate::ipv4::ecn::Ecn;
use crate::ipv4::frag_offset::FragOffset;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload, Reader,
};
use crate::tcp::Tcp;
use crate::udp::Udp;
use etherparse::{IpDscp, IpEcn, IpFragOffset, IpNumber, Ipv4Header};
use std::net::Ipv4Addr;
use std::num::NonZero;
use tracing::{debug, trace};

pub mod addr;
pub mod dscp;

pub mod ecn;

mod checksum;
pub mod frag_offset;

pub use checksum::*;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// An IPv4 header
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv4(pub(crate) Ipv4Header);

/// Error describing illegal length in an IPv4 header
#[derive(Debug, thiserror::Error)]
#[error(
    "Invalid IPv4 length requested: {requested}, max is {max} when considering all options and headers"
)]
pub struct Ipv4LengthError {
    requested: usize,
    max: usize,
}

impl Ipv4 {
    /// The minimum length of an IPv4 header (i.e., a header with no options)
    #[allow(clippy::unwrap_used)] // const-eval and trivially safe
    pub const MIN_LEN: NonZero<u16> = NonZero::new(20).unwrap();

    /// The maximum length of an IPv4 header (i.e., a header with full options)
    #[allow(clippy::unwrap_used)] // const-eval and trivially safe
    pub const MAX_LEN: NonZero<u16> = NonZero::new(60).unwrap();

    /// Create a new IPv4 header
    pub(crate) fn new(header: Ipv4Header) -> Result<Self, Ipv4Error> {
        UnicastIpv4Addr::new(Ipv4Addr::from(header.source))
            .map_err(Ipv4Error::InvalidSourceAddr)?;
        Ok(Self(header))
    }

    /// Get the source ip address of the header
    #[must_use]
    pub fn source(&self) -> UnicastIpv4Addr {
        UnicastIpv4Addr::new(Ipv4Addr::from(self.0.source)).unwrap_or_else(|_| unreachable!())
    }

    /// Get the destination ip address of the header
    #[must_use]
    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.0.destination)
    }

    // TODO: proper wrapper type
    /// Get the options for this header (as a byte slice)
    #[must_use]
    pub fn options(&self) -> &[u8] {
        self.0.options.as_slice()
    }

    // TODO: proper wrapper type for [`IpNumber`] (low priority)
    /// Get the next layer protocol which follows this header.
    #[must_use]
    pub fn protocol(&self) -> IpNumber {
        self.0.protocol
    }

    /// Length of the header (includes options) in bytes.
    ///
    /// <div class="warning">
    /// The returned value is in bytes (not in units of 32 bits as per the IHL field).
    /// </div>
    #[must_use]
    pub fn header_len(&self) -> usize {
        self.0.header_len()
    }

    /// Value of total length ip header field
    #[must_use]
    pub fn total_len(&self) -> u16 {
        self.0.total_len
    }

    /// The number of routing hops the packet is allowed to take.
    #[must_use]
    pub fn ttl(&self) -> u8 {
        self.0.time_to_live
    }

    // TODO: proper wrapper type (low priority)
    /// Get the header's [differentiated services code point].
    ///
    /// [differentiated services code point]: https://en.wikipedia.org/wiki/Differentiated_services
    #[must_use]
    pub fn dscp(&self) -> IpDscp {
        self.0.dscp
    }

    // TODO: proper wrapper type (low priority)
    /// Get the header's [explicit congestion notification]
    ///
    /// [explicit congestion notification]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
    #[must_use]
    pub fn ecn(&self) -> IpEcn {
        self.0.ecn
    }

    /// Returns true if the "don't fragment" bit is set in this header.
    #[must_use]
    pub fn dont_fragment(&self) -> bool {
        self.0.dont_fragment
    }

    /// Returns true if the "more-fragments" bit is set in this header.
    #[must_use]
    pub fn more_fragments(&self) -> bool {
        self.0.more_fragments
    }

    // TODO: proper wrapper type (low priority)
    /// In case this message contains parts of a fragmented packet, the fragment offset is the
    /// offset of payload the current message relative to the original payload of the message.
    #[must_use]
    pub fn fragment_offset(&self) -> IpFragOffset {
        self.0.fragment_offset
    }

    /// Return the headers "identification".
    /// See [IP fragmentation]
    ///
    /// [IP Fragmentation]: https://en.wikipedia.org/wiki/IP_fragmentation
    #[must_use]
    pub fn identification(&self) -> u16 {
        self.0.identification
    }

    /// Set the source ip of the header.
    pub fn set_source(&mut self, source: UnicastIpv4Addr) -> &mut Self {
        self.0.source = source.inner().octets();
        self
    }

    /// Set the source ip of the header.
    ///
    /// # Safety
    ///
    /// This method does not check to ensure that the source is valid.
    /// For example, a multicast source can be assigned to a packet with this method.
    ///
    /// Note(manish) Why do we even have this function?
    #[allow(unsafe_code)]
    pub unsafe fn set_source_unchecked(&mut self, source: Ipv4Addr) -> &mut Self {
        self.0.source = source.octets();
        self
    }

    /// Set the destination ip address for this header.
    pub fn set_destination(&mut self, dest: Ipv4Addr) -> &mut Self {
        self.0.destination = dest.octets();
        self
    }

    /// Set the header's time to live
    /// (i.e., the maximum number of routing hops it can traverse without being dropped).
    pub fn set_ttl(&mut self, ttl: u8) -> &mut Self {
        self.0.time_to_live = ttl;
        self
    }

    /// Attempt to decrement the TTL.
    ///
    /// # Errors
    ///
    /// Returns a [`TtlAlreadyZero`] if the ttl is already at zero.
    /// This outcome usually indicated the need to drop the packet in a routing stack.
    pub fn decrement_ttl(&mut self) -> Result<(), TtlAlreadyZero> {
        if self.0.time_to_live == 0 {
            return Err(TtlAlreadyZero);
        }
        self.0.time_to_live -= 1;
        self.update_checksum();
        Ok(())
    }

    /// Set the header's [explicit congestion notification]
    ///
    /// [explicit congestion notification]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
    pub fn set_ecn(&mut self, ecn: Ecn) -> &mut Self {
        self.0.ecn = ecn.0;
        self
    }

    /// Set the header's [differentiated services code point].
    ///
    /// [differentiated services code point]: https://en.wikipedia.org/wiki/Differentiated_services
    pub fn set_dscp(&mut self, dscp: Dscp) -> &mut Self {
        self.0.dscp = dscp.0;
        self
    }

    /// Set the "identification"
    /// of this packet i.e., the number used to identify packets that contain an originally
    /// fragmented packet.
    pub fn set_identification(&mut self, id: u16) -> &mut Self {
        self.0.identification = id;
        self
    }

    /// Set the "don't fragment" bit of the header
    pub fn set_dont_fragment(&mut self, dont_fragment: bool) -> &mut Self {
        self.0.dont_fragment = dont_fragment;
        self
    }

    /// Set the "more-fragments" flag
    ///
    /// # Safety
    ///
    /// This function does not (and can-not)
    /// check if there are actually more fragments to the packet.
    pub fn set_more_fragments(&mut self, more_fragments: bool) -> &mut Self {
        self.0.more_fragments = more_fragments;
        self
    }

    /// Set the fragment offset
    ///
    /// # Safety
    ///
    /// This function does not (and can-not) check if the assigned fragment offset is valid or even
    /// reasonable.
    pub fn set_fragment_offset(&mut self, fragment_offset: FragOffset) -> &mut Self {
        self.0.fragment_offset = fragment_offset.0;
        self
    }

    /// Set the next layer protocol.
    ///
    /// # Safety
    ///
    /// This function does not (and can-not)
    /// check if the assigned [`IpNumber`] is valid for this packet.
    #[allow(unsafe_code)]
    pub unsafe fn set_next_header(&mut self, next_header: NextHeader) -> &mut Self {
        self.0.protocol = next_header.0;
        self
    }

    /// Set the length _of the payload_ of the ipv4 packet.
    ///
    /// This method will adjust the total length of the header to account for options and the length
    /// of this header.
    ///
    /// This method _will not_ update the checksum of the header.
    /// # Errors
    ///    This method returns [`Ipv4LengthError`] if the value is too big
    pub fn set_payload_len(&mut self, payload_len: u16) -> Result<(), Ipv4LengthError> {
        match self.0.set_payload_len(payload_len as usize) {
            Ok(()) => Ok(()),
            Err(err) => Err(Ipv4LengthError {
                requested: payload_len as usize + self.header_len(),
                max: err.max_allowed,
            }),
        }
    }
}

/// Error which is triggered when decrementing the TTL which is already zero.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[repr(transparent)]
#[error("ttl is already zero")]
pub struct TtlAlreadyZero;

/// Error which is triggered during construction of an [`Ipv4`] object.
#[derive(thiserror::Error, Debug)]
pub enum Ipv4Error {
    /// Source address is invalid because it is multicast.
    #[error("multicast source forbidden (received {0})")]
    InvalidSourceAddr(Ipv4Addr),
    /// Error triggered when etherparse fails to parse the header.
    #[error(transparent)]
    Invalid(etherparse::err::ipv4::HeaderSliceError),
}

impl Parse for Ipv4 {
    type Error = Ipv4Error;
    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (etherparse_header, rest) =
            Ipv4Header::from_slice(buf).map_err(|e| ParseError::Invalid(Ipv4Error::Invalid(e)))?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((
            Self::new(etherparse_header).map_err(ParseError::Invalid)?,
            consumed,
        ))
    }
}

impl DeParse for Ipv4 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // ipv4 headers have safe upper bound on length
        NonZero::new(self.0.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(DeParseError::BufferTooLong(buf.len()));
        }
        let len = buf.len();
        if len < self.size().into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        buf[..(self.size().get() as usize)].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}

pub(crate) enum Ipv4Next {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    IpAuth(IpAuth),
}

impl ParsePayload for Ipv4 {
    type Next = Ipv4Next;

    fn parse_payload(&self, cursor: &mut Reader) -> Option<Self::Next> {
        match self.0.protocol {
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
                trace!("unsupported protocol: {:?}", self.0.protocol);
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

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ip::NextHeader;
    use crate::ipv4::Ipv4;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use etherparse::Ipv4Header;
    use std::net::Ipv4Addr;

    /// A [`bolero::TypeGenerator`] for common (and supported) [`NextHeader`] values
    #[derive(Copy, Clone, Debug, bolero::TypeGenerator)]
    pub enum CommonNextHeader {
        /// TCP next header (see [`NextHeader::TCP`]
        Tcp,
        /// UDP next header (see [`NextHeader::UDP`]
        Udp,
        /// ICMP next header (see [`NextHeader::ICMP`]
        Icmp4,
    }

    impl From<CommonNextHeader> for NextHeader {
        fn from(value: CommonNextHeader) -> Self {
            match value {
                CommonNextHeader::Tcp => NextHeader::TCP,
                CommonNextHeader::Udp => NextHeader::UDP,
                CommonNextHeader::Icmp4 => NextHeader::ICMP,
            }
        }
    }

    /// [`ValueGenerator`] for an (otherwise) arbitrary [`Ipv4`] with a specified [`NextHeader`].
    pub struct GenWithNextHeader(pub NextHeader);

    impl ValueGenerator for GenWithNextHeader {
        type Output = Ipv4;

        /// Generates an arbitrary [`Ipv4`] header with the [`NextHeader`] specified in `self`.
        fn generate<D: Driver>(&self, u: &mut D) -> Option<Self::Output> {
            let mut header = Ipv4(Ipv4Header::default());
            header.set_source(u.produce()?);
            header.set_destination(Ipv4Addr::from(u.produce::<u32>()?));

            // safe in so far as the whole point of this method is to generate a header with
            // the specified `NextHeader`.
            #[allow(unsafe_code)]
            unsafe {
                header.set_next_header(self.0);
            }
            header
                .set_ttl(u.produce()?)
                .set_dscp(u.produce()?)
                .set_ecn(u.produce()?)
                .set_dont_fragment(u.produce()?)
                .set_more_fragments(u.produce()?)
                .set_identification(u.produce()?)
                .set_fragment_offset(u.produce()?);
            Some(header)
        }
    }

    impl TypeGenerator for Ipv4 {
        /// Generates an arbitrary [`Ipv4`] header.
        ///
        /// # Note
        ///
        /// Ideally, the generated header would cover the space of all possible [`Ipv4`] headers.
        /// That is, if you called `generate` a (very) large number of times, you would eventually
        /// reach the set of all [`Ipv4`] (as should be true with any implementation of
        /// [`TypeGenerator`]).
        ///
        /// Unfortunately, the current implementation does not cover [`Ipv4::options`].
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            GenWithNextHeader(u.produce()?).generate(u)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::ipv4::{Ipv4, Ipv4Error};
    use crate::parse::{DeParse, IntoNonZeroUSize, Parse, ParseError};
    use etherparse::err::ipv4::{HeaderError, HeaderSliceError};

    const MIN_LEN_USIZE: usize = 20;
    const MAX_LEN_USIZE: usize = 60;

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!().with_type().for_each(|header: &Ipv4| {
            let mut buffer = [0u8; MIN_LEN_USIZE];
            let bytes_written = header
                .deparse(&mut buffer)
                .unwrap_or_else(|e| unreachable!("{e:?}"));
            assert_eq!(bytes_written, Ipv4::MIN_LEN);
            let (parse_back, bytes_read) = Ipv4::parse(&buffer[..(bytes_written.get() as usize)])
                .unwrap_or_else(|e| unreachable!("{e:?}"));
            assert_eq!(header.source(), parse_back.source());
            assert_eq!(header.destination(), parse_back.destination());
            assert_eq!(header.protocol(), parse_back.protocol());
            assert_eq!(header.ecn(), parse_back.ecn());
            assert_eq!(header.dscp(), parse_back.dscp());
            #[cfg(not(kani))] // remove when we fix options generation
            assert_eq!(header, &parse_back);
            assert_eq!(bytes_written, bytes_read);
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; MAX_LEN_USIZE]| {
                match Ipv4::parse(slice) {
                    Ok((header, consumed)) => {
                        assert!(consumed.into_non_zero_usize().get() <= slice.len());
                        let mut buf = vec![0; consumed.into_non_zero_usize().get()];
                        header.deparse(&mut buf).unwrap();
                        assert_eq!(&slice[..=5], &buf.as_slice()[..=5]);
                        // reserved bit in ipv4 flags should serialize to zero
                        assert_eq!(slice[6] & 0b0111_1111, buf[6]);
                        assert_eq!(&slice[7..MIN_LEN_USIZE], &buf.as_slice()[7..MIN_LEN_USIZE]);
                        #[cfg(not(kani))] // remove when we fix options generation
                        assert_eq!(
                            &slice[MIN_LEN_USIZE..consumed.into_non_zero_usize().get()],
                            &buf.as_slice()[MIN_LEN_USIZE..consumed.into_non_zero_usize().get()]
                        );
                    }
                    Err(e) => match e {
                        ParseError::Length(e) => {
                            assert!(e.expected.get() < slice.len());
                            assert_eq!(e.actual, slice.len());
                        }
                        ParseError::Invalid(Ipv4Error::InvalidSourceAddr(source)) => {
                            assert!(source.is_multicast());
                        }
                        ParseError::Invalid(Ipv4Error::Invalid(HeaderSliceError::Content(
                            HeaderError::UnexpectedVersion { version_number },
                        ))) => assert_ne!(version_number, 4),
                        ParseError::Invalid(Ipv4Error::Invalid(HeaderSliceError::Content(
                            HeaderError::HeaderLengthSmallerThanHeader { ihl },
                        ))) => {
                            // Remember, ihl is given in units of 4-byte values.
                            // The minimum header is 5 * 4 = 20 bytes.
                            assert!(((4 * ihl) as usize) < MIN_LEN_USIZE);
                        }
                        ParseError::Invalid(_) | ParseError::BufferTooLong(_) => unreachable!(),
                    },
                }
            });
    }
}
