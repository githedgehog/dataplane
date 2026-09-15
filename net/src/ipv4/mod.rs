// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ipv4 Address type and manipulation

use crate::headers::{EmbeddedHeader, Header};
use crate::icmp4::{Icmp4, TruncatedIcmp4};
use crate::impl_from_for_enum;
use crate::ip::NextHeader;
use crate::ip::dscp::Dscp;
use crate::ip::ecn::Ecn;
use crate::ip_auth::Ipv4Auth;
pub use crate::ipv4::addr::UnicastIpv4Addr;
use crate::ipv4::frag_offset::FragOffset;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParseHeader, Reader,
};
use crate::tcp::{Tcp, TruncatedTcp};
use crate::udp::{TruncatedUdp, Udp};
use etherparse::{IpDscp, IpEcn, IpFragOffset, IpNumber, Ipv4Options};
use std::net::Ipv4Addr;
use std::num::NonZero;
use tracing::trace;

pub mod addr;

mod checksum;
pub mod frag_offset;

pub use checksum::*;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// An IPv4 header
///
/// The fixed twenty bytes are stored inline; the options are boxed.
///
/// # Why the options are boxed
///
/// This type used to be a newtype over [`etherparse::Ipv4Header`], which is 64 bytes -- 41 of
/// them an inline `Ipv4Options { len: u8, buf: [u8; 40] }`. IPv4 options are vanishingly rare
/// in forwarded traffic, so ordinary packets paid for a 40-byte buffer they never filled, in a
/// struct that is copied at every stage of the pipeline.
///
/// The first saturation profile taken on hardware (2026-09-12, 4 workers at 5.6 Mpps) found
/// `Ipv4::parse` at 16.8% of all cycles, with **78.9% of its own samples on a single `vmovups`
/// store to the stack**: a chain of redundant copies of that 64-byte header, not any real work.
/// `Headers::parse` showed the same shape with a 1,544-byte stack frame. Boxing the options
/// halves this type, and lets `deparse` write only the bytes the header actually has rather
/// than materializing all 60 and truncating, as `Ipv4Header::to_bytes` does.
///
/// `options` is normalized: it is `None`, never `Some(empty)`, so that [`PartialEq`] agrees
/// with what is on the wire. Construct it only through [`Ipv4::set_options`].
///
/// See the `size_budget` test in [`crate::headers`] for the companion budget on `Headers`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ipv4 {
    pub(crate) source: [u8; 4],
    pub(crate) destination: [u8; 4],
    pub(crate) options: Option<Box<Ipv4Options>>,
    pub(crate) total_len: u16,
    pub(crate) identification: u16,
    pub(crate) fragment_offset: IpFragOffset,
    pub(crate) header_checksum: u16,
    pub(crate) dscp: IpDscp,
    pub(crate) ecn: IpEcn,
    pub(crate) time_to_live: u8,
    pub(crate) protocol: IpNumber,
    pub(crate) dont_fragment: bool,
    pub(crate) more_fragments: bool,
}

/// Error describing illegal length in an IPv4 header
#[derive(Debug, thiserror::Error)]
#[error(
    "Invalid IPv4 length requested: {requested}, max is {max} when considering all options and headers"
)]
pub struct Ipv4LengthError {
    requested: usize,
    max: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
#[error("invalid IPv4 options length {len}: must be a multiple of 4 and at most 40 bytes")]
#[allow(missing_docs)]
pub struct Ipv4OptionsLenError {
    len: usize,
}

impl Ipv4 {
    /// The minimum length of an IPv4 header (i.e., a header with no options)
    #[allow(clippy::unwrap_used)] // const-eval and trivially safe
    pub const MIN_LEN: NonZero<u16> = NonZero::new(20).unwrap();

    /// The maximum length of an IPv4 header (i.e., a header with full options)
    #[allow(clippy::unwrap_used)] // const-eval and trivially safe
    pub const MAX_LEN: NonZero<u16> = NonZero::new(60).unwrap();

    /// Build from a borrowed view of the wire bytes.
    ///
    /// Deliberately does *not* go through [`etherparse::Ipv4HeaderSlice::to_header`]: that
    /// materializes a 64-byte owned header, 41 bytes of which are an options buffer that is
    /// empty on essentially all traffic, and the copy then propagates through every move of
    /// the result. Reading the fields we keep costs a fraction of that.
    fn from_header_slice(slice: &etherparse::Ipv4HeaderSlice<'_>) -> Result<Self, Ipv4Error> {
        UnicastIpv4Addr::new(slice.source_addr()).map_err(Ipv4Error::InvalidSourceAddr)?;
        let options = slice.options();
        Ok(Self {
            source: slice.source(),
            destination: slice.destination(),
            // normalized: never `Some` of an empty options block. See the type's docs.
            options: if options.is_empty() {
                None
            } else {
                Some(Box::new(
                    Ipv4Options::try_from(options).unwrap_or_else(|_| unreachable!()),
                ))
            },
            total_len: slice.total_len(),
            identification: slice.identification(),
            fragment_offset: slice.fragments_offset(),
            header_checksum: slice.header_checksum(),
            // `dcp` is etherparse's spelling; it is the DSCP field.
            dscp: slice.dcp(),
            ecn: slice.ecn(),
            time_to_live: slice.ttl(),
            protocol: slice.protocol(),
            dont_fragment: slice.dont_fragment(),
            more_fragments: slice.more_fragments(),
        })
    }

    /// Length of the options in bytes (zero when there are none).
    fn options_len(&self) -> usize {
        self.options.as_deref().map_or(0, Ipv4Options::len)
    }

    /// The IHL field: header length in 32-bit words.
    #[allow(clippy::cast_possible_truncation)] // options are at most 40 bytes
    fn ihl(&self) -> u8 {
        (self.options_len() / 4) as u8 + 5
    }

    /// Bytes 6 and 7 of the header: the three flag bits packed above the fragment offset.
    ///
    /// The reserved bit is always emitted as zero, which is why `parse_arbitrary_bytes`
    /// compares byte 6 under a `0b0111_1111` mask.
    fn flags_and_fragment_offset(&self) -> [u8; 2] {
        let frag = self.fragment_offset.value().to_be_bytes();
        let mut flags = 0u8;
        if self.dont_fragment {
            flags |= 0b0100_0000;
        }
        if self.more_fragments {
            flags |= 0b0010_0000;
        }
        [flags | (frag[0] & 0x1f), frag[1]]
    }

    /// Write the header into `buf`, which must be exactly [`Ipv4::header_len`] bytes.
    ///
    /// Byte-for-byte identical to `etherparse::Ipv4Header::to_bytes`, but writes only the bytes
    /// the header actually has. `to_bytes` builds all 60 -- including 40 option bytes it then
    /// truncates away -- on every single call, which showed up in the on-hardware profile.
    fn write_header(&self, buf: &mut [u8]) {
        debug_assert_eq!(
            buf.len(),
            self.header_len(),
            "buffer is not the header's size"
        );
        let total_len = self.total_len.to_be_bytes();
        let id = self.identification.to_be_bytes();
        let frag = self.flags_and_fragment_offset();
        let checksum = self.header_checksum.to_be_bytes();
        buf[0] = (4 << 4) | self.ihl();
        buf[1] = (self.dscp.value() << 2) | self.ecn.value();
        buf[2] = total_len[0];
        buf[3] = total_len[1];
        buf[4] = id[0];
        buf[5] = id[1];
        buf[6] = frag[0];
        buf[7] = frag[1];
        buf[8] = self.time_to_live;
        buf[9] = self.protocol.0;
        buf[10] = checksum[0];
        buf[11] = checksum[1];
        buf[12..16].copy_from_slice(&self.source);
        buf[16..20].copy_from_slice(&self.destination);
        buf[20..].copy_from_slice(self.options());
    }

    /// The IPv4 header checksum over this header's own fields.
    ///
    /// Same word sequence as `etherparse::Ipv4Header::calc_header_checksum`, reusing
    /// etherparse's accumulator so the arithmetic cannot drift from it.
    pub(crate) fn compute_header_checksum(&self) -> u16 {
        etherparse::checksum::Sum16BitWords::new()
            .add_2bytes([
                (4 << 4) | self.ihl(),
                (self.dscp.value() << 2) | self.ecn.value(),
            ])
            .add_2bytes(self.total_len.to_be_bytes())
            .add_2bytes(self.identification.to_be_bytes())
            .add_2bytes(self.flags_and_fragment_offset())
            .add_2bytes([self.time_to_live, self.protocol.0])
            .add_4bytes(self.source)
            .add_4bytes(self.destination)
            .add_slice(self.options())
            .ones_complement()
            .to_be()
    }

    /// Get the source ip address of the header
    #[must_use]
    pub fn source(&self) -> UnicastIpv4Addr {
        UnicastIpv4Addr::new(Ipv4Addr::from(self.source)).unwrap_or_else(|_| unreachable!())
    }

    /// Get the destination ip address of the header
    #[must_use]
    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.destination)
    }

    // TODO: proper wrapper type
    /// Get the options for this header (as a byte slice)
    #[must_use]
    pub fn options(&self) -> &[u8] {
        self.options
            .as_deref()
            .map_or(&[][..], Ipv4Options::as_slice)
    }

    /// Set this header's options to `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Ipv4OptionsLenError`] if `data` is longer than the options field can hold.
    pub fn set_options(&mut self, data: &[u8]) -> Result<&mut Self, Ipv4OptionsLenError> {
        if data.is_empty() {
            self.options = None;
            return Ok(self);
        }
        let options =
            Ipv4Options::try_from(data).map_err(|_| Ipv4OptionsLenError { len: data.len() })?;
        self.options = Some(Box::new(options));
        Ok(self)
    }

    // TODO: proper wrapper type for [`IpNumber`] (low priority)
    /// Get the next layer protocol which follows this header.
    #[must_use]
    pub fn protocol(&self) -> IpNumber {
        self.protocol
    }

    /// The IP protocol / next-header field as a [`NextHeader`].
    #[must_use]
    pub fn next_header(&self) -> NextHeader {
        self.protocol.into()
    }

    /// Length of the header (includes options) in bytes.
    ///
    /// <div class="warning">
    /// The returned value is in bytes (not in units of 32 bits as per the IHL field).
    /// </div>
    #[must_use]
    pub fn header_len(&self) -> usize {
        Self::MIN_LEN.get() as usize + self.options_len()
    }

    /// Value of total length ip header field
    #[must_use]
    pub fn total_len(&self) -> u16 {
        self.total_len
    }

    /// Length of the payload this header claims to carry, i.e. `total_len` less the header.
    ///
    /// Returns `None` when `total_len` is smaller than the header itself, which is a malformed
    /// header rather than a zero-length payload.
    #[must_use]
    pub fn payload_len(&self) -> Option<u16> {
        #[allow(clippy::cast_possible_truncation)] // header_len() is at most 60
        let header_len = self.header_len() as u16;
        self.total_len.checked_sub(header_len)
    }

    /// The number of routing hops the packet is allowed to take.
    #[must_use]
    pub fn ttl(&self) -> u8 {
        self.time_to_live
    }

    // TODO: proper wrapper type (low priority)
    /// Get the header's [differentiated services code point].
    ///
    /// [differentiated services code point]: https://en.wikipedia.org/wiki/Differentiated_services
    #[must_use]
    pub fn dscp(&self) -> IpDscp {
        self.dscp
    }

    // TODO: proper wrapper type (low priority)
    /// Get the header's [explicit congestion notification]
    ///
    /// [explicit congestion notification]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
    #[must_use]
    pub fn ecn(&self) -> IpEcn {
        self.ecn
    }

    /// Returns true if the "don't fragment" bit is set in this header.
    #[must_use]
    pub fn dont_fragment(&self) -> bool {
        self.dont_fragment
    }

    /// Returns true if the "more-fragments" bit is set in this header.
    #[must_use]
    pub fn more_fragments(&self) -> bool {
        self.more_fragments
    }

    // TODO: proper wrapper type (low priority)
    /// In case this message contains parts of a fragmented packet, the fragment offset is the
    /// offset of payload the current message relative to the original payload of the message.
    #[must_use]
    pub fn fragment_offset(&self) -> IpFragOffset {
        self.fragment_offset
    }

    /// Return the headers "identification".
    /// See [IP fragmentation]
    ///
    /// [IP Fragmentation]: https://en.wikipedia.org/wiki/IP_fragmentation
    #[must_use]
    pub fn identification(&self) -> u16 {
        self.identification
    }

    /// Set the source ip of the header.
    pub fn set_source(&mut self, source: UnicastIpv4Addr) -> &mut Self {
        self.source = source.inner().octets();
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
    pub unsafe fn set_source_unchecked(&mut self, source: impl Into<Ipv4Addr>) -> &mut Self {
        self.source = source.into().octets();
        self
    }

    /// Set the destination ip address for this header.
    pub fn set_destination(&mut self, dest: Ipv4Addr) -> &mut Self {
        self.destination = dest.octets();
        self
    }

    /// Set the header's time to live
    /// (i.e., the maximum number of routing hops it can traverse without being dropped).
    pub fn set_ttl(&mut self, ttl: u8) -> &mut Self {
        self.time_to_live = ttl;
        self
    }

    /// Attempt to decrement the TTL.
    ///
    /// # Errors
    ///
    /// Returns a [`TtlAlreadyZero`] if the ttl is already at zero.
    /// This outcome usually indicated the need to drop the packet in a routing stack.
    pub fn decrement_ttl(&mut self) -> Result<(), TtlAlreadyZero> {
        if self.time_to_live == 0 {
            return Err(TtlAlreadyZero);
        }
        self.time_to_live -= 1;
        Ok(())
    }

    /// Set the header's [explicit congestion notification]
    ///
    /// [explicit congestion notification]: https://en.wikipedia.org/wiki/Explicit_Congestion_Notification
    pub fn set_ecn(&mut self, ecn: Ecn) -> &mut Self {
        self.ecn = ecn.0;
        self
    }

    /// Set the header's [differentiated services code point].
    ///
    /// [differentiated services code point]: https://en.wikipedia.org/wiki/Differentiated_services
    pub fn set_dscp(&mut self, dscp: Dscp) -> &mut Self {
        self.dscp = dscp.0;
        self
    }

    /// Set the "identification"
    /// of this packet i.e., the number used to identify packets that contain an originally
    /// fragmented packet.
    pub fn set_identification(&mut self, id: u16) -> &mut Self {
        self.identification = id;
        self
    }

    /// Set the "don't fragment" bit of the header
    pub fn set_dont_fragment(&mut self, dont_fragment: bool) -> &mut Self {
        self.dont_fragment = dont_fragment;
        self
    }

    /// Set the "more-fragments" flag
    ///
    /// # Safety
    ///
    /// This function does not (and can-not)
    /// check if there are actually more fragments to the packet.
    pub fn set_more_fragments(&mut self, more_fragments: bool) -> &mut Self {
        self.more_fragments = more_fragments;
        self
    }

    /// Set the fragment offset
    ///
    /// # Safety
    ///
    /// This function does not (and can-not) check if the assigned fragment offset is valid or even
    /// reasonable.
    pub fn set_fragment_offset(&mut self, fragment_offset: FragOffset) -> &mut Self {
        self.fragment_offset = fragment_offset.0;
        self
    }

    /// Set the next layer protocol.
    ///
    /// # Safety
    ///
    /// This function does not (and can-not)
    /// check if the assigned [`IpNumber`] is valid for this packet.
    pub fn set_next_header(&mut self, next_header: NextHeader) -> &mut Self {
        self.protocol = next_header.0;
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
        // Matches `etherparse::Ipv4Header::set_payload_len`: the bound is
        // `u16::MAX - options_len - 20`, and `total_len` covers header plus payload.
        let header_len = self.header_len();
        let max = usize::from(u16::MAX) - self.options_len() - Self::MIN_LEN.get() as usize;
        let requested = payload_len as usize + header_len;
        if payload_len as usize > max {
            return Err(Ipv4LengthError { requested, max });
        }
        #[allow(clippy::cast_possible_truncation)] // bounded by the check above
        {
            self.total_len = requested as u16;
        }
        Ok(())
    }

    /// Parse the payload of the ipv4 packet.
    ///
    /// # Returns
    ///
    /// * `Some(Ipv4Next)` if the payload is a supported protocol
    /// * `None` if the payload is not a supported protocol
    pub(crate) fn parse_payload(&self, cursor: &mut Reader) -> Option<Ipv4Next> {
        match self.protocol {
            IpNumber::TCP => cursor.parse_header::<Tcp, Ipv4Next>(),
            IpNumber::UDP => cursor.parse_header::<Udp, Ipv4Next>(),
            IpNumber::ICMP => cursor.parse_header::<Icmp4, Ipv4Next>(),
            IpNumber::AUTHENTICATION_HEADER => cursor.parse_header::<Ipv4Auth, Ipv4Next>(),
            _ => {
                trace!("unsupported protocol: {:?}", self.protocol);
                None
            }
        }
    }

    /// Parse the payload of an IPv4 packet embedded in an ICMP Error message.
    ///
    /// # Returns
    ///
    /// * `Some(EmbeddedIpv4Next)` if the payload is a supported protocol
    /// * `None` if the payload is not a supported protocol
    pub(crate) fn parse_embedded_payload(&self, cursor: &mut Reader) -> Option<EmbeddedIpv4Next> {
        match self.protocol {
            IpNumber::TCP => cursor.parse_header::<TruncatedTcp, EmbeddedIpv4Next>(),
            IpNumber::UDP => cursor.parse_header::<TruncatedUdp, EmbeddedIpv4Next>(),
            IpNumber::ICMP => cursor.parse_header::<TruncatedIcmp4, EmbeddedIpv4Next>(),
            IpNumber::AUTHENTICATION_HEADER => cursor.parse_header::<Ipv4Auth, EmbeddedIpv4Next>(),
            _ => {
                trace!("unsupported protocol: {:?}", self.protocol);
                None
            }
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
    /// Source address is invalid because it is not a unicast address.
    #[error("multicast and broadcast source forbidden (received {0})")]
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
        let slice = etherparse::Ipv4HeaderSlice::from_slice(buf)
            .map_err(|e| ParseError::Invalid(Ipv4Error::Invalid(e)))?;
        // `Ipv4HeaderSlice` only validates once it has a header that fits, so the slice it
        // reports is non-empty and no longer than the buffer it came from.
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed = NonZero::new(slice.slice().len() as u16).ok_or_else(|| unreachable!())?;
        Ok((
            Self::from_header_slice(&slice).map_err(ParseError::Invalid)?,
            consumed,
        ))
    }
}

impl DeParse for Ipv4 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // ipv4 headers have safe upper bound on length
        NonZero::new(self.header_len() as u16).unwrap_or_else(|| unreachable!())
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
        self.write_header(&mut buf[..(self.size().get() as usize)]);
        Ok(self.size())
    }
}

pub(crate) enum Ipv4Next {
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Ipv4Auth(Ipv4Auth),
}

impl_from_for_enum![
    Ipv4Next,
    Tcp(Tcp),
    Udp(Udp),
    Icmp4(Icmp4),
    Ipv4Auth(Ipv4Auth)
];

impl From<Ipv4Next> for Header {
    fn from(value: Ipv4Next) -> Self {
        match value {
            Ipv4Next::Tcp(x) => Header::Tcp(x),
            Ipv4Next::Udp(x) => Header::Udp(x),
            Ipv4Next::Icmp4(x) => Header::Icmp4(x),
            Ipv4Next::Ipv4Auth(x) => Header::Ipv4Auth(x),
        }
    }
}

pub(crate) enum EmbeddedIpv4Next {
    Tcp(TruncatedTcp),
    Udp(TruncatedUdp),
    Icmp4(TruncatedIcmp4),
    Ipv4Auth(Ipv4Auth),
}

impl_from_for_enum![
    EmbeddedIpv4Next,
    Tcp(TruncatedTcp),
    Udp(TruncatedUdp),
    Icmp4(TruncatedIcmp4),
    Ipv4Auth(Ipv4Auth),
];

impl From<EmbeddedIpv4Next> for EmbeddedHeader {
    fn from(value: EmbeddedIpv4Next) -> Self {
        match value {
            EmbeddedIpv4Next::Tcp(x) => EmbeddedHeader::Tcp(x),
            EmbeddedIpv4Next::Udp(x) => EmbeddedHeader::Udp(x),
            EmbeddedIpv4Next::Icmp4(x) => EmbeddedHeader::Icmp4(x),
            EmbeddedIpv4Next::Ipv4Auth(x) => EmbeddedHeader::Ipv4Auth(x),
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::ip::NextHeader;
    use crate::ipv4::Ipv4;
    use bolero::generator::bolero_generator::bounded::BoundedValue;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use std::collections::Bound;
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
            let mut header = Ipv4::default();
            let option_words = u8::gen_bounded(u, Bound::Included(&0), Bound::Included(&10))?;
            let mut options = [0u8; (Ipv4::MAX_LEN.get() - Ipv4::MIN_LEN.get()) as usize];
            let options = &mut options[..(option_words as usize) * 4];
            for byte in options.iter_mut() {
                *byte = u.produce()?;
            }
            header.set_options(options).ok()?;
            header.set_source(u.produce()?);
            header.set_destination(Ipv4Addr::from(u.produce::<u32>()?));
            header.set_next_header(self.0);
            header
                .set_ttl(u.produce()?)
                .set_dscp(u.produce()?)
                .set_ecn(u.produce()?)
                .set_dont_fragment(u.produce()?)
                .set_more_fragments(u.produce()?)
                .set_identification(u.produce()?)
                .set_fragment_offset(u.produce()?);
            header
                .set_payload_len(u16::gen_bounded(
                    u,
                    Bound::Included(&Ipv4::MIN_LEN.get()),
                    Bound::Included(&Ipv4::MAX_LEN.get()),
                )?)
                .ok();
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
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            GenWithNextHeader(u.produce()?).generate(u)
        }
    }
}

#[cfg(test)]
mod size_budget {
    use super::Ipv4;

    /// `Ipv4` travels inside `Headers`, which is moved by value at every pipeline stage, so its
    /// size is a per-packet cost paid many times over.
    ///
    /// It was 64 bytes as a newtype over `etherparse::Ipv4Header`, 41 of which were an inline
    /// `Ipv4Options { len: u8, buf: [u8; 40] }` that is empty on essentially all forwarded
    /// traffic. The first on-hardware saturation profile (2026-09-12) found `Ipv4::parse` at
    /// 13-17% of all cycles with 79% of its own samples on one stack-copy instruction --
    /// the signature of shuffling that struct around, not of parsing.
    ///
    /// Raise this deliberately if a field has to grow, and prefer boxing a cold field over
    /// raising it. See the companion budget on `Headers` in [`crate::headers`].
    #[test]
    fn ipv4_stays_small() {
        const BUDGET: usize = 32;
        assert!(
            size_of::<Ipv4>() <= BUDGET,
            "Ipv4 is {} bytes, over the {BUDGET}-byte budget; it rides inside Headers, which is \
             moved by value at every pipeline stage. Box the cold field rather than raising this.",
            size_of::<Ipv4>()
        );
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
    fn parse_back() {
        bolero::check!().with_type().for_each(|header: &Ipv4| {
            let mut buffer = [0u8; MAX_LEN_USIZE];
            let bytes_written = header
                .deparse(&mut buffer)
                .unwrap_or_else(|e| unreachable!("{e:?}"));
            assert_eq!(bytes_written.get() as usize, header.header_len());
            assert!(bytes_written >= Ipv4::MIN_LEN && bytes_written <= Ipv4::MAX_LEN);
            let (parse_back, bytes_read) = Ipv4::parse(&buffer[..(bytes_written.get() as usize)])
                .unwrap_or_else(|e| unreachable!("{e:?}"));
            assert_eq!(header.options(), parse_back.options());
            assert_eq!(header.source(), parse_back.source());
            assert_eq!(header.destination(), parse_back.destination());
            assert_eq!(header.protocol(), parse_back.protocol());
            assert_eq!(header.ecn(), parse_back.ecn());
            assert_eq!(header.dscp(), parse_back.dscp());
            assert_eq!(header, &parse_back);
            assert_eq!(bytes_written, bytes_read);
        });
    }

    #[test]
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
                            assert!(source.is_multicast() || source.is_broadcast());
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
