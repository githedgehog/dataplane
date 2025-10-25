// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `Icmp6` header type and logic.

mod checksum;
mod truncated;

pub use checksum::*;
pub use truncated::*;

use crate::headers::{AbstractEmbeddedHeaders, EmbeddedHeaders, EmbeddedIpVersion};
use crate::icmp_any::get_payload_for_checksum;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParseWith, Reader,
};
use etherparse::{Icmpv6Header, Icmpv6Type};
use std::num::NonZero;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// An `Icmp6` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp6(pub(crate) Icmpv6Header);

impl Icmp6 {
    /// Returns the type of the `Icmp6` message.
    #[must_use]
    pub const fn icmp_type(&self) -> Icmpv6Type {
        self.0.icmp_type
    }

    /// Returns a mutable reference to the type of the `Icmp6` message.
    #[must_use]
    pub const fn icmp_type_mut(&mut self) -> &mut Icmpv6Type {
        &mut self.0.icmp_type
    }

    /// Returns true if the ICMP type is an error message
    #[must_use]
    pub fn is_error_message(&self) -> bool {
        // List all types to make it sure we catch any new addition to the enum
        match self.icmp_type() {
            Icmpv6Type::DestinationUnreachable(_)
            | Icmpv6Type::PacketTooBig { .. }
            | Icmpv6Type::TimeExceeded(_)
            | Icmpv6Type::ParameterProblem(_) => true,
            Icmpv6Type::Unknown { .. }
            | Icmpv6Type::EchoRequest(_)
            | Icmpv6Type::EchoReply(_)
            | Icmpv6Type::RouterSolicitation
            | Icmpv6Type::RouterAdvertisement(_)
            | Icmpv6Type::NeighborSolicitation
            | Icmpv6Type::NeighborAdvertisement(_)
            | Icmpv6Type::Redirect => false,
        }
    }

    /// Returns the identifier field value if the ICMP type allows it.
    #[must_use]
    pub fn identifier(&self) -> Option<u16> {
        match self.icmp_type() {
            Icmpv6Type::EchoRequest(msg) | Icmpv6Type::EchoReply(msg) => Some(msg.id),
            _ => None,
        }
    }

    /// Creates a new `Icmp6` with the given type.
    ///
    /// The checksum will be set to zero.
    #[must_use]
    pub const fn with_type(icmp_type: Icmpv6Type) -> Self {
        Self(Icmpv6Header {
            icmp_type,
            checksum: 0,
        })
    }

    #[must_use]
    pub(crate) fn supports_extensions(&self) -> bool {
        // See RFC 4884.
        matches!(
            self.icmp_type(),
            Icmpv6Type::DestinationUnreachable(_)
                | Icmpv6Type::TimeExceeded(_)
                | Icmpv6Type::ParameterProblem(_)
        )
    }

    fn payload_length(&self, buf: &[u8]) -> usize {
        // See RFC 4884.
        if !self.supports_extensions() {
            return 0;
        }
        let payload_length = buf[4];
        payload_length as usize * 8
    }

    pub(crate) fn parse_payload(&self, cursor: &mut Reader) -> Option<EmbeddedHeaders> {
        if !self.is_error_message() {
            return None;
        }
        let (mut headers, consumed) = EmbeddedHeaders::parse_with(
            EmbeddedIpVersion::Ipv6,
            &cursor.inner[cursor.inner.len() - cursor.remaining as usize..],
        )
        .ok()?;
        cursor.consume(consumed).ok()?;

        // Mark whether the payload of the embedded IP packet is full
        headers.check_full_payload(
            &cursor.inner[cursor.inner.len() - cursor.remaining as usize..],
            cursor.remaining as usize,
            consumed.get() as usize,
            self.payload_length(cursor.inner),
        );

        Some(headers)
    }

    /// Generate the payload for checksum calculation
    #[must_use]
    pub fn get_payload_for_checksum(
        &self,
        embedded_headers: Option<&impl AbstractEmbeddedHeaders>,
        payload: &[u8],
    ) -> Vec<u8> {
        if !self.is_error_message() {
            return payload.to_vec();
        }
        get_payload_for_checksum(embedded_headers, payload)
    }
}

impl Parse for Icmp6 {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = Icmpv6Header::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::Length(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Icmp6 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // header size bounded
        NonZero::new(self.0.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        buf[..self.size().into_non_zero_usize().get()].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::headers::{EmbeddedHeaders, EmbeddedTransport, Net};
    use crate::icmp6::{Icmp6, TruncatedIcmp6};
    use crate::ip::NextHeader;
    use crate::ipv6::GenWithNextHeader;
    use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse};
    use crate::tcp::TruncatedTcp;
    use crate::udp::TruncatedUdp;
    use arrayvec::ArrayVec;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use etherparse::icmpv6::{
        DestUnreachableCode, ParameterProblemCode, ParameterProblemHeader, TimeExceededCode,
    };
    use etherparse::{Icmpv6Header, Icmpv6Type};
    use std::num::NonZero;

    /// The number of bytes to use in parsing arbitrary test values for [`Icmp6`]
    pub const BYTE_SLICE_SIZE: usize = 128;

    impl TypeGenerator for Icmp6 {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let buf: [u8; BYTE_SLICE_SIZE] = driver.produce()?;
            let header = match Icmp6::parse(&buf) {
                Ok((h, _)) => h,
                Err(e) => unreachable!("{e:?}", e = e),
            };
            Some(header)
        }
    }

    struct Icmp6DestUnreachableGenerator;
    impl ValueGenerator for Icmp6DestUnreachableGenerator {
        type Output = Icmp6;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv6Header {
                icmp_type: Icmpv6Type::DestinationUnreachable(
                    DestUnreachableCode::from_u8(driver.produce::<u8>()? % 7).unwrap(),
                ),
                checksum: driver.produce()?,
            };
            Some(Icmp6(icmp_header))
        }
    }

    struct Icmp6PacketTooBigGenerator;
    impl ValueGenerator for Icmp6PacketTooBigGenerator {
        type Output = Icmp6;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv6Header {
                icmp_type: Icmpv6Type::PacketTooBig {
                    mtu: driver.produce()?,
                },
                checksum: driver.produce()?,
            };
            Some(Icmp6(icmp_header))
        }
    }

    struct Icmp6TimeExceededGenerator;
    impl ValueGenerator for Icmp6TimeExceededGenerator {
        type Output = Icmp6;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv6Header {
                icmp_type: Icmpv6Type::TimeExceeded(
                    TimeExceededCode::from_u8(driver.produce::<u8>()? % 2).unwrap(),
                ),
                checksum: driver.produce()?,
            };
            Some(Icmp6(icmp_header))
        }
    }

    struct Icmp6ParameterProblemGenerator;
    impl ValueGenerator for Icmp6ParameterProblemGenerator {
        type Output = Icmp6;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv6Header {
                icmp_type: Icmpv6Type::ParameterProblem(ParameterProblemHeader {
                    code: ParameterProblemCode::from_u8(driver.produce::<u8>()? % 11).unwrap(),
                    pointer: driver.produce()?,
                }),
                checksum: driver.produce()?,
            };
            Some(Icmp6(icmp_header))
        }
    }

    /// Generator for `ICMPv6` Error message headers.
    pub struct Icmp6ErrorMsgGenerator;
    impl ValueGenerator for Icmp6ErrorMsgGenerator {
        type Output = Icmp6;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            match driver.produce::<u32>()? % 4 {
                0 => Icmp6DestUnreachableGenerator.generate(driver),
                1 => Icmp6PacketTooBigGenerator.generate(driver),
                2 => Icmp6TimeExceededGenerator.generate(driver),
                _ => Icmp6ParameterProblemGenerator.generate(driver),
            }
        }
    }

    /// Generator for `ICMPv6` Error message embedded IP headers.
    pub struct Icmp6EmbeddedHeadersGenerator;
    impl ValueGenerator for Icmp6EmbeddedHeadersGenerator {
        type Output = EmbeddedHeaders;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let transport = match driver.produce::<u32>()? % 11 {
                0..=3 => Some(EmbeddedTransport::Tcp(
                    driver.produce::<TruncatedTcp>().unwrap(),
                )),
                4..=7 => Some(EmbeddedTransport::Udp(
                    driver.produce::<TruncatedUdp>().unwrap(),
                )),
                8..=9 => Some(EmbeddedTransport::Icmp6(
                    driver.produce::<TruncatedIcmp6>().unwrap(),
                )),
                _ => None,
            };
            let net = match transport {
                Some(EmbeddedTransport::Tcp(_)) => {
                    let net_gen = GenWithNextHeader(NextHeader::TCP);
                    Some(Net::Ipv6(net_gen.generate(driver)?))
                }
                Some(EmbeddedTransport::Udp(_)) => {
                    let net_gen = GenWithNextHeader(NextHeader::UDP);
                    Some(Net::Ipv6(net_gen.generate(driver)?))
                }
                Some(EmbeddedTransport::Icmp4(_)) => {
                    // We never produce ICMPv4 headers to embed inside ICMPv6 Error messages
                    unreachable!()
                }
                Some(EmbeddedTransport::Icmp6(_)) => {
                    let net_gen = GenWithNextHeader(NextHeader::ICMP);
                    Some(Net::Ipv6(net_gen.generate(driver)?))
                }
                None => {
                    if driver.produce::<bool>()? {
                        let net_gen = GenWithNextHeader(NextHeader::TCP);
                        Some(Net::Ipv6(net_gen.generate(driver)?))
                    } else {
                        let net_gen = GenWithNextHeader(NextHeader::UDP);
                        Some(Net::Ipv6(net_gen.generate(driver)?))
                    }
                }
            };
            let headers = EmbeddedHeaders::new(net, transport, ArrayVec::default(), None);
            Some(headers)
        }
    }

    /// Extension Structure for `ICMPv6`
    #[derive(bolero::TypeGenerator)]
    pub struct Icmp6ExtensionStructure([u8; Self::LENGTH]);

    impl Icmp6ExtensionStructure {
        /// The length of an Extension Structure for `ICMPv6`
        pub const LENGTH: usize = 8;
    }

    /// An array of [`Icmp6ExtensionStructure`]
    pub struct Icmp6ExtensionStructures(ArrayVec<Icmp6ExtensionStructure, 8>);

    impl Icmp6ExtensionStructures {
        /// Return the size of the padding area to be filled with zeroes between an ICMP Error
        /// message inner IP packet's payload and `ICMPv6` Extension Structure objects.
        #[must_use]
        pub fn padding_size(payload_size: usize) -> usize {
            if payload_size < 128 {
                128 - payload_size
            } else if payload_size.is_multiple_of(Icmp6ExtensionStructure::LENGTH) {
                0
            } else {
                Icmp6ExtensionStructure::LENGTH - payload_size % Icmp6ExtensionStructure::LENGTH
            }
        }
    }

    impl DeParse for Icmp6ExtensionStructures {
        type Error = ();

        // PANICS IF EMPTY!
        // FIXME: Change error handling if using ICMP Extension Structures outside of tests
        fn size(&self) -> NonZero<u16> {
            #[allow(clippy::cast_possible_truncation)] // header length bounded
            NonZero::new((self.0.len() * Icmp6ExtensionStructure::LENGTH) as u16)
                .unwrap_or_else(|| unreachable!())
        }

        fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
            let len = buf.len();
            if len < self.size().into_non_zero_usize().get() {
                return Err(DeParseError::Length(LengthError {
                    expected: self.size().into_non_zero_usize(),
                    actual: len,
                }));
            }
            let mut offset = 0;
            for s in &self.0 {
                buf[offset..offset + Icmp6ExtensionStructure::LENGTH].copy_from_slice(&s.0);
                offset += Icmp6ExtensionStructure::LENGTH;
            }
            Ok(self.size())
        }
    }

    impl TypeGenerator for Icmp6ExtensionStructures {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let mut extensions = ArrayVec::new();
            while driver.produce::<bool>()? {
                if extensions.len() >= 8 {
                    break;
                }
                extensions.push(driver.produce()?);
            }
            if extensions.is_empty() {
                None
            } else {
                Some(Icmp6ExtensionStructures(extensions))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::icmp6::Icmp6;
    use crate::parse::{DeParse, Parse};

    fn parse_back_test_helper(header: &Icmp6) {
        let mut buf = [0; super::contract::BYTE_SLICE_SIZE];
        let bytes_written = header
            .deparse(&mut buf)
            .unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        let (parsed, bytes_read) =
            Icmp6::parse(&buf).unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        assert_eq!(header, &parsed);
        assert_eq!(bytes_written, bytes_read);
        assert_eq!(header.size(), bytes_read);
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!()
            .with_type()
            .for_each(parse_back_test_helper);
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(|buffer: &[u8; super::contract::BYTE_SLICE_SIZE]| {
                let (parsed, bytes_read) =
                    Icmp6::parse(buffer).unwrap_or_else(|e| unreachable!("{e:?}", e = e));
                assert_eq!(parsed.size(), bytes_read);
                parse_back_test_helper(&parsed);
            });
    }
}
