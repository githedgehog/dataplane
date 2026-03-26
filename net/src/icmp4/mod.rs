// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv4` header type and logic.

mod checksum;
mod truncated;

pub use checksum::*;
pub use truncated::*;

use crate::headers::{AbstractEmbeddedHeaders, EmbeddedHeaders, EmbeddedIpVersion};
use crate::icmp_any::get_payload_for_checksum;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParseWith, Reader,
};
use etherparse::{Icmpv4Header, Icmpv4Type};
use std::num::NonZero;

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// Errors which may occur when using ICMP v4 methods
#[derive(Debug, thiserror::Error)]
pub enum Icmp4Error {
    /// The ICMP type does not allow setting an identifier.
    #[error("Invalid ICMP type")]
    InvalidIcmpType,
}

/// An `ICMPv4` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp4(pub(crate) Icmpv4Header);

impl Icmp4 {
    /// Get the icmp type (reference) field value
    #[must_use]
    pub const fn icmp_type(&self) -> &Icmpv4Type {
        &self.0.icmp_type
    }

    /// Return a mutable reference to the icmp type field value
    #[must_use]
    pub const fn icmp_type_mut(&mut self) -> &mut Icmpv4Type {
        &mut self.0.icmp_type
    }

    /// Returns true if the ICMP type is a query message
    #[must_use]
    pub fn is_query_message(&self) -> bool {
        // List all types to make it sure we catch any new addition to the enum
        match self.icmp_type() {
            Icmpv4Type::EchoRequest(_)
            | Icmpv4Type::EchoReply(_)
            | Icmpv4Type::TimestampReply(_)
            | Icmpv4Type::TimestampRequest(_) => true,
            Icmpv4Type::Unknown { .. }
            | Icmpv4Type::DestinationUnreachable(_)
            | Icmpv4Type::Redirect(_)
            | Icmpv4Type::TimeExceeded(_)
            | Icmpv4Type::ParameterProblem(_) => false,
        }
    }

    /// Returns true if the ICMP type is an error message
    #[must_use]
    pub fn is_error_message(&self) -> bool {
        // List all types to make it sure we catch any new addition to the enum
        match self.icmp_type() {
            Icmpv4Type::DestinationUnreachable(_)
            | Icmpv4Type::Redirect(_)
            | Icmpv4Type::TimeExceeded(_)
            | Icmpv4Type::ParameterProblem(_) => true,
            Icmpv4Type::Unknown { .. }
            | Icmpv4Type::EchoRequest(_)
            | Icmpv4Type::EchoReply(_)
            | Icmpv4Type::TimestampReply(_)
            | Icmpv4Type::TimestampRequest(_) => false,
        }
    }

    /// Returns the identifier field value if the ICMP type allows it.
    #[must_use]
    pub fn identifier(&self) -> Option<u16> {
        match self.icmp_type() {
            Icmpv4Type::EchoRequest(msg) | Icmpv4Type::EchoReply(msg) => Some(msg.id),
            Icmpv4Type::TimestampReply(msg) | Icmpv4Type::TimestampRequest(msg) => Some(msg.id),
            _ => None,
        }
    }

    /// Set the identifier field value
    ///
    /// # Errors
    ///
    /// This method returns [`Icmp4Error::InvalidIcmpType`] if the ICMP type does not allow setting an identifier.
    pub fn try_set_identifier(&mut self, id: u16) -> Result<(), Icmp4Error> {
        match self.icmp_type_mut() {
            Icmpv4Type::EchoRequest(msg) | Icmpv4Type::EchoReply(msg) => {
                msg.id = id;
                Ok(())
            }
            Icmpv4Type::TimestampReply(msg) | Icmpv4Type::TimestampRequest(msg) => {
                msg.id = id;
                Ok(())
            }
            _ => Err(Icmp4Error::InvalidIcmpType),
        }
    }

    /// Create a new `Icmp4` with the given icmp type.
    /// The checksum will be set to 0.
    #[must_use]
    pub const fn with_type(icmp_type: Icmpv4Type) -> Self {
        Icmp4(Icmpv4Header {
            icmp_type,
            checksum: 0,
        })
    }

    #[must_use]
    pub(crate) fn supports_extensions(&self) -> bool {
        // See RFC 4884. Icmpv4Type::Redirect does not get an optional length field.
        matches!(
            self.icmp_type(),
            Icmpv4Type::DestinationUnreachable(_)
                | Icmpv4Type::TimeExceeded(_)
                | Icmpv4Type::ParameterProblem(_)
        )
    }

    fn payload_length(&self, buf: &[u8]) -> usize {
        if !self.supports_extensions() {
            return 0;
        }
        let payload_length = buf[5];
        payload_length as usize * 4
    }

    pub(crate) fn parse_payload(&self, cursor: &mut Reader) -> Option<EmbeddedHeaders> {
        if !self.is_error_message() {
            return None;
        }
        let (mut headers, consumed) = EmbeddedHeaders::parse_with(
            EmbeddedIpVersion::Ipv4,
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

impl Parse for Icmp4 {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        // Truncate the input to the maximum ICMPv4 header length before
        // calling `from_slice`.  Without this, Timestamp / TimestampReply
        // messages (RFC 792 §3.1) fail because `etherparse::Icmpv4Slice`
        // enforces `slice.len() == TimestampMessage::LEN` (20 bytes) for
        // those types — any trailing payload bytes cause a spurious
        // `LenError`.  Capping at `MAX_LEN` is safe for all ICMP types:
        // non-timestamp headers consume only 8 bytes of the 20-byte window,
        // and timestamp headers consume exactly 20.
        let parse_buf = &buf[..buf.len().min(Icmpv4Header::MAX_LEN)];
        let (inner, rest) = Icmpv4Header::from_slice(parse_buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::Length(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < parse_buf.len(),
            "rest.len() >= parse_buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = parse_buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // checked above
        let consumed =
            NonZero::new((parse_buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        Ok((Self(inner), consumed))
    }
}

impl DeParse for Icmp4 {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // header length bounded
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
    use crate::icmp4::{Icmp4, TruncatedIcmp4};
    use crate::ip::NextHeader;
    use crate::ipv4::GenWithNextHeader;
    use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError};
    use crate::tcp::TruncatedTcp;
    use crate::udp::TruncatedUdp;
    use arrayvec::ArrayVec;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use etherparse::icmpv4::{
        DestUnreachableHeader, ParameterProblemHeader, RedirectCode, RedirectHeader,
        TimeExceededCode,
    };
    use etherparse::{Icmpv4Header, Icmpv4Type};
    use std::num::NonZero;

    /// The number of bytes to use in parsing arbitrary test values for [`Icmp4`].
    ///
    /// Now that [`Icmp4::parse`] truncates the input to
    /// [`Icmpv4Header::MAX_LEN`] (fixing the RFC 792 Timestamp exact-length
    /// check in etherparse), we can safely use a generous buffer that reaches
    /// all `ICMPv4` type/code combinations — including Timestamp (type 13/14),
    /// Echo (type 0/8), error messages (type 3/5/11/12), and `Unknown`
    /// variants.
    pub const BYTE_SLICE_SIZE: usize = 128;

    impl TypeGenerator for Icmp4 {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let buffer: [u8; BYTE_SLICE_SIZE] = driver.produce()?;
            let icmp4 = match Icmp4::parse(&buffer) {
                Ok((icmp4, _)) => icmp4,
                Err(ParseError::Length(l)) => unreachable!("{:?}", l),
                Err(ParseError::Invalid(e)) => unreachable!("{:?}", e),
                Err(ParseError::BufferTooLong(_)) => {
                    unreachable!()
                }
            };
            Some(icmp4)
        }
    }

    struct Icmp4DestUnreachableGenerator;
    impl ValueGenerator for Icmp4DestUnreachableGenerator {
        type Output = Icmp4;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::DestinationUnreachable(
                    DestUnreachableHeader::from_values(
                        driver.produce::<u8>()? % 16,
                        driver.produce()?,
                    )
                    .unwrap(),
                ),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4RedirectGenerator;
    impl ValueGenerator for Icmp4RedirectGenerator {
        type Output = Icmp4;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::Redirect(RedirectHeader {
                    code: RedirectCode::from_u8(driver.produce::<u8>()? % 4).unwrap(),
                    gateway_internet_address: driver.produce()?,
                }),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4TimeExceededGenerator;
    impl ValueGenerator for Icmp4TimeExceededGenerator {
        type Output = Icmp4;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::TimeExceeded(
                    TimeExceededCode::from_u8(driver.produce::<u8>()? % 2).unwrap(),
                ),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4ParameterProblemGenerator;
    impl ValueGenerator for Icmp4ParameterProblemGenerator {
        type Output = Icmp4;

        #[allow(clippy::unwrap_used)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::ParameterProblem(
                    ParameterProblemHeader::from_values(
                        driver.produce::<u8>()? % 3,
                        driver.produce()?,
                    )
                    .unwrap(),
                ),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    /// Generator for `ICMPv4` Error message headers.
    pub struct Icmp4ErrorMsgGenerator;
    impl ValueGenerator for Icmp4ErrorMsgGenerator {
        type Output = Icmp4;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            match driver.produce::<u32>()? % 4 {
                0 => Icmp4DestUnreachableGenerator.generate(driver),
                1 => Icmp4RedirectGenerator.generate(driver),
                2 => Icmp4TimeExceededGenerator.generate(driver),
                _ => Icmp4ParameterProblemGenerator.generate(driver),
            }
        }
    }

    /// Generator for `ICMPv4` Error message embedded IP headers.
    pub struct Icmp4EmbeddedHeadersGenerator;
    impl ValueGenerator for Icmp4EmbeddedHeadersGenerator {
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
                8..=9 => Some(EmbeddedTransport::Icmp4(
                    driver.produce::<TruncatedIcmp4>().unwrap(),
                )),
                _ => None,
            };
            let net = match transport {
                Some(EmbeddedTransport::Tcp(_)) => {
                    let net_gen = GenWithNextHeader(NextHeader::TCP);
                    Some(Net::Ipv4(net_gen.generate(driver)?))
                }
                Some(EmbeddedTransport::Udp(_)) => {
                    let net_gen = GenWithNextHeader(NextHeader::UDP);
                    Some(Net::Ipv4(net_gen.generate(driver)?))
                }
                Some(EmbeddedTransport::Icmp4(_)) => {
                    let net_gen = GenWithNextHeader(NextHeader::ICMP);
                    Some(Net::Ipv4(net_gen.generate(driver)?))
                }
                Some(EmbeddedTransport::Icmp6(_)) => {
                    // We never produce ICMPv6 headers to embed inside ICMPv4 Error messages
                    unreachable!()
                }
                None => {
                    if driver.produce::<bool>()? {
                        let net_gen = GenWithNextHeader(NextHeader::TCP);
                        Some(Net::Ipv4(net_gen.generate(driver)?))
                    } else {
                        let net_gen = GenWithNextHeader(NextHeader::UDP);
                        Some(Net::Ipv4(net_gen.generate(driver)?))
                    }
                }
            };
            let headers = EmbeddedHeaders::new(net, transport, ArrayVec::default(), None);
            Some(headers)
        }
    }

    /// See RFC 4884: Extended ICMP to Support Multi-Part Messages
    #[derive(bolero::TypeGenerator)]
    pub struct Icmp4ExtensionStructure([u8; Self::LENGTH]);

    impl Icmp4ExtensionStructure {
        /// The length of an Extension Structure for `ICMPv4`
        pub const LENGTH: usize = 4;
    }

    /// An array of [`Icmp4ExtensionStructure`]
    pub struct Icmp4ExtensionStructures(ArrayVec<Icmp4ExtensionStructure, 8>);

    impl Icmp4ExtensionStructures {
        /// Return the size of the padding area to be filled with zeroes between an ICMP Error
        /// message inner IP packet's payload and `ICMPv4` Extension Structure objects.
        // RFC 4884:
        //
        //     When the ICMP Extension Structure is appended to an ICMP message and that ICMP
        //     message contains an "original datagram" field, the "original datagram" field MUST
        //     contain at least 128 octets.
        //
        //     When the ICMP Extension Structure is appended to an ICMPv4 message and that ICMPv4
        //     message contains an "original datagram" field, the "original datagram" field MUST be
        //     zero padded to the nearest 32-bit boundary.
        #[must_use]
        pub fn padding_size(payload_size: usize) -> usize {
            if payload_size < 128 {
                128 - payload_size
            } else if payload_size.is_multiple_of(Icmp4ExtensionStructure::LENGTH) {
                0
            } else {
                Icmp4ExtensionStructure::LENGTH - payload_size % Icmp4ExtensionStructure::LENGTH
            }
        }
    }

    impl DeParse for Icmp4ExtensionStructures {
        type Error = ();

        // PANICS IF EMPTY!
        // FIXME: Change error handling if using ICMP Extension Structures outside of tests
        fn size(&self) -> NonZero<u16> {
            #[allow(clippy::cast_possible_truncation)] // header length bounded
            NonZero::new((self.0.len() * Icmp4ExtensionStructure::LENGTH) as u16)
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
            let s_len = Icmp4ExtensionStructure::LENGTH;
            for (i, s) in self.0.iter().enumerate() {
                buf[i * s_len..(i + 1) * s_len].copy_from_slice(&s.0);
            }
            Ok(self.size())
        }
    }

    impl TypeGenerator for Icmp4ExtensionStructures {
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
                Some(Icmp4ExtensionStructures(extensions))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::icmp4::Icmp4;
    use crate::parse::{DeParse, Parse};

    fn parse_back_test_helper(header: &Icmp4) {
        let mut buf = [0; super::contract::BYTE_SLICE_SIZE];
        let bytes_written = header
            .deparse(&mut buf)
            .unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        let (parsed, bytes_read) =
            Icmp4::parse(&buf).unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        assert_eq!(header, &parsed);
        assert_eq!(bytes_written, bytes_read);
        assert_eq!(header.size(), bytes_read);
    }

    /// Deparse → parse roundtrip for all generated [`Icmp4`] headers.
    ///
    /// Now that `Icmp4::parse` truncates the input slice to
    /// `Icmpv4Header::MAX_LEN` (RFC 792), this test covers all `ICMPv4`
    /// types including `TimestampRequest` / `TimestampReply` without
    /// triggering etherparse's exact-length check.
    #[test]
    fn parse_back() {
        bolero::check!()
            .with_type()
            .for_each(parse_back_test_helper);
    }

    /// Parse arbitrary bytes → deparse → re-parse, confirming that any
    /// parseable byte pattern survives a roundtrip.
    #[test]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(|buffer: &[u8; super::contract::BYTE_SLICE_SIZE]| {
                let (parsed, bytes_read) =
                    Icmp4::parse(buffer).unwrap_or_else(|e| unreachable!("{e:?}", e = e));
                assert_eq!(parsed.size(), bytes_read);
                parse_back_test_helper(&parsed);
            });
    }
}
