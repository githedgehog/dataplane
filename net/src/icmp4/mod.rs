// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv4` header type and logic.

mod checksum;
mod truncated;

pub use checksum::*;
pub use truncated::*;

use crate::headers::{AbstractEmbeddedHeaders, EmbeddedHeaders, EmbeddedIpVersion};
use crate::icmp_any::get_payload_for_checksum;
use crate::ipv4::UnicastIpv4Addr;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParseWith, Reader,
};
use etherparse::{IcmpEchoHeader, Icmpv4Header, Icmpv4Type, icmpv4};
use std::num::NonZero;
use tracing::debug;

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

// -- ICMPv4 message subtypes ------------------------------------------------
//
// Each type corresponds to one ICMPv4 message variant with native Rust
// fields.  Used by the header builder to enforce valid layer ordering at
// compile time (e.g. `.embedded()` is only available on error subtypes).

/// `ICMPv4` Destination Unreachable (type 3).
#[derive(Clone, Debug, PartialEq, Eq, strum_macros::EnumCount)]
pub enum Icmp4DestUnreachable {
    /// Code 0.
    Network,
    /// Code 1.
    Host,
    /// Code 2.
    Protocol,
    /// Code 3.
    Port,
    /// Code 4.
    FragmentationNeeded {
        /// The MTU of the next-hop link, or `None` if the sender does
        /// not support Path MTU Discovery (RFC 1191 -- indicated by a
        /// zero value on the wire).
        next_hop_mtu: Option<NonZero<u16>>,
    },
    /// Code 5.
    SourceRouteFailed,
    /// Code 6.
    NetworkUnknown,
    /// Code 7.
    HostUnknown,
    /// Code 8.
    Isolated,
    /// Code 9.
    NetworkProhibited,
    /// Code 10.
    HostProhibited,
    /// Code 11.
    TosNetwork,
    /// Code 12.
    TosHost,
    /// Code 13.
    FilterProhibited,
    /// Code 14.
    HostPrecedenceViolation,
    /// Code 15.
    PrecedenceCutoff,
}

impl From<icmpv4::DestUnreachableHeader> for Icmp4DestUnreachable {
    fn from(h: icmpv4::DestUnreachableHeader) -> Self {
        match h {
            icmpv4::DestUnreachableHeader::Network => Self::Network,
            icmpv4::DestUnreachableHeader::Host => Self::Host,
            icmpv4::DestUnreachableHeader::Protocol => Self::Protocol,
            icmpv4::DestUnreachableHeader::Port => Self::Port,
            icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu } => {
                Self::FragmentationNeeded {
                    next_hop_mtu: NonZero::new(next_hop_mtu),
                }
            }
            icmpv4::DestUnreachableHeader::SourceRouteFailed => Self::SourceRouteFailed,
            icmpv4::DestUnreachableHeader::NetworkUnknown => Self::NetworkUnknown,
            icmpv4::DestUnreachableHeader::HostUnknown => Self::HostUnknown,
            icmpv4::DestUnreachableHeader::Isolated => Self::Isolated,
            icmpv4::DestUnreachableHeader::NetworkProhibited => Self::NetworkProhibited,
            icmpv4::DestUnreachableHeader::HostProhibited => Self::HostProhibited,
            icmpv4::DestUnreachableHeader::TosNetwork => Self::TosNetwork,
            icmpv4::DestUnreachableHeader::TosHost => Self::TosHost,
            icmpv4::DestUnreachableHeader::FilterProhibited => Self::FilterProhibited,
            icmpv4::DestUnreachableHeader::HostPrecedenceViolation => Self::HostPrecedenceViolation,
            icmpv4::DestUnreachableHeader::PrecedenceCutoff => Self::PrecedenceCutoff,
        }
    }
}

impl From<Icmp4DestUnreachable> for icmpv4::DestUnreachableHeader {
    fn from(v: Icmp4DestUnreachable) -> Self {
        match v {
            Icmp4DestUnreachable::Network => Self::Network,
            Icmp4DestUnreachable::Host => Self::Host,
            Icmp4DestUnreachable::Protocol => Self::Protocol,
            Icmp4DestUnreachable::Port => Self::Port,
            Icmp4DestUnreachable::FragmentationNeeded { next_hop_mtu } => {
                Self::FragmentationNeeded {
                    next_hop_mtu: next_hop_mtu.map_or(0, NonZero::get),
                }
            }
            Icmp4DestUnreachable::SourceRouteFailed => Self::SourceRouteFailed,
            Icmp4DestUnreachable::NetworkUnknown => Self::NetworkUnknown,
            Icmp4DestUnreachable::HostUnknown => Self::HostUnknown,
            Icmp4DestUnreachable::Isolated => Self::Isolated,
            Icmp4DestUnreachable::NetworkProhibited => Self::NetworkProhibited,
            Icmp4DestUnreachable::HostProhibited => Self::HostProhibited,
            Icmp4DestUnreachable::TosNetwork => Self::TosNetwork,
            Icmp4DestUnreachable::TosHost => Self::TosHost,
            Icmp4DestUnreachable::FilterProhibited => Self::FilterProhibited,
            Icmp4DestUnreachable::HostPrecedenceViolation => Self::HostPrecedenceViolation,
            Icmp4DestUnreachable::PrecedenceCutoff => Self::PrecedenceCutoff,
        }
    }
}

/// `ICMPv4` Redirect code (type 5).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    strum_macros::EnumCount,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
    strum_macros::AsRefStr,
    strum_macros::EnumMessage,
)]
#[repr(u8)]
pub enum Icmp4RedirectCode {
    /// Code 0: Redirect for the Network.
    #[strum(message = "redirect for network")]
    Network = 0,
    /// Code 1: Redirect for the Host.
    #[strum(message = "redirect for host")]
    Host = 1,
    /// Code 2: Redirect for Type-of-Service and Network.
    #[strum(message = "redirect for ToS and network")]
    TosNetwork = 2,
    /// Code 3: Redirect for Type-of-Service and Host.
    #[strum(message = "redirect for ToS and host")]
    TosHost = 3,
}

impl From<icmpv4::RedirectCode> for Icmp4RedirectCode {
    fn from(c: icmpv4::RedirectCode) -> Self {
        match c {
            icmpv4::RedirectCode::RedirectForNetwork => Self::Network,
            icmpv4::RedirectCode::RedirectForHost => Self::Host,
            icmpv4::RedirectCode::RedirectForTypeOfServiceAndNetwork => Self::TosNetwork,
            icmpv4::RedirectCode::RedirectForTypeOfServiceAndHost => Self::TosHost,
        }
    }
}

impl From<Icmp4RedirectCode> for icmpv4::RedirectCode {
    fn from(c: Icmp4RedirectCode) -> Self {
        match c {
            Icmp4RedirectCode::Network => Self::RedirectForNetwork,
            Icmp4RedirectCode::Host => Self::RedirectForHost,
            Icmp4RedirectCode::TosNetwork => Self::RedirectForTypeOfServiceAndNetwork,
            Icmp4RedirectCode::TosHost => Self::RedirectForTypeOfServiceAndHost,
        }
    }
}

/// `ICMPv4` Redirect (type 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp4Redirect {
    code: Icmp4RedirectCode,
    gateway: crate::ipv4::UnicastIpv4Addr,
}

impl Icmp4Redirect {
    /// Create a new redirect.
    #[must_use]
    pub fn new(code: Icmp4RedirectCode, gateway: crate::ipv4::UnicastIpv4Addr) -> Self {
        Self { code, gateway }
    }

    /// The redirect code.
    #[must_use]
    pub fn code(&self) -> Icmp4RedirectCode {
        self.code
    }

    /// The gateway to which traffic should be sent.
    ///
    /// Per RFC 1122 section 3.2.2.2, this MUST be a unicast address of
    /// a directly reachable neighbor.  Packets with a non-unicast
    /// gateway are rejected during parsing and treated as unknown ICMP.
    #[must_use]
    pub fn gateway(&self) -> crate::ipv4::UnicastIpv4Addr {
        self.gateway
    }
}

/// `ICMPv4` Time Exceeded code (type 11).
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    strum_macros::EnumCount,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
    strum_macros::AsRefStr,
    strum_macros::EnumMessage,
)]
#[repr(u8)]
pub enum Icmp4TimeExceeded {
    /// Code 0: TTL exceeded in transit.
    #[strum(message = "ttl exceeded", detailed_message = "TTL exceeded in transit")]
    TtlExceeded = 0,
    /// Code 1: Fragment reassembly time exceeded.
    #[strum(
        message = "reassembly time exceeded",
        detailed_message = "Fragment reassembly time exceeded"
    )]
    FragmentReassembly = 1,
}

impl From<icmpv4::TimeExceededCode> for Icmp4TimeExceeded {
    fn from(c: icmpv4::TimeExceededCode) -> Self {
        match c {
            icmpv4::TimeExceededCode::TtlExceededInTransit => Self::TtlExceeded,
            icmpv4::TimeExceededCode::FragmentReassemblyTimeExceeded => Self::FragmentReassembly,
        }
    }
}

impl From<Icmp4TimeExceeded> for icmpv4::TimeExceededCode {
    fn from(c: Icmp4TimeExceeded) -> Self {
        match c {
            Icmp4TimeExceeded::TtlExceeded => Self::TtlExceededInTransit,
            Icmp4TimeExceeded::FragmentReassembly => Self::FragmentReassemblyTimeExceeded,
        }
    }
}

/// `ICMPv4` Parameter Problem (type 12).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    strum_macros::EnumCount,
    strum_macros::Display,
    strum_macros::IntoStaticStr,
    strum_macros::AsRefStr,
    strum_macros::EnumMessage,
)]
#[repr(u8)]
pub enum Icmp4ParamProblem {
    /// Code 0: Pointer indicates the error.
    #[strum(message = "pointer indicates problem {0}")]
    PointerIndicatesError(u8) = 0,
    /// Code 1: Missing required option.
    #[strum(message = "missing required option")]
    MissingRequiredOption = 1,
    /// Code 2: Bad length.
    #[strum(message = "bad length")]
    BadLength = 2,
}

impl From<icmpv4::ParameterProblemHeader> for Icmp4ParamProblem {
    fn from(h: icmpv4::ParameterProblemHeader) -> Self {
        match h {
            icmpv4::ParameterProblemHeader::PointerIndicatesError(p) => {
                Self::PointerIndicatesError(p)
            }
            icmpv4::ParameterProblemHeader::MissingRequiredOption => Self::MissingRequiredOption,
            icmpv4::ParameterProblemHeader::BadLength => Self::BadLength,
        }
    }
}

impl From<Icmp4ParamProblem> for icmpv4::ParameterProblemHeader {
    fn from(v: Icmp4ParamProblem) -> Self {
        match v {
            Icmp4ParamProblem::PointerIndicatesError(p) => Self::PointerIndicatesError(p),
            Icmp4ParamProblem::MissingRequiredOption => Self::MissingRequiredOption,
            Icmp4ParamProblem::BadLength => Self::BadLength,
        }
    }
}

/// `ICMPv4` Echo Request (type 8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp4EchoRequest {
    /// Identifier.
    pub id: u16,
    /// Sequence number.
    pub seq: u16,
}

/// `ICMPv4` Echo Reply (type 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp4EchoReply {
    /// Identifier.
    pub id: u16,
    /// Sequence number.
    pub seq: u16,
}

/// `ICMPv4` Timestamp (types 13, 14).
///
/// Timestamps are deprecated (RFC 6918) but we model them for
/// round-trip fidelity during parse/deparse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp4Timestamp {
    /// Identifier.
    pub id: u16,
    /// Sequence number.
    pub seq: u16,
    /// Originate timestamp (milliseconds since midnight UTC).
    ///
    /// Stored as a raw `u32` rather than `Duration` to preserve
    /// lossless round-tripping through parse/deparse.
    pub originate: u32,
    /// Receive timestamp (milliseconds since midnight UTC).
    ///
    /// Raw `u32` for the same round-trip reason as [`originate`](Self::originate).
    pub receive: u32,
    /// Transmit timestamp (milliseconds since midnight UTC).
    ///
    /// Raw `u32` for the same round-trip reason as [`originate`](Self::originate).
    pub transmit: u32,
}

/// The type of an `ICMPv4` message.
///
/// This enum mirrors the protocol-level `ICMPv4` type/code space using
/// native Rust types.  No etherparse types appear in the public API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Icmp4Type {
    /// Destination Unreachable (type 3).
    DestUnreachable(Icmp4DestUnreachable),
    /// Redirect (type 5).
    Redirect(Icmp4Redirect),
    /// Time Exceeded (type 11).
    TimeExceeded(Icmp4TimeExceeded),
    /// Parameter Problem (type 12).
    ParamProblem(Icmp4ParamProblem),
    /// Echo Request (type 8).
    EchoRequest(Icmp4EchoRequest),
    /// Echo Reply (type 0).
    EchoReply(Icmp4EchoReply),
    /// Timestamp Request (type 13).
    TimestampRequest(Icmp4Timestamp),
    /// Timestamp Reply (type 14).
    TimestampReply(Icmp4Timestamp),
    /// Unrecognized type/code.
    Unknown {
        /// Raw type byte.
        type_u8: u8,
        /// Raw code byte.
        code_u8: u8,
        /// Bytes 5-8 of the ICMP header.
        bytes5to8: [u8; 4],
    },
}

impl From<&Icmpv4Type> for Icmp4Type {
    fn from(et: &Icmpv4Type) -> Self {
        match et {
            Icmpv4Type::DestinationUnreachable(h) => {
                Self::DestUnreachable(Icmp4DestUnreachable::from(h.clone()))
            }
            Icmpv4Type::Redirect(h) => {
                let addr = std::net::Ipv4Addr::from(h.gateway_internet_address);
                if let Ok(gateway) = UnicastIpv4Addr::new(addr) {
                    Self::Redirect(Icmp4Redirect::new(Icmp4RedirectCode::from(h.code), gateway))
                } else {
                    debug!(
                        gateway = %addr,
                        "ICMP redirect with non-unicast gateway, treating as unknown"
                    );
                    Self::Unknown {
                        type_u8: 5,
                        code_u8: h.code.code_u8(),
                        bytes5to8: h.gateway_internet_address,
                    }
                }
            }
            Icmpv4Type::TimeExceeded(c) => Self::TimeExceeded(Icmp4TimeExceeded::from(*c)),
            Icmpv4Type::ParameterProblem(h) => {
                Self::ParamProblem(Icmp4ParamProblem::from(h.clone()))
            }
            Icmpv4Type::EchoRequest(h) => Self::EchoRequest(Icmp4EchoRequest {
                id: h.id,
                seq: h.seq,
            }),
            Icmpv4Type::EchoReply(h) => Self::EchoReply(Icmp4EchoReply {
                id: h.id,
                seq: h.seq,
            }),
            Icmpv4Type::TimestampRequest(h) => Self::TimestampRequest(Icmp4Timestamp {
                id: h.id,
                seq: h.seq,
                originate: h.originate_timestamp,
                receive: h.receive_timestamp,
                transmit: h.transmit_timestamp,
            }),
            Icmpv4Type::TimestampReply(h) => Self::TimestampReply(Icmp4Timestamp {
                id: h.id,
                seq: h.seq,
                originate: h.originate_timestamp,
                receive: h.receive_timestamp,
                transmit: h.transmit_timestamp,
            }),
            Icmpv4Type::Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => Self::Unknown {
                type_u8: *type_u8,
                code_u8: *code_u8,
                bytes5to8: *bytes5to8,
            },
        }
    }
}

impl From<Icmp4Type> for Icmpv4Type {
    fn from(native: Icmp4Type) -> Self {
        match native {
            Icmp4Type::DestUnreachable(v) => {
                Icmpv4Type::DestinationUnreachable(icmpv4::DestUnreachableHeader::from(v))
            }
            Icmp4Type::Redirect(v) => Icmpv4Type::Redirect(icmpv4::RedirectHeader {
                code: icmpv4::RedirectCode::from(v.code()),
                gateway_internet_address: v.gateway().inner().octets(),
            }),
            Icmp4Type::TimeExceeded(v) => {
                Icmpv4Type::TimeExceeded(icmpv4::TimeExceededCode::from(v))
            }
            Icmp4Type::ParamProblem(v) => {
                Icmpv4Type::ParameterProblem(icmpv4::ParameterProblemHeader::from(v))
            }
            Icmp4Type::EchoRequest(v) => Icmpv4Type::EchoRequest(IcmpEchoHeader {
                id: v.id,
                seq: v.seq,
            }),
            Icmp4Type::EchoReply(v) => Icmpv4Type::EchoReply(IcmpEchoHeader {
                id: v.id,
                seq: v.seq,
            }),
            Icmp4Type::TimestampRequest(v) => {
                Icmpv4Type::TimestampRequest(icmpv4::TimestampMessage {
                    id: v.id,
                    seq: v.seq,
                    originate_timestamp: v.originate,
                    receive_timestamp: v.receive,
                    transmit_timestamp: v.transmit,
                })
            }
            Icmp4Type::TimestampReply(v) => Icmpv4Type::TimestampReply(icmpv4::TimestampMessage {
                id: v.id,
                seq: v.seq,
                originate_timestamp: v.originate,
                receive_timestamp: v.receive,
                transmit_timestamp: v.transmit,
            }),
            Icmp4Type::Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => Icmpv4Type::Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            },
        }
    }
}

impl Icmp4 {
    /// Get the ICMP message type.
    #[must_use]
    pub fn icmp_type(&self) -> Icmp4Type {
        Icmp4Type::from(&self.0.icmp_type)
    }

    /// Return a mutable reference to the raw etherparse type field.
    ///
    /// This is `pub(crate)` to keep etherparse out of the public API.
    /// External callers should use [`set_type`](Self::set_type) instead.
    #[must_use]
    pub(crate) const fn icmp_type_mut(&mut self) -> &mut Icmpv4Type {
        &mut self.0.icmp_type
    }

    /// Set the ICMP message type.
    pub fn set_type(&mut self, icmp_type: Icmp4Type) {
        self.0.icmp_type = icmp_type.into();
    }

    /// Returns true if the ICMP type is a query message.
    #[must_use]
    pub fn is_query_message(&self) -> bool {
        matches!(
            self.icmp_type(),
            Icmp4Type::EchoRequest(_)
                | Icmp4Type::EchoReply(_)
                | Icmp4Type::TimestampRequest(_)
                | Icmp4Type::TimestampReply(_)
        )
    }

    /// Returns true if the ICMP type is an error message.
    #[must_use]
    pub fn is_error_message(&self) -> bool {
        matches!(
            self.icmp_type(),
            Icmp4Type::DestUnreachable(_)
                | Icmp4Type::Redirect(_)
                | Icmp4Type::TimeExceeded(_)
                | Icmp4Type::ParamProblem(_)
        )
    }

    /// Returns the identifier field value if the ICMP type allows it.
    #[must_use]
    pub fn identifier(&self) -> Option<u16> {
        match self.icmp_type() {
            Icmp4Type::EchoRequest(v) => Some(v.id),
            Icmp4Type::EchoReply(v) => Some(v.id),
            #[allow(clippy::match_same_arms)]
            Icmp4Type::TimestampRequest(v) => Some(v.id),
            Icmp4Type::TimestampReply(v) => Some(v.id),
            _ => None,
        }
    }

    /// Set the identifier field value.
    ///
    /// # Errors
    ///
    /// Returns [`Icmp4Error::InvalidIcmpType`] if the ICMP type does not
    /// support an identifier field.
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

    /// Create a new `Icmp4` with the given ICMP type.
    ///
    /// The checksum will be set to zero.
    #[must_use]
    pub fn with_type(icmp_type: Icmp4Type) -> Self {
        Icmp4(Icmpv4Header {
            icmp_type: icmp_type.into(),
            checksum: 0,
        })
    }

    #[must_use]
    pub(crate) fn supports_extensions(&self) -> bool {
        // See RFC 4884. Redirect does not get an optional length field.
        matches!(
            self.icmp_type(),
            Icmp4Type::DestUnreachable(_) | Icmp4Type::TimeExceeded(_) | Icmp4Type::ParamProblem(_)
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
        let (inner, rest) = Icmpv4Header::from_slice(buf).map_err(|e| {
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
        #[allow(clippy::cast_possible_truncation)] // checked above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
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
    use crate::icmp4::{
        Icmp4, Icmp4DestUnreachable, Icmp4ParamProblem, Icmp4RedirectCode, Icmp4TimeExceeded,
        TruncatedIcmp4,
    };
    use crate::ip::NextHeader;
    use crate::ipv4::GenWithNextHeader;
    use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError};
    use crate::tcp::TruncatedTcp;
    use crate::udp::TruncatedUdp;
    use arrayvec::ArrayVec;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use etherparse::icmpv4::{
        DestUnreachableHeader, ParameterProblemHeader, RedirectCode, RedirectHeader,
        TimeExceededCode, TimestampMessage,
    };
    use etherparse::{IcmpEchoHeader, Icmpv4Header, Icmpv4Type};
    use std::num::NonZero;
    use strum::EnumCount;

    // ICMP code enums must fit in u8 for generator modulus arithmetic.
    static_assertions::const_assert!(Icmp4DestUnreachable::COUNT <= u8::MAX as usize);
    static_assertions::const_assert!(Icmp4RedirectCode::COUNT <= u8::MAX as usize);
    static_assertions::const_assert!(Icmp4TimeExceeded::COUNT <= u8::MAX as usize);
    static_assertions::const_assert!(Icmp4ParamProblem::COUNT <= u8::MAX as usize);

    impl TypeGenerator for Icmp4 {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? % 10 {
                0 => Icmp4DestUnreachableGenerator.generate(driver),
                1 => Icmp4RedirectGenerator.generate(driver),
                2 => Icmp4TimeExceededGenerator.generate(driver),
                3 => Icmp4ParameterProblemGenerator.generate(driver),
                4 => Icmp4EchoRequestGenerator.generate(driver),
                5 => Icmp4EchoReplyGenerator.generate(driver),
                6 => Icmp4TimestampRequestGenerator.generate(driver),
                7 => Icmp4TimestampReplyGenerator.generate(driver),
                8 => Icmp4InvalidCodeGenerator.generate(driver),
                // NOTE: if you add a variant, update the modulo above!
                _ => Icmp4UnknownGenerator.generate(driver),
            }
        }
    }

    struct Icmp4DestUnreachableGenerator;
    impl ValueGenerator for Icmp4DestUnreachableGenerator {
        type Output = Icmp4;

        #[allow(clippy::cast_possible_truncation)] // code enums have < 256 variants
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::DestinationUnreachable(
                    DestUnreachableHeader::from_values(
                        driver.produce::<u8>()? % Icmp4DestUnreachable::COUNT as u8,
                        driver.produce()?,
                    )
                    .unwrap_or_else(|| unreachable!()),
                ),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4RedirectGenerator;
    impl ValueGenerator for Icmp4RedirectGenerator {
        type Output = Icmp4;

        #[allow(clippy::cast_possible_truncation)] // code enums have < 256 variants
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let gateway: crate::ipv4::UnicastIpv4Addr = driver.produce()?;
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::Redirect(RedirectHeader {
                    code: RedirectCode::from_u8(
                        driver.produce::<u8>()? % Icmp4RedirectCode::COUNT as u8,
                    )
                    .unwrap_or_else(|| unreachable!()),
                    gateway_internet_address: gateway.inner().octets(),
                }),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4TimeExceededGenerator;
    impl ValueGenerator for Icmp4TimeExceededGenerator {
        type Output = Icmp4;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            // assert that truncation is impossible by construction
            static_assertions::const_assert!(Icmp4TimeExceeded::COUNT <= u8::MAX as _);
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::TimeExceeded(
                    #[allow(clippy::cast_possible_truncation)] // impossible
                    TimeExceededCode::from_u8(
                        driver.produce::<u8>()? % Icmp4TimeExceeded::COUNT as u8,
                    )
                    .unwrap_or_else(|| unreachable!()),
                ),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4ParameterProblemGenerator;
    impl ValueGenerator for Icmp4ParameterProblemGenerator {
        type Output = Icmp4;

        #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::ParameterProblem(
                    ParameterProblemHeader::from_values(
                        driver.produce::<u8>()? % Icmp4ParamProblem::COUNT as u8,
                        driver.produce()?,
                    )
                    .unwrap(),
                ),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4EchoRequestGenerator;
    impl ValueGenerator for Icmp4EchoRequestGenerator {
        type Output = Icmp4;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::EchoRequest(IcmpEchoHeader {
                    id: driver.produce()?,
                    seq: driver.produce()?,
                }),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4EchoReplyGenerator;
    impl ValueGenerator for Icmp4EchoReplyGenerator {
        type Output = Icmp4;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::EchoReply(IcmpEchoHeader {
                    id: driver.produce()?,
                    seq: driver.produce()?,
                }),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4TimestampRequestGenerator;
    impl ValueGenerator for Icmp4TimestampRequestGenerator {
        type Output = Icmp4;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::TimestampRequest(TimestampMessage {
                    id: driver.produce()?,
                    seq: driver.produce()?,
                    originate_timestamp: driver.produce()?,
                    receive_timestamp: driver.produce()?,
                    transmit_timestamp: driver.produce()?,
                }),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4TimestampReplyGenerator;
    impl ValueGenerator for Icmp4TimestampReplyGenerator {
        type Output = Icmp4;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::TimestampReply(TimestampMessage {
                    id: driver.produce()?,
                    seq: driver.produce()?,
                    originate_timestamp: driver.produce()?,
                    receive_timestamp: driver.produce()?,
                    transmit_timestamp: driver.produce()?,
                }),
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    /// Generates `ICMPv4` headers with a known type byte but an
    /// out-of-range code, which etherparse maps to `Unknown`.  This
    /// covers the portion of the `Unknown` value space that
    /// [`Icmp4UnknownGenerator`] intentionally avoids.
    struct Icmp4InvalidCodeGenerator;
    impl ValueGenerator for Icmp4InvalidCodeGenerator {
        type Output = Icmp4;

        #[allow(clippy::cast_possible_truncation)] // code enums have < 256 variants
        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            use etherparse::icmpv4 as c;
            // (type_u8, first invalid code value)
            let (type_u8, min_invalid) = match driver.produce::<u8>()? % 8 {
                0 => (c::TYPE_ECHO_REPLY, 1u8),
                1 => (c::TYPE_DEST_UNREACH, Icmp4DestUnreachable::COUNT as u8),
                2 => (c::TYPE_REDIRECT, Icmp4RedirectCode::COUNT as u8),
                3 => (c::TYPE_ECHO_REQUEST, 1),
                4 => (c::TYPE_TIME_EXCEEDED, Icmp4TimeExceeded::COUNT as u8),
                5 => (c::TYPE_PARAMETER_PROBLEM, Icmp4ParamProblem::COUNT as u8),
                6 => (c::TYPE_TIMESTAMP, 1),
                _ => (c::TYPE_TIMESTAMP_REPLY, 1),
            };
            let range = u8::MAX - min_invalid + 1;
            let code_u8 = min_invalid + driver.produce::<u8>()? % range;
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::Unknown {
                    type_u8,
                    code_u8,
                    bytes5to8: driver.produce()?,
                },
                checksum: driver.produce()?,
            };
            Some(Icmp4(icmp_header))
        }
    }

    struct Icmp4UnknownGenerator;
    impl Icmp4UnknownGenerator {
        /// Map a raw byte to a type value that etherparse will not
        /// recognize as a known `ICMPv4` type, ensuring round-trip
        /// fidelity through deparse/parse.
        fn unknown_type(raw: u8) -> u8 {
            use etherparse::icmpv4 as c;
            // Known ICMPv4 type bytes.  Remap collisions to nearby
            // unused values.
            match raw {
                c::TYPE_ECHO_REPLY => 1,
                c::TYPE_DEST_UNREACH => 2,
                c::TYPE_REDIRECT => 4,
                c::TYPE_ECHO_REQUEST => 6,
                c::TYPE_TIME_EXCEEDED => 7,
                c::TYPE_PARAMETER_PROBLEM => 9,
                c::TYPE_TIMESTAMP => 10,
                c::TYPE_TIMESTAMP_REPLY => 15,
                v => v,
            }
        }
    }
    impl ValueGenerator for Icmp4UnknownGenerator {
        type Output = Icmp4;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let icmp_header = Icmpv4Header {
                icmp_type: Icmpv4Type::Unknown {
                    type_u8: Self::unknown_type(driver.produce()?),
                    code_u8: driver.produce()?,
                    bytes5to8: driver.produce()?,
                },
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
    use crate::icmp4::{Icmp4, Icmp4Type};
    use crate::parse::{DeParse, IntoNonZeroUSize, Parse};
    use etherparse::Icmpv4Header;

    /// A redirect with a multicast gateway should be treated as unknown
    /// ICMP, since RFC 1122 section 3.2.2.2 requires unicast.
    #[test]
    fn redirect_with_multicast_gateway_is_unknown() {
        use etherparse::{Icmpv4Header, Icmpv4Type, icmpv4};

        let multicast_gateway: [u8; 4] = [224, 0, 0, 1];
        let header = Icmpv4Header {
            icmp_type: Icmpv4Type::Redirect(icmpv4::RedirectHeader {
                code: icmpv4::RedirectCode::RedirectForNetwork,
                gateway_internet_address: multicast_gateway,
            }),
            checksum: 0,
        };
        let icmp = Icmp4(header);
        assert!(
            matches!(icmp.icmp_type(), Icmp4Type::Unknown { type_u8: 5, .. }),
            "multicast gateway should cause redirect to be treated as unknown"
        );
    }

    fn parse_back_test_helper(input: &Icmp4) {
        // etherparse requires timestamp slices to be exactly 20 bytes,
        // so size the buffer to match the header.
        let size = input.size().into_non_zero_usize().get();
        let mut buffer = vec![0u8; size];
        let bytes_written = input
            .deparse(&mut buffer)
            .unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        let (parsed, bytes_read) =
            Icmp4::parse(&buffer).unwrap_or_else(|e| unreachable!("{e:?}", e = e));
        assert_eq!(input, &parsed);
        assert_eq!(bytes_written, bytes_read);
        assert_eq!(input.size(), bytes_read);
    }

    #[test]
    fn parse_back() {
        bolero::check!()
            .with_type()
            .for_each(parse_back_test_helper);
    }

    /// Parse arbitrary bytes as `ICMPv4` and verify round-trip.
    ///
    /// Uses a 20-byte buffer because etherparse requires timestamp
    /// messages to be exactly 20 bytes (`Icmpv4Header::MAX_LEN`).
    #[test]
    fn parse_arbitrary_bytes() {
        bolero::check!()
            .with_type()
            .for_each(|buffer: &[u8; Icmpv4Header::MAX_LEN]| {
                let (parsed, bytes_read) =
                    Icmp4::parse(buffer).unwrap_or_else(|e| unreachable!("{e:?}", e = e));
                assert_eq!(parsed.size(), bytes_read);
                parse_back_test_helper(&parsed);
            });
    }
}
