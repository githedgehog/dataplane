// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `ICMPv6` header type and logic.

mod checksum;
mod truncated;

pub use checksum::*;
pub use truncated::*;

use crate::headers::{AbstractEmbeddedHeaders, EmbeddedHeaders, EmbeddedIpVersion};
use crate::icmp_any::get_payload_for_checksum;
use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParseWith, Reader,
};
use etherparse::{IcmpEchoHeader, Icmpv6Header, Icmpv6Type, icmpv6};
use std::num::NonZero;
use tracing::debug;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// Errors which may occur when using ICMP v6 methods
#[derive(Debug, thiserror::Error)]
pub enum Icmp6Error {
    /// The ICMP type does not allow setting an identifier.
    #[error("Invalid ICMP type")]
    InvalidIcmpType,
}

/// An `Icmp6` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp6(pub(crate) Icmpv6Header);

// -- ICMPv6 message subtypes ------------------------------------------------

/// `ICMPv6` Destination Unreachable (type 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icmp6DestUnreachable {
    /// Code 0: No Route to Destination.
    NoRoute,
    /// Code 1: Administratively Prohibited.
    Prohibited,
    /// Code 2: Beyond Scope of Source Address.
    BeyondScope,
    /// Code 3: Address Unreachable.
    Address,
    /// Code 4: Port Unreachable.
    Port,
    /// Code 5: Source Address Failed Ingress/Egress Policy.
    SourceAddressFailedPolicy,
    /// Code 6: Reject Route to Destination.
    RejectRoute,
}

impl From<icmpv6::DestUnreachableCode> for Icmp6DestUnreachable {
    fn from(c: icmpv6::DestUnreachableCode) -> Self {
        match c {
            icmpv6::DestUnreachableCode::NoRoute => Self::NoRoute,
            icmpv6::DestUnreachableCode::Prohibited => Self::Prohibited,
            icmpv6::DestUnreachableCode::BeyondScope => Self::BeyondScope,
            icmpv6::DestUnreachableCode::Address => Self::Address,
            icmpv6::DestUnreachableCode::Port => Self::Port,
            icmpv6::DestUnreachableCode::SourceAddressFailedPolicy => {
                Self::SourceAddressFailedPolicy
            }
            icmpv6::DestUnreachableCode::RejectRoute => Self::RejectRoute,
        }
    }
}

impl From<Icmp6DestUnreachable> for icmpv6::DestUnreachableCode {
    fn from(v: Icmp6DestUnreachable) -> Self {
        match v {
            Icmp6DestUnreachable::NoRoute => Self::NoRoute,
            Icmp6DestUnreachable::Prohibited => Self::Prohibited,
            Icmp6DestUnreachable::BeyondScope => Self::BeyondScope,
            Icmp6DestUnreachable::Address => Self::Address,
            Icmp6DestUnreachable::Port => Self::Port,
            Icmp6DestUnreachable::SourceAddressFailedPolicy => Self::SourceAddressFailedPolicy,
            Icmp6DestUnreachable::RejectRoute => Self::RejectRoute,
        }
    }
}

/// `ICMPv6` Packet Too Big (type 2).
///
/// The MTU must be at least 1280 per [RFC 8200 section 5].
/// Packets with a smaller MTU on the wire are rejected during parsing
/// and treated as unknown `ICMPv6`.
///
/// [RFC 8200 section 5]: https://datatracker.ietf.org/doc/html/rfc8200#section-5
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp6PacketTooBig {
    mtu: u32,
}

/// Error returned when constructing an [`Icmp6PacketTooBig`] with an
/// MTU below the IPv6 minimum of 1280.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("MTU {} is below the IPv6 minimum of 1280 (RFC 8200 section 5)", .0)]
pub struct Icmp6MtuTooSmall(u32);

impl Icmp6MtuTooSmall {
    /// The rejected MTU value.
    #[must_use]
    pub fn mtu(&self) -> u32 {
        self.0
    }
}

impl Icmp6PacketTooBig {
    /// IPv6 minimum MTU per [RFC 8200 section 5].
    pub const MIN_MTU: u32 = 1280;

    /// Create a new Packet Too Big message.
    ///
    /// # Errors
    ///
    /// Returns [`Icmp6MtuTooSmall`] if `mtu < 1280`.
    pub fn new(mtu: u32) -> Result<Self, Icmp6MtuTooSmall> {
        if mtu < Self::MIN_MTU {
            return Err(Icmp6MtuTooSmall(mtu));
        }
        Ok(Self { mtu })
    }

    /// The MTU of the next-hop link.
    #[must_use]
    pub fn mtu(&self) -> u32 {
        self.mtu
    }
}

/// `ICMPv6` Time Exceeded (type 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icmp6TimeExceeded {
    /// Code 0: Hop Limit Exceeded in Transit.
    HopLimitExceeded,
    /// Code 1: Fragment Reassembly Time Exceeded.
    FragmentReassembly,
}

impl From<icmpv6::TimeExceededCode> for Icmp6TimeExceeded {
    fn from(c: icmpv6::TimeExceededCode) -> Self {
        match c {
            icmpv6::TimeExceededCode::HopLimitExceeded => Self::HopLimitExceeded,
            icmpv6::TimeExceededCode::FragmentReassemblyTimeExceeded => Self::FragmentReassembly,
        }
    }
}

impl From<Icmp6TimeExceeded> for icmpv6::TimeExceededCode {
    fn from(v: Icmp6TimeExceeded) -> Self {
        match v {
            Icmp6TimeExceeded::HopLimitExceeded => Self::HopLimitExceeded,
            Icmp6TimeExceeded::FragmentReassembly => Self::FragmentReassemblyTimeExceeded,
        }
    }
}

/// `ICMPv6` Parameter Problem code (type 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Icmp6ParamProblemCode {
    /// Code 0: Erroneous Header Field Encountered.
    ErroneousHeaderField = 0,
    /// Code 1: Unrecognized Next Header Type Encountered.
    UnrecognizedNextHeader = 1,
    /// Code 2: Unrecognized IPv6 Option Encountered.
    UnrecognizedIpv6Option = 2,
    /// Code 3: IPv6 First Fragment has incomplete IPv6 Header Chain.
    Ipv6FirstFragmentIncompleteHeaderChain = 3,
    /// Code 4: SR Upper-layer Header Error.
    SrUpperLayerHeaderError = 4,
    /// Code 5: Unrecognized Next Header type encountered by intermediate node.
    UnrecognizedNextHeaderByIntermediateNode = 5,
    /// Code 6: Extension header too big.
    ExtensionHeaderTooBig = 6,
    /// Code 7: Extension header chain too long.
    ExtensionHeaderChainTooLong = 7,
    /// Code 8: Too many extension headers.
    TooManyExtensionHeaders = 8,
    /// Code 9: Too many options in extension header.
    TooManyOptionsInExtensionHeader = 9,
    /// Code 10: Option too big.
    OptionTooBig = 10,
}

impl From<icmpv6::ParameterProblemCode> for Icmp6ParamProblemCode {
    fn from(c: icmpv6::ParameterProblemCode) -> Self {
        match c {
            icmpv6::ParameterProblemCode::ErroneousHeaderField => Self::ErroneousHeaderField,
            icmpv6::ParameterProblemCode::UnrecognizedNextHeader => Self::UnrecognizedNextHeader,
            icmpv6::ParameterProblemCode::UnrecognizedIpv6Option => Self::UnrecognizedIpv6Option,
            icmpv6::ParameterProblemCode::Ipv6FirstFragmentIncompleteHeaderChain => {
                Self::Ipv6FirstFragmentIncompleteHeaderChain
            }
            icmpv6::ParameterProblemCode::SrUpperLayerHeaderError => Self::SrUpperLayerHeaderError,
            icmpv6::ParameterProblemCode::UnrecognizedNextHeaderByIntermediateNode => {
                Self::UnrecognizedNextHeaderByIntermediateNode
            }
            icmpv6::ParameterProblemCode::ExtensionHeaderTooBig => Self::ExtensionHeaderTooBig,
            icmpv6::ParameterProblemCode::ExtensionHeaderChainTooLong => {
                Self::ExtensionHeaderChainTooLong
            }
            icmpv6::ParameterProblemCode::TooManyExtensionHeaders => Self::TooManyExtensionHeaders,
            icmpv6::ParameterProblemCode::TooManyOptionsInExtensionHeader => {
                Self::TooManyOptionsInExtensionHeader
            }
            icmpv6::ParameterProblemCode::OptionTooBig => Self::OptionTooBig,
        }
    }
}

impl From<Icmp6ParamProblemCode> for icmpv6::ParameterProblemCode {
    fn from(v: Icmp6ParamProblemCode) -> Self {
        match v {
            Icmp6ParamProblemCode::ErroneousHeaderField => Self::ErroneousHeaderField,
            Icmp6ParamProblemCode::UnrecognizedNextHeader => Self::UnrecognizedNextHeader,
            Icmp6ParamProblemCode::UnrecognizedIpv6Option => Self::UnrecognizedIpv6Option,
            Icmp6ParamProblemCode::Ipv6FirstFragmentIncompleteHeaderChain => {
                Self::Ipv6FirstFragmentIncompleteHeaderChain
            }
            Icmp6ParamProblemCode::SrUpperLayerHeaderError => Self::SrUpperLayerHeaderError,
            Icmp6ParamProblemCode::UnrecognizedNextHeaderByIntermediateNode => {
                Self::UnrecognizedNextHeaderByIntermediateNode
            }
            Icmp6ParamProblemCode::ExtensionHeaderTooBig => Self::ExtensionHeaderTooBig,
            Icmp6ParamProblemCode::ExtensionHeaderChainTooLong => Self::ExtensionHeaderChainTooLong,
            Icmp6ParamProblemCode::TooManyExtensionHeaders => Self::TooManyExtensionHeaders,
            Icmp6ParamProblemCode::TooManyOptionsInExtensionHeader => {
                Self::TooManyOptionsInExtensionHeader
            }
            Icmp6ParamProblemCode::OptionTooBig => Self::OptionTooBig,
        }
    }
}

/// `ICMPv6` Parameter Problem (type 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp6ParamProblem {
    /// The problem code.
    pub code: Icmp6ParamProblemCode,
    /// Byte offset in the original packet where the problem was found.
    pub pointer: u32,
}

/// `ICMPv6` Echo Request (type 128).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp6EchoRequest {
    /// Identifier.
    pub id: u16,
    /// Sequence number.
    pub seq: u16,
}

/// `ICMPv6` Echo Reply (type 129).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp6EchoReply {
    /// Identifier.
    pub id: u16,
    /// Sequence number.
    pub seq: u16,
}

/// `ICMPv6` Router Advertisement (type 134).
///
/// Preserved for round-trip fidelity; not modeled as a builder subtype.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp6RouterAdvertisement {
    /// Default hop limit for outgoing packets. `None` means unspecified.
    pub cur_hop_limit: Option<NonZero<u8>>,
    /// "Managed address configuration" flag (`DHCPv6`).
    pub managed_address_config: bool,
    /// "Other configuration" flag (`DHCPv6`).
    pub other_config: bool,
    /// Lifetime of this router as a default router, in seconds.
    pub router_lifetime: u16,
}

/// `ICMPv6` Neighbor Advertisement (type 136).
///
/// Preserved for round-trip fidelity; not modeled as a builder subtype.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Icmp6NeighborAdvertisement {
    /// Router flag.
    pub router: bool,
    /// Solicited flag.
    pub solicited: bool,
    /// Override flag.
    pub override_flag: bool,
}

/// The type of an `ICMPv6` message.
///
/// This enum mirrors the protocol-level `ICMPv6` type/code space using
/// native Rust types.  No etherparse types appear in the public API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Icmp6Type {
    /// Destination Unreachable (type 1).
    DestUnreachable(Icmp6DestUnreachable),
    /// Packet Too Big (type 2).
    PacketTooBig(Icmp6PacketTooBig),
    /// Time Exceeded (type 3).
    TimeExceeded(Icmp6TimeExceeded),
    /// Parameter Problem (type 4).
    ParamProblem(Icmp6ParamProblem),
    /// Echo Request (type 128).
    EchoRequest(Icmp6EchoRequest),
    /// Echo Reply (type 129).
    EchoReply(Icmp6EchoReply),
    /// Router Solicitation (type 133).  Unit variant -- no header data.
    RouterSolicitation,
    /// Router Advertisement (type 134).
    RouterAdvertisement(Icmp6RouterAdvertisement),
    /// Neighbor Solicitation (type 135).  Unit variant -- no header data.
    NeighborSolicitation,
    /// Neighbor Advertisement (type 136).
    NeighborAdvertisement(Icmp6NeighborAdvertisement),
    /// Redirect (type 137).  Unit variant -- no header data.
    Redirect,
    /// Unrecognized or unsupported type.
    Unknown {
        /// Raw type byte.
        type_u8: u8,
        /// Raw code byte.
        code_u8: u8,
        /// Bytes 5-8 of the ICMP header.
        bytes5to8: [u8; 4],
    },
}

impl From<Icmpv6Type> for Icmp6Type {
    fn from(et: Icmpv6Type) -> Self {
        match et {
            Icmpv6Type::DestinationUnreachable(c) => {
                Self::DestUnreachable(Icmp6DestUnreachable::from(c))
            }
            Icmpv6Type::PacketTooBig { mtu } => {
                if let Ok(v) = Icmp6PacketTooBig::new(mtu) {
                    Self::PacketTooBig(v)
                } else {
                    debug!(
                        mtu,
                        "ICMPv6 Packet Too Big with MTU below 1280, treating as unknown"
                    );
                    Self::Unknown {
                        type_u8: 2,
                        code_u8: 0,
                        bytes5to8: mtu.to_be_bytes(),
                    }
                }
            }
            Icmpv6Type::TimeExceeded(c) => Self::TimeExceeded(Icmp6TimeExceeded::from(c)),
            Icmpv6Type::ParameterProblem(h) => Self::ParamProblem(Icmp6ParamProblem {
                code: Icmp6ParamProblemCode::from(h.code),
                pointer: h.pointer,
            }),
            Icmpv6Type::EchoRequest(h) => Self::EchoRequest(Icmp6EchoRequest {
                id: h.id,
                seq: h.seq,
            }),
            Icmpv6Type::EchoReply(h) => Self::EchoReply(Icmp6EchoReply {
                id: h.id,
                seq: h.seq,
            }),
            Icmpv6Type::RouterSolicitation => Self::RouterSolicitation,
            Icmpv6Type::RouterAdvertisement(h) => {
                Self::RouterAdvertisement(Icmp6RouterAdvertisement {
                    cur_hop_limit: NonZero::new(h.cur_hop_limit),
                    managed_address_config: h.managed_address_config,
                    other_config: h.other_config,
                    router_lifetime: h.router_lifetime,
                })
            }
            Icmpv6Type::NeighborSolicitation => Self::NeighborSolicitation,
            Icmpv6Type::NeighborAdvertisement(h) => {
                Self::NeighborAdvertisement(Icmp6NeighborAdvertisement {
                    router: h.router,
                    solicited: h.solicited,
                    override_flag: h.r#override,
                })
            }
            Icmpv6Type::Redirect => Self::Redirect,
            Icmpv6Type::Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => Self::Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            },
        }
    }
}

impl From<Icmp6Type> for Icmpv6Type {
    fn from(native: Icmp6Type) -> Self {
        match native {
            Icmp6Type::DestUnreachable(v) => {
                Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::from(v))
            }
            Icmp6Type::PacketTooBig(v) => Icmpv6Type::PacketTooBig { mtu: v.mtu() },
            Icmp6Type::TimeExceeded(v) => {
                Icmpv6Type::TimeExceeded(icmpv6::TimeExceededCode::from(v))
            }
            Icmp6Type::ParamProblem(v) => {
                Icmpv6Type::ParameterProblem(icmpv6::ParameterProblemHeader {
                    code: icmpv6::ParameterProblemCode::from(v.code),
                    pointer: v.pointer,
                })
            }
            Icmp6Type::EchoRequest(v) => Icmpv6Type::EchoRequest(IcmpEchoHeader {
                id: v.id,
                seq: v.seq,
            }),
            Icmp6Type::EchoReply(v) => Icmpv6Type::EchoReply(IcmpEchoHeader {
                id: v.id,
                seq: v.seq,
            }),
            Icmp6Type::RouterSolicitation => Icmpv6Type::RouterSolicitation,
            Icmp6Type::RouterAdvertisement(v) => {
                Icmpv6Type::RouterAdvertisement(etherparse::icmpv6::RouterAdvertisementHeader {
                    cur_hop_limit: v.cur_hop_limit.map_or(0, NonZero::get),
                    managed_address_config: v.managed_address_config,
                    other_config: v.other_config,
                    router_lifetime: v.router_lifetime,
                })
            }
            Icmp6Type::NeighborSolicitation => Icmpv6Type::NeighborSolicitation,
            Icmp6Type::NeighborAdvertisement(v) => {
                Icmpv6Type::NeighborAdvertisement(etherparse::icmpv6::NeighborAdvertisementHeader {
                    router: v.router,
                    solicited: v.solicited,
                    r#override: v.override_flag,
                })
            }
            Icmp6Type::Redirect => Icmpv6Type::Redirect,
            Icmp6Type::Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            } => Icmpv6Type::Unknown {
                type_u8,
                code_u8,
                bytes5to8,
            },
        }
    }
}

impl Icmp6 {
    /// Work around an etherparse 0.19 bug where `RouterSolicitation` (133),
    /// `RouterAdvertisement` (134), and `Redirect` (137) are not recognised by
    /// `Icmpv6Slice::icmp_type()`, so they arrive as `Unknown` after
    /// `from_slice`.  This method corrects them.
    fn fixup_ndp_types(mut header: Icmpv6Header) -> Icmpv6Header {
        if let Icmpv6Type::Unknown {
            type_u8,
            code_u8: 0,
            bytes5to8,
        } = header.icmp_type
        {
            header.icmp_type = match type_u8 {
                // RS and Redirect are unit variants; bytes 5-8 are
                // reserved and must be zero (RFC 4861).  Keep Unknown
                // when the reserved field is non-zero.
                icmpv6::TYPE_ROUTER_SOLICITATION if bytes5to8 == [0; 4] => {
                    Icmpv6Type::RouterSolicitation
                }
                icmpv6::TYPE_REDIRECT_MESSAGE if bytes5to8 == [0; 4] => Icmpv6Type::Redirect,
                // RA carries data in bytes 5-8 (cur_hop_limit, flags, router_lifetime).
                icmpv6::TYPE_ROUTER_ADVERTISEMENT => Icmpv6Type::RouterAdvertisement(
                    icmpv6::RouterAdvertisementHeader::from_bytes(bytes5to8),
                ),
                _ => return header,
            };
        }
        header
    }

    /// Get the ICMP message type.
    #[must_use]
    pub fn icmp_type(&self) -> Icmp6Type {
        Icmp6Type::from(self.0.icmp_type)
    }

    /// Return a mutable reference to the raw etherparse type field.
    ///
    /// This is `pub(crate)` to keep etherparse out of the public API.
    /// External callers should use [`set_type`](Self::set_type) instead.
    #[must_use]
    pub(crate) const fn icmp_type_mut(&mut self) -> &mut Icmpv6Type {
        &mut self.0.icmp_type
    }

    /// Set the ICMP message type.
    pub fn set_type(&mut self, icmp_type: Icmp6Type) {
        self.0.icmp_type = icmp_type.into();
    }

    /// Returns true if the ICMP type is a query message.
    #[must_use]
    pub fn is_query_message(&self) -> bool {
        matches!(
            self.icmp_type(),
            Icmp6Type::EchoRequest(_) | Icmp6Type::EchoReply(_)
        )
    }

    /// Returns true if the ICMP type is an error message.
    #[must_use]
    pub fn is_error_message(&self) -> bool {
        matches!(
            self.icmp_type(),
            Icmp6Type::DestUnreachable(_)
                | Icmp6Type::PacketTooBig(_)
                | Icmp6Type::TimeExceeded(_)
                | Icmp6Type::ParamProblem(_)
        )
    }

    /// Returns the identifier field value if the ICMP type allows it.
    #[must_use]
    pub fn identifier(&self) -> Option<u16> {
        match self.icmp_type() {
            Icmp6Type::EchoRequest(v) => Some(v.id),
            Icmp6Type::EchoReply(v) => Some(v.id),
            _ => None,
        }
    }

    /// Set the identifier field value.
    ///
    /// # Errors
    ///
    /// Returns [`Icmp6Error::InvalidIcmpType`] if the ICMP type does not
    /// support an identifier field.
    pub fn try_set_identifier(&mut self, id: u16) -> Result<(), Icmp6Error> {
        match self.icmp_type_mut() {
            Icmpv6Type::EchoRequest(msg) | Icmpv6Type::EchoReply(msg) => {
                msg.id = id;
                Ok(())
            }
            _ => Err(Icmp6Error::InvalidIcmpType),
        }
    }

    /// Creates a new `Icmp6` with the given type.
    ///
    /// The checksum will be set to zero.
    #[must_use]
    pub fn with_type(icmp_type: Icmp6Type) -> Self {
        Self(Icmpv6Header {
            icmp_type: icmp_type.into(),
            checksum: 0,
        })
    }

    #[must_use]
    pub(crate) fn supports_extensions(&self) -> bool {
        // See RFC 4884.
        matches!(
            self.icmp_type(),
            Icmp6Type::DestUnreachable(_) | Icmp6Type::TimeExceeded(_) | Icmp6Type::ParamProblem(_)
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
        // etherparse 0.19 does not parse RS/RA/Redirect, so they fall
        // through to Unknown.  Remap them here until an upstream fix
        // lands (see https://github.com/JulianSchmid/etherparse).
        let inner = Self::fixup_ndp_types(inner);
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
    use crate::icmp6::{Icmp6, Icmp6Type};
    use crate::parse::{DeParse, Parse};

    /// A Packet Too Big with MTU below 1280 should be treated as unknown
    /// `ICMPv6`, since RFC 8200 section 5 sets 1280 as the IPv6 minimum.
    #[test]
    fn packet_too_big_below_min_mtu_is_unknown() {
        use etherparse::{Icmpv6Header, Icmpv6Type};

        let header = Icmpv6Header {
            icmp_type: Icmpv6Type::PacketTooBig { mtu: 1000 },
            checksum: 0,
        };
        let icmp = Icmp6(header);
        assert!(
            matches!(icmp.icmp_type(), Icmp6Type::Unknown { type_u8: 2, .. }),
            "sub-minimum MTU should cause PacketTooBig to be treated as unknown"
        );
    }

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
    fn parse_back() {
        bolero::check!()
            .with_type()
            .for_each(parse_back_test_helper);
    }

    #[test]
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
