// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The optional TLVs of an LLDPDU.
//!
//! Everything between the time to live TLV and the end of LLDPDU marker is
//! optional, may appear in any order, and may be repeated.  [`OptionalTlv`]
//! decodes the ones [IEEE Std 802.1AB] defines and keeps the octets of the ones
//! it does not.
//!
//! [IEEE Std 802.1AB]: https://standards.ieee.org/ieee/802.1AB/6047/

use core::num::NonZero;

use crate::lldp::capabilities::{SystemCapabilities, SystemCapabilitiesError};
use crate::lldp::management::{ManagementAddress, ManagementAddressError};
use crate::lldp::octets::{Octets, OctetsError};
use crate::lldp::org::{OrgTlvError, OrganizationallySpecific};
use crate::lldp::tlv::{
    RawTlv, TlvHeader, TlvType, UnexpectedTlvType, lift, never, split_tlv, write_tlv,
};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};

/// A human readable field of an LLDPDU.
///
/// Unlike a chassis or port identifier, these may be empty: a station with no
/// configured system name says so by sending a zero length TLV rather than by
/// omitting it.
pub type Text = Octets<0, 255>;

/// A TLV from the optional section of an `Lldpdu`.
///
/// # Unrecognized TLVs
///
/// A TLV type this library does not model is kept verbatim in
/// [`OptionalTlv::Unrecognized`], so it survives a parse and deparse cycle
/// octet for octet.  A TLV type it *does* model is always decoded, never kept
/// verbatim, which is what makes the mapping between octets and values
/// one-to-one in both directions.
///
/// # Malformed TLVs
///
/// A TLV of a recognized type whose value does not match that type's layout is
/// a parse error, and fails the whole LLDPDU.  The alternative, skipping the
/// bad TLV and carrying on, would mean an LLDPDU no longer deparses to the
/// octets it was parsed from, which costs more than it buys for a library whose
/// job is to read and write frames faithfully.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum OptionalTlv {
    /// A description of the sending port (type 4).
    PortDescription(Text),
    /// The administratively assigned name of the sending system (type 5).
    SystemName(Text),
    /// A description of the sending system (type 6).
    SystemDescription(Text),
    /// What the sending system can do, and what it has enabled (type 7).
    SystemCapabilities(SystemCapabilities),
    /// An address at which the sending system may be managed (type 8).
    ManagementAddress(ManagementAddress),
    /// A vendor defined TLV (type 127).
    OrganizationallySpecific(OrganizationallySpecific),
    /// A TLV of a type this library does not model.
    Unrecognized(UnrecognizedTlv),
}

impl OptionalTlv {
    /// The type of this TLV.
    #[must_use]
    pub const fn typ(&self) -> TlvType {
        match self {
            OptionalTlv::PortDescription(_) => TlvType::PORT_DESCRIPTION,
            OptionalTlv::SystemName(_) => TlvType::SYSTEM_NAME,
            OptionalTlv::SystemDescription(_) => TlvType::SYSTEM_DESCRIPTION,
            OptionalTlv::SystemCapabilities(_) => TlvType::SYSTEM_CAPABILITIES,
            OptionalTlv::ManagementAddress(_) => TlvType::MANAGEMENT_ADDRESS,
            OptionalTlv::OrganizationallySpecific(_) => TlvType::ORGANIZATIONALLY_SPECIFIC,
            OptionalTlv::Unrecognized(tlv) => tlv.0.typ(),
        }
    }
}

/// A TLV of a type this library does not model.
///
/// The type is guaranteed to be neither structural nor modelled.  Without that
/// guarantee a system name, say, could be represented either as
/// [`OptionalTlv::SystemName`] or as an `Unrecognized` TLV holding the same
/// octets, and a parse would have to pick one arbitrarily.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "RawTlv", into = "RawTlv")]
pub struct UnrecognizedTlv(RawTlv);

impl UnrecognizedTlv {
    /// Wrap a TLV whose type this library does not model.
    ///
    /// # Errors
    ///
    /// Returns [`RecognizedTlvType`] if `tlv` is of a type which has a
    /// dedicated [`OptionalTlv`] variant, or which an
    /// `Lldpdu` models structurally.
    pub fn new(tlv: RawTlv) -> Result<UnrecognizedTlv, RecognizedTlvType> {
        if tlv.typ().is_structural() || tlv.typ().is_modelled() {
            return Err(RecognizedTlvType(tlv.typ()));
        }
        Ok(UnrecognizedTlv(tlv))
    }

    /// The TLV this wraps.
    #[must_use]
    pub const fn tlv(&self) -> &RawTlv {
        &self.0
    }
}

/// Deserialization goes through [`UnrecognizedTlv::new`], so a TLV type which
/// has a structured representation cannot be smuggled in as a verbatim one.
impl TryFrom<RawTlv> for UnrecognizedTlv {
    type Error = RecognizedTlvType;

    fn try_from(value: RawTlv) -> Result<UnrecognizedTlv, RecognizedTlvType> {
        UnrecognizedTlv::new(value)
    }
}

impl From<UnrecognizedTlv> for RawTlv {
    fn from(value: UnrecognizedTlv) -> RawTlv {
        value.0
    }
}

/// The error returned when [`UnrecognizedTlv`] is handed a TLV type which does
/// have a structured representation.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("a {0} TLV has a structured representation and may not be kept verbatim")]
pub struct RecognizedTlvType(pub TlvType);

/// Errors which can occur while parsing an [`OptionalTlv`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum OptionalTlvError {
    /// The TLV was not of the type the parser dispatched on.  This cannot
    /// happen through [`OptionalTlv::parse`], which reads the type first.
    #[error(transparent)]
    UnexpectedTlvType(#[from] UnexpectedTlvType),
    /// A text TLV carried more octets than the standard permits.
    #[error("invalid {0} TLV: {1}")]
    Text(TlvType, OctetsError),
    /// A system capabilities TLV was malformed.
    #[error("invalid system capabilities TLV: {0}")]
    SystemCapabilities(SystemCapabilitiesError),
    /// A management address TLV was malformed.
    #[error("invalid management address TLV: {0}")]
    ManagementAddress(ManagementAddressError),
    /// An organizationally specific TLV was malformed.
    #[error("invalid organizationally specific TLV: {0}")]
    OrganizationallySpecific(OrgTlvError),
    /// A TLV which an `Lldpdu` models structurally
    /// appeared in the optional section, where it does not belong.
    #[error("a {0} TLV may not appear in the optional section of an LLDPDU")]
    Structural(TlvType),
}

/// Parse a TLV whose whole value is text.
fn parse_text(
    buf: &[u8],
    typ: TlvType,
) -> Result<(Text, NonZero<u16>), ParseError<OptionalTlvError>> {
    let (value, total) = split_tlv::<OptionalTlvError>(buf, typ)?;
    let text = Text::new(value).map_err(|e| ParseError::Invalid(OptionalTlvError::Text(typ, e)))?;
    Ok((text, total))
}

impl Parse for OptionalTlv {
    type Error = OptionalTlvError;

    fn parse(buf: &[u8]) -> Result<(OptionalTlv, NonZero<u16>), ParseError<OptionalTlvError>> {
        let (header, _) = TlvHeader::parse(buf).map_err(never)?;
        let typ = header.typ();
        match typ {
            TlvType::PORT_DESCRIPTION => {
                parse_text(buf, typ).map(|(t, n)| (OptionalTlv::PortDescription(t), n))
            }
            TlvType::SYSTEM_NAME => {
                parse_text(buf, typ).map(|(t, n)| (OptionalTlv::SystemName(t), n))
            }
            TlvType::SYSTEM_DESCRIPTION => {
                parse_text(buf, typ).map(|(t, n)| (OptionalTlv::SystemDescription(t), n))
            }
            TlvType::SYSTEM_CAPABILITIES => SystemCapabilities::parse(buf)
                .map(|(c, n)| (OptionalTlv::SystemCapabilities(c), n))
                .map_err(lift(OptionalTlvError::SystemCapabilities)),
            TlvType::MANAGEMENT_ADDRESS => ManagementAddress::parse(buf)
                .map(|(a, n)| (OptionalTlv::ManagementAddress(a), n))
                .map_err(lift(OptionalTlvError::ManagementAddress)),
            TlvType::ORGANIZATIONALLY_SPECIFIC => OrganizationallySpecific::parse(buf)
                .map(|(o, n)| (OptionalTlv::OrganizationallySpecific(o), n))
                .map_err(lift(OptionalTlvError::OrganizationallySpecific)),
            structural if structural.is_structural() => Err(ParseError::Invalid(
                OptionalTlvError::Structural(structural),
            )),
            _ => {
                let (raw, total) = RawTlv::parse(buf).map_err(never)?;
                // The dispatch above has already excluded every structural and
                // modelled type, so this cannot be refused.
                let unrecognized = UnrecognizedTlv::new(raw)
                    .unwrap_or_else(|e| unreachable!("type was dispatched as unmodelled: {e:?}"));
                Ok((OptionalTlv::Unrecognized(unrecognized), total))
            }
        }
    }
}

impl DeParse for OptionalTlv {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            OptionalTlv::PortDescription(text)
            | OptionalTlv::SystemName(text)
            | OptionalTlv::SystemDescription(text) => {
                // `Text` caps the field at 255 octets.
                #[allow(clippy::cast_possible_truncation)] // bounded by 255
                TlvHeader::LENGTH.saturating_add(text.len() as u16)
            }
            OptionalTlv::SystemCapabilities(capabilities) => capabilities.size(),
            OptionalTlv::ManagementAddress(address) => address.size(),
            OptionalTlv::OrganizationallySpecific(org) => org.size(),
            OptionalTlv::Unrecognized(tlv) => tlv.0.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            OptionalTlv::PortDescription(text)
            | OptionalTlv::SystemName(text)
            | OptionalTlv::SystemDescription(text) => {
                #[allow(clippy::cast_possible_truncation)] // bounded by 255
                let value_length = text.len() as u16;
                write_tlv(buf, self.typ(), value_length, |slot| {
                    slot.copy_from_slice(text.as_bytes());
                })
            }
            OptionalTlv::SystemCapabilities(capabilities) => capabilities.deparse(buf),
            OptionalTlv::ManagementAddress(address) => address.deparse(buf),
            OptionalTlv::OrganizationallySpecific(org) => org.deparse(buf),
            OptionalTlv::Unrecognized(tlv) => tlv.0.deparse(buf),
        }
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{OptionalTlv, UnrecognizedTlv};
    use crate::lldp::tlv::{RawTlv, TlvType};
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for OptionalTlv {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            match u.produce::<u8>()? % 7 {
                0 => Some(OptionalTlv::PortDescription(u.produce()?)),
                1 => Some(OptionalTlv::SystemName(u.produce()?)),
                2 => Some(OptionalTlv::SystemDescription(u.produce()?)),
                3 => Some(OptionalTlv::SystemCapabilities(u.produce()?)),
                4 => Some(OptionalTlv::ManagementAddress(u.produce()?)),
                5 => Some(OptionalTlv::OrganizationallySpecific(u.produce()?)),
                _ => {
                    let tlv: RawTlv = u.produce()?;
                    let typ = if tlv.typ().is_structural() || tlv.typ().is_modelled() {
                        // Nudge onto a type with no structured form rather than
                        // rejecting, so the driver does not waste budget.
                        TlvType::new_checked(9).ok()?
                    } else {
                        tlv.typ()
                    };
                    let tlv = RawTlv::new(typ, tlv.value().clone());
                    Some(OptionalTlv::Unrecognized(UnrecognizedTlv::new(tlv).ok()?))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{OptionalTlv, OptionalTlvError, Text, UnrecognizedTlv};
    use crate::lldp::tlv::{RawTlv, TlvType, TlvValue};
    use crate::parse::{DeParse, Parse, ParseError};

    fn deparse(tlv: &OptionalTlv) -> Vec<u8> {
        let mut buf = vec![0u8; tlv.size().get() as usize];
        let written = tlv.deparse(&mut buf).unwrap();
        assert_eq!(written, tlv.size());
        buf
    }

    #[test]
    fn round_trips() {
        bolero::check!().with_type().for_each(|tlv: &OptionalTlv| {
            let buf = deparse(tlv);
            let (parsed, consumed) = OptionalTlv::parse(&buf).unwrap();
            assert_eq!(&parsed, tlv);
            assert_eq!(consumed, tlv.size());
            assert_eq!(parsed.typ(), tlv.typ());
        });
    }

    #[test]
    fn parse_of_arbitrary_octets_is_byte_exact() {
        bolero::check!().with_type().for_each(|raw: &Vec<u8>| {
            let Ok((tlv, consumed)) = OptionalTlv::parse(raw) else {
                return;
            };
            assert_eq!(consumed, tlv.size());
            assert_eq!(&deparse(&tlv)[..], &raw[..consumed.get() as usize]);
        });
    }

    #[test]
    fn a_system_name_encodes_as_expected() {
        let tlv = OptionalTlv::SystemName(Text::new(b"leaf-01").unwrap());
        assert_eq!(
            deparse(&tlv),
            vec![0x0a, 0x07, b'l', b'e', b'a', b'f', b'-', b'0', b'1']
        );
    }

    #[test]
    fn an_empty_text_tlv_is_legal() {
        let tlv = OptionalTlv::PortDescription(Text::new(b"").unwrap());
        let buf = deparse(&tlv);
        assert_eq!(buf, vec![0x08, 0x00]);
        let (parsed, _) = OptionalTlv::parse(&buf).unwrap();
        assert_eq!(parsed, tlv);
    }

    #[test]
    fn recognized_types_are_refused_by_the_verbatim_wrapper() {
        for typ in [
            TlvType::END_OF_LLDPDU,
            TlvType::CHASSIS_ID,
            TlvType::PORT_ID,
            TlvType::TIME_TO_LIVE,
            TlvType::PORT_DESCRIPTION,
            TlvType::SYSTEM_NAME,
            TlvType::SYSTEM_DESCRIPTION,
            TlvType::SYSTEM_CAPABILITIES,
            TlvType::MANAGEMENT_ADDRESS,
            TlvType::ORGANIZATIONALLY_SPECIFIC,
        ] {
            let tlv = RawTlv::new(typ, TlvValue::default());
            assert_eq!(UnrecognizedTlv::new(tlv).unwrap_err().0, typ);
        }
        let unmodelled = RawTlv::new(TlvType::new_checked(9).unwrap(), TlvValue::default());
        assert!(UnrecognizedTlv::new(unmodelled).is_ok());
    }

    #[test]
    fn a_structural_tlv_in_the_optional_section_is_rejected() {
        let tlv = RawTlv::new(
            TlvType::CHASSIS_ID,
            TlvValue::new(&[4, 1, 2, 3, 4, 5, 6]).unwrap(),
        );
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match OptionalTlv::parse(&buf) {
            Err(ParseError::Invalid(OptionalTlvError::Structural(found))) => {
                assert_eq!(found, TlvType::CHASSIS_ID);
            }
            other => unreachable!("expected a structural rejection, got {other:?}"),
        }
    }

    /// A recognized type with a malformed value fails rather than degrading
    /// into an unrecognized TLV, which is what keeps the mapping one-to-one.
    #[test]
    fn a_malformed_recognized_tlv_does_not_degrade_to_verbatim() {
        let tlv = RawTlv::new(
            TlvType::SYSTEM_CAPABILITIES,
            TlvValue::new(&[0x00, 0x04, 0x00]).unwrap(),
        );
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match OptionalTlv::parse(&buf) {
            Err(ParseError::Invalid(OptionalTlvError::SystemCapabilities(_))) => {}
            other => unreachable!("expected a capabilities error, got {other:?}"),
        }
    }

    #[test]
    fn an_over_long_text_tlv_is_rejected() {
        let tlv = RawTlv::new(TlvType::SYSTEM_NAME, TlvValue::new(&[b'x'; 256]).unwrap());
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match OptionalTlv::parse(&buf) {
            Err(ParseError::Invalid(OptionalTlvError::Text(typ, _))) => {
                assert_eq!(typ, TlvType::SYSTEM_NAME);
            }
            other => unreachable!("expected a text length error, got {other:?}"),
        }
    }

    #[test]
    fn deparse_into_insufficient_buffer_fails_gracefully() {
        bolero::check!().with_type().for_each(|tlv: &OptionalTlv| {
            let mut buf = vec![0u8; tlv.size().get() as usize - 1];
            assert!(tlv.deparse(&mut buf).is_err());
        });
    }
}
