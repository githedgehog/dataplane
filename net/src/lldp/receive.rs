// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Lenient decoding of a received LLDPDU, following the receive rules of
//! [IEEE Std 802.1AB]-2005 §10.3.2 (§9.2.7.7 in the 2016 edition).
//!
//! [`Lldpdu::parse`] is strict and byte-exact: what it accepts deparses back to
//! the octets it came from, which is what lets a parsed frame be re-serialized.
//! A receiver is not allowed to be that strict.  The standard asks it to keep
//! as much of a neighbour's advertisement as it can, so [`Lldpdu::receive`]
//!
//! - discards an optional TLV with an error specific to that TLV, and counts it;
//! - ignores octets past the end of a TLV whose information is fixed in size or
//!   self-delimiting (time to live, system capabilities, management address,
//!   and the modelled 802.1 and 802.3 TLVs);
//! - keeps the TLVs which came before one that runs past the end of the frame;
//! - accepts an LLDPDU with no end of LLDPDU TLV;
//!
//! but still rejects the whole LLDPDU if a mandatory TLV is missing, malformed,
//! or repeated, or if a TLV is too short to hold the fields its type requires.
//!
//! [IEEE Std 802.1AB]: https://standards.ieee.org/ieee/802.1AB/6047/

use crate::lldp::capabilities::{SystemCapabilities, SystemCapabilitiesError};
use crate::lldp::chassis_id::ChassisId;
use crate::lldp::management::ManagementAddressError;
use crate::lldp::optional::{OptionalTlv, OptionalTlvError};
use crate::lldp::org::{Dot1Tlv, Dot3Tlv, OrgTlvError, OrganizationallySpecific, Oui};
use crate::lldp::pdu::{Lldpdu, LldpduError};
use crate::lldp::port_id::PortId;
use crate::lldp::tlv::{TlvHeader, TlvType, lift, never};
use crate::lldp::ttl::TimeToLive;
use crate::parse::{DeParse, Parse, ParseError};

/// An LLDPDU decoded by [`Lldpdu::receive`], along with how much of it had to
/// be thrown away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Received {
    /// What survived of the LLDPDU.
    pub lldpdu: Lldpdu,
    /// How many TLVs were discarded rather than kept.
    pub discarded: u16,
}

impl Lldpdu {
    /// Decode a received LLDPDU, keeping as much of it as the receive rules of
    /// [IEEE Std 802.1AB]-2005 §10.3.2 allow.
    ///
    /// Use [`Lldpdu::parse`] where the octets must round-trip; use this where a
    /// neighbour's advertisement is being heard.  This
    ///
    /// - discards an optional TLV with an error specific to that TLV, and counts it;
    /// - ignores octets past the end of a TLV whose information is fixed in size or
    ///   self-delimiting (time to live, system capabilities, management address,
    ///   and the modelled 802.1 and 802.3 TLVs);
    /// - keeps the TLVs which came before one that runs past the end of the frame;
    /// - accepts an LLDPDU with no end of LLDPDU TLV.
    ///
    /// # Errors
    ///
    /// Returns an error if the LLDPDU must be discarded as a whole: a mandatory
    /// TLV is missing, malformed, or repeated, or a TLV is too short for the
    /// fields its type requires.
    ///
    /// [IEEE Std 802.1AB]: https://standards.ieee.org/ieee/802.1AB/6047/
    pub fn receive(buf: &[u8]) -> Result<Received, ParseError<LldpduError>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }

        let (chassis_id, consumed) = ChassisId::parse(buf).map_err(lift(LldpduError::ChassisId))?;
        let mut offset = consumed.get() as usize;

        let (port_id, consumed) =
            PortId::parse(&buf[offset..]).map_err(lift(LldpduError::PortId))?;
        offset += consumed.get() as usize;

        let (ttl, consumed) = receive_ttl(&buf[offset..])?;
        offset += consumed;

        let mut lldpdu = Lldpdu::new(chassis_id, port_id, ttl);
        let mut discarded = 0u16;
        // A missing end marker is accepted: the LLDPDU ends where the frame
        // does, or where a TLV header can no longer fit.
        while let Ok((header, _)) = TlvHeader::parse(&buf[offset..]) {
            let typ = header.typ();
            if typ == TlvType::END_OF_LLDPDU {
                break;
            }
            if typ.is_structural() {
                return Err(ParseError::Invalid(LldpduError::OptionalTlv(
                    OptionalTlvError::Structural(typ),
                )));
            }
            let total = header.total_length().get() as usize;
            let Some(tlv) = buf.get(offset..offset + total) else {
                // This TLV runs past the end of the frame.  Keep what came
                // before it and stop.
                discarded = discarded.saturating_add(1);
                break;
            };
            offset += total;
            let kept =
                receive_optional(header, tlv)?.is_some_and(|tlv| lldpdu.try_push(tlv).is_ok());
            if !kept {
                discarded = discarded.saturating_add(1);
            }
        }

        Ok(Received { lldpdu, discarded })
    }
}

/// Decode the time to live, using the first two octets of a longer one.
fn receive_ttl(buf: &[u8]) -> Result<(TimeToLive, usize), ParseError<LldpduError>> {
    let (header, _) = TlvHeader::parse(buf).map_err(never)?;
    let total = header.total_length().get() as usize;
    let value_length = TimeToLive::VALUE_LENGTH;
    if header.typ() == TimeToLive::TLV_TYPE
        && header.length() > value_length
        && let Some(tlv) = buf.get(..total)
    {
        let (ttl, _) = TimeToLive::parse(&trimmed(header, tlv, value_length))
            .map_err(lift(LldpduError::TimeToLive))?;
        return Ok((ttl, total));
    }
    let (ttl, consumed) = TimeToLive::parse(buf).map_err(lift(LldpduError::TimeToLive))?;
    Ok((ttl, consumed.get() as usize))
}

/// Decode one optional TLV, `tlv` being exactly its octets.
///
/// Returns `None` if the TLV is to be discarded, and an error if the whole
/// LLDPDU is.
fn receive_optional(
    header: TlvHeader,
    tlv: &[u8],
) -> Result<Option<OptionalTlv>, ParseError<LldpduError>> {
    let error = match OptionalTlv::parse(tlv) {
        Ok((tlv, _)) => return Ok(Some(tlv)),
        Err(ParseError::Invalid(error)) => error,
        // `tlv` holds exactly the octets the header describes, so the TLV
        // parsers have nothing to run out of.
        Err(error) => return Err(lift(LldpduError::OptionalTlv)(error)),
    };
    match intended_length(header, &error) {
        Shape::TooShort => Err(ParseError::Invalid(LldpduError::OptionalTlv(error))),
        Shape::TooLong(length) => Ok(OptionalTlv::parse(&trimmed(header, tlv, length))
            .ok()
            .map(|(tlv, _)| tlv)),
        Shape::Other => Ok(None),
    }
}

/// What a TLV-specific error says about the TLV's length.
enum Shape {
    /// The TLV is too short to hold the fields its type requires.
    TooShort,
    /// The TLV carries octets past a known end, which is this long.
    TooLong(u16),
    /// The error is about the content rather than the length.
    Other,
}

fn intended_length(header: TlvHeader, error: &OptionalTlvError) -> Shape {
    let length = header.length();
    let shorten = |by: usize| {
        u16::try_from(by)
            .ok()
            .and_then(|by| length.checked_sub(by))
            .map_or(Shape::Other, Shape::TooLong)
    };
    match error {
        OptionalTlvError::SystemCapabilities(SystemCapabilitiesError::InvalidValueLength(
            found,
        )) => fixed(SystemCapabilities::VALUE_LENGTH, *found),
        OptionalTlvError::ManagementAddress(ManagementAddressError::Truncated(..))
        | OptionalTlvError::OrganizationallySpecific(OrgTlvError::Truncated(_)) => Shape::TooShort,
        OptionalTlvError::ManagementAddress(ManagementAddressError::TrailingOctets(extra)) => {
            shorten(*extra)
        }
        OptionalTlvError::OrganizationallySpecific(OrgTlvError::InvalidInfoLength {
            oui,
            subtype,
            found,
        }) => {
            let info = match (*oui, *subtype) {
                (Oui::IEEE_802_1, Dot1Tlv::PORT_VLAN_ID)
                | (Oui::IEEE_802_3, Dot3Tlv::MAXIMUM_FRAME_SIZE) => 2,
                (Oui::IEEE_802_3, Dot3Tlv::LINK_AGGREGATION) => 5,
                // A VLAN name too short for its VLAN ID and name length.
                _ => return Shape::TooShort,
            };
            match u16::try_from(*found) {
                Ok(found) => fixed(info, found).offset(OrganizationallySpecific::HEADER_LEN),
                Err(_) => Shape::Other,
            }
        }
        OptionalTlvError::OrganizationallySpecific(OrgTlvError::VlanNameLengthMismatch {
            declared,
            found,
        }) => match found.checked_sub(*declared) {
            Some(extra) => shorten(extra),
            None => Shape::TooShort,
        },
        _ => Shape::Other,
    }
}

/// Compare a fixed-size value's expected length with what was found.
fn fixed(expected: u16, found: u16) -> Shape {
    if found < expected {
        Shape::TooShort
    } else {
        Shape::TooLong(expected)
    }
}

impl Shape {
    /// Account for octets which come before the fixed-size part of the value.
    fn offset(self, by: usize) -> Shape {
        match self {
            #[allow(clippy::cast_possible_truncation)] // a four octet OUI and subtype
            Shape::TooLong(length) => Shape::TooLong(length + by as u16),
            other => other,
        }
    }
}

/// Re-frame a TLV with its value cut down to `length` octets.
fn trimmed(header: TlvHeader, tlv: &[u8], length: u16) -> Vec<u8> {
    let header = TlvHeader::new(header.typ(), length)
        .unwrap_or_else(|e| unreachable!("a trimmed TLV is shorter than the original: {e:?}"));
    let header_length = TlvHeader::LENGTH.get() as usize;
    let mut out = vec![0u8; header_length + length as usize];
    header
        .deparse(&mut out)
        .unwrap_or_else(|e| unreachable!("the buffer holds the header: {e:?}"));
    out[header_length..].copy_from_slice(&tlv[header_length..header_length + length as usize]);
    out
}

#[cfg(test)]
mod test {
    use super::Received;
    use crate::eth::mac::Mac;
    use crate::lldp::chassis_id::{ChassisId, IdOctets};
    use crate::lldp::optional::{OptionalTlv, OptionalTlvError, Text};
    use crate::lldp::pdu::{Lldpdu, LldpduError};
    use crate::lldp::port_id::PortId;
    use crate::lldp::tlv::TlvType;
    use crate::lldp::ttl::TimeToLive;
    use crate::parse::{DeParse, ParseError};

    fn minimal() -> Lldpdu {
        Lldpdu::new(
            ChassisId::MacAddress(Mac([0x02, 0, 0, 0, 0, 1])),
            PortId::InterfaceName(IdOctets::new(b"swp1").unwrap()),
            TimeToLive::new(120),
        )
    }

    fn named(name: &[u8]) -> Lldpdu {
        let mut pdu = minimal();
        pdu.try_push(OptionalTlv::SystemName(Text::new(name).unwrap()))
            .unwrap();
        pdu
    }

    fn deparse(pdu: &Lldpdu) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size().get() as usize];
        pdu.deparse(&mut buf).unwrap();
        buf
    }

    /// The octets of the mandatory TLVs of [`minimal`], without the end marker.
    fn mandatory() -> Vec<u8> {
        let mut buf = deparse(&minimal());
        buf.truncate(buf.len() - 2);
        buf
    }

    fn tlv(typ: u8, value: &[u8]) -> Vec<u8> {
        let length = u16::try_from(value.len()).unwrap();
        let [high, low] = length.to_be_bytes();
        let mut out = vec![(typ << 1) | high, low];
        out.extend_from_slice(value);
        out
    }

    fn received(buf: &[u8]) -> Received {
        Lldpdu::receive(buf).unwrap()
    }

    #[test]
    fn whatever_parse_accepts_receive_accepts_unchanged() {
        bolero::check!().with_type().for_each(|pdu: &Lldpdu| {
            let buf = deparse(pdu);
            assert_eq!(
                received(&buf),
                Received {
                    lldpdu: pdu.clone(),
                    discarded: 0
                }
            );
        });
    }

    #[test]
    fn receive_never_panics() {
        bolero::check!().for_each(|buf: &[u8]| {
            let _ = Lldpdu::receive(buf);
        });
    }

    #[test]
    fn a_missing_end_marker_is_accepted() {
        let mut buf = deparse(&named(b"spine1"));
        buf.truncate(buf.len() - 2);
        assert_eq!(received(&buf).lldpdu, named(b"spine1"));
    }

    #[test]
    fn a_tlv_running_past_the_end_is_dropped_and_what_came_before_kept() {
        let mut buf = deparse(&named(b"spine1"));
        buf.truncate(buf.len() - 2);
        buf.extend_from_slice(&[6 << 1, 40, b'x']);
        let received = received(&buf);
        assert_eq!(received.lldpdu, named(b"spine1"));
        assert_eq!(received.discarded, 1);
    }

    #[test]
    fn a_tlv_with_a_specific_error_is_discarded_and_counted() {
        let mut buf = mandatory();
        // A system name may not exceed 255 octets.
        buf.extend(tlv(5, &[b'x'; 300]));
        buf.extend(tlv(5, b"spine1"));
        buf.extend([0, 0]);
        let received = received(&buf);
        assert_eq!(received.lldpdu, named(b"spine1"));
        assert_eq!(received.discarded, 1);
    }

    #[test]
    fn a_longer_ttl_uses_its_first_two_octets() {
        let mut buf = deparse(&minimal());
        buf.truncate(buf.len() - 6);
        buf.extend(tlv(3, &[0, 120, 0xff, 0xff]));
        buf.extend([0, 0]);
        assert_eq!(received(&buf).lldpdu, minimal());
    }

    #[test]
    fn a_short_ttl_rejects_the_lldpdu() {
        let mut buf = deparse(&minimal());
        buf.truncate(buf.len() - 6);
        buf.extend(tlv(3, &[120]));
        buf.extend([0, 0]);
        assert!(matches!(
            Lldpdu::receive(&buf),
            Err(ParseError::Invalid(LldpduError::TimeToLive(_)))
        ));
    }

    #[test]
    fn a_repeated_mandatory_tlv_rejects_the_lldpdu() {
        let mut buf = mandatory();
        buf.extend(tlv(3, &[0, 120]));
        buf.extend([0, 0]);
        assert!(matches!(
            Lldpdu::receive(&buf),
            Err(ParseError::Invalid(LldpduError::OptionalTlv(
                OptionalTlvError::Structural(TlvType::TIME_TO_LIVE)
            )))
        ));
    }

    #[test]
    fn extra_octets_after_fixed_size_tlvs_are_ignored() {
        let mut buf = mandatory();
        // System capabilities, then an 802.1 port VLAN ID, then an 802.3
        // maximum frame size, then a management address, each with two
        // octets too many.
        buf.extend(tlv(7, &[0, 0x14, 0, 0x10, 0xaa, 0xbb]));
        buf.extend(tlv(127, &[0x00, 0x80, 0xc2, 1, 0, 10, 0xaa, 0xbb]));
        buf.extend(tlv(127, &[0x00, 0x12, 0x0f, 4, 0x05, 0xee, 0xaa, 0xbb]));
        buf.extend(tlv(8, &[5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 1, 0, 0xaa, 0xbb]));
        buf.extend([0, 0]);
        let received = received(&buf);
        assert_eq!(received.discarded, 0);
        let mut expected = mandatory();
        expected.extend(tlv(7, &[0, 0x14, 0, 0x10]));
        expected.extend(tlv(127, &[0x00, 0x80, 0xc2, 1, 0, 10]));
        expected.extend(tlv(127, &[0x00, 0x12, 0x0f, 4, 0x05, 0xee]));
        expected.extend(tlv(8, &[5, 1, 192, 0, 2, 1, 2, 0, 0, 0, 1, 0]));
        expected.extend([0, 0]);
        assert_eq!(deparse(&received.lldpdu), expected);
    }

    #[test]
    fn a_tlv_too_short_for_its_fields_rejects_the_lldpdu() {
        let mut buf = mandatory();
        buf.extend(tlv(127, &[0x00, 0x80]));
        buf.extend([0, 0]);
        assert!(matches!(
            Lldpdu::receive(&buf),
            Err(ParseError::Invalid(LldpduError::OptionalTlv(
                OptionalTlvError::OrganizationallySpecific(_)
            )))
        ));
    }
}
