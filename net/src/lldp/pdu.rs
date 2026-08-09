// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The LLDPDU: the sequence of TLVs which makes up the payload of an LLDP
//! frame.

use core::num::NonZero;

use crate::lldp::chassis_id::{ChassisId, ChassisIdError};
use crate::lldp::optional::{OptionalTlv, OptionalTlvError};
use crate::lldp::port_id::{PortId, PortIdError};
use crate::lldp::tlv::{TlvHeader, TlvType, lift, never};
use crate::lldp::ttl::{EndOfLldpdu, EndOfLldpduError, TimeToLive, TimeToLiveError};
use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError};

/// An LLDP Data Unit.
///
/// # Shape
///
/// [IEEE Std 802.1AB] requires that an LLDPDU begin with a chassis ID TLV, a
/// port ID TLV, and a time to live TLV, in that order and exactly once each,
/// and that it end with an end of LLDPDU TLV.  Everything between the time to
/// live and the end marker is optional and may appear in any order.
///
/// This type encodes that shape rather than checking it: the three mandatory
/// TLVs are fields, the end marker is supplied by the serializer, and only the
/// optional TLVs live in a list.  An `Lldpdu` therefore cannot be built in an
/// order the standard forbids, and because [`OptionalTlv`] cannot represent a
/// structural TLV at all, one cannot be smuggled into the optional section
/// where it would change the meaning of the frame.
///
/// [IEEE Std 802.1AB]: https://standards.ieee.org/ieee/802.1AB/6047/
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
pub struct Lldpdu {
    chassis_id: ChassisId,
    port_id: PortId,
    ttl: TimeToLive,
    optional: Vec<OptionalTlv>,
}

impl Lldpdu {
    /// The largest LLDPDU this type will build or accept.
    ///
    /// The standard requires an LLDPDU to fit in a single frame, and LLDP is
    /// not carried over jumbo frames, so the basic Ethernet payload limit is
    /// the effective bound.  Enforcing it is also what lets [`Lldpdu::size`]
    /// return a `u16` without any possibility of overflow.
    pub const MAX_LENGTH: u16 = 1500;

    /// Build an LLDPDU carrying only the three mandatory TLVs.
    ///
    /// Optional TLVs are added with [`Lldpdu::try_push`].
    #[must_use]
    pub fn new(chassis_id: ChassisId, port_id: PortId, ttl: TimeToLive) -> Lldpdu {
        Lldpdu {
            chassis_id,
            port_id,
            ttl,
            optional: Vec::new(),
        }
    }

    /// The chassis ID of this LLDPDU.
    #[must_use]
    pub const fn chassis_id(&self) -> &ChassisId {
        &self.chassis_id
    }

    /// The port ID of this LLDPDU.
    #[must_use]
    pub const fn port_id(&self) -> &PortId {
        &self.port_id
    }

    /// The time to live of this LLDPDU.
    #[must_use]
    pub const fn ttl(&self) -> TimeToLive {
        self.ttl
    }

    /// Set the time to live of this LLDPDU.
    ///
    /// A time to live is fixed length, so this can never overflow the LLDPDU.
    pub const fn set_ttl(&mut self, ttl: TimeToLive) -> &mut Lldpdu {
        self.ttl = ttl;
        self
    }

    /// The optional TLVs of this LLDPDU, in the order they appear on the wire.
    #[must_use]
    pub fn optional(&self) -> &[OptionalTlv] {
        &self.optional
    }

    /// Append an optional TLV.
    ///
    /// # Errors
    ///
    /// Returns [`LldpduTooLong`] if adding `tlv` would push the LLDPDU past
    /// [`Lldpdu::MAX_LENGTH`].
    pub fn try_push(&mut self, tlv: OptionalTlv) -> Result<&mut Lldpdu, LldpduTooLong> {
        let current = self.length();
        let added = tlv.size().get();
        if u32::from(current) + u32::from(added) > u32::from(Lldpdu::MAX_LENGTH) {
            return Err(LldpduTooLong {
                current,
                added,
                max: Lldpdu::MAX_LENGTH,
            });
        }
        self.optional.push(tlv);
        Ok(self)
    }

    /// The number of octets this LLDPDU occupies on the wire, including the end
    /// of LLDPDU marker.
    fn length(&self) -> u16 {
        let sum = u32::from(self.chassis_id.size().get())
            + u32::from(self.port_id.size().get())
            + u32::from(self.ttl.size().get())
            + u32::from(EndOfLldpdu.size().get())
            + self
                .optional
                .iter()
                .map(|tlv| u32::from(tlv.size().get()))
                .sum::<u32>();
        u16::try_from(sum).unwrap_or_else(|_| {
            unreachable!("try_push holds the LLDPDU length below Lldpdu::MAX_LENGTH")
        })
    }
}

/// Deserialization goes through the derived shape and then re-runs every
/// optional TLV through [`Lldpdu::try_push`], so a representation whose TLVs add
/// up to more than [`Lldpdu::MAX_LENGTH`] is rejected rather than trusted.
impl<'de> serde::Deserialize<'de> for Lldpdu {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Lldpdu, D::Error> {
        let unchecked = Lldpdu::deserialize(deserializer)?;
        let mut pdu = Lldpdu::new(unchecked.chassis_id, unchecked.port_id, unchecked.ttl);
        for tlv in unchecked.optional {
            pdu.try_push(tlv).map_err(serde::de::Error::custom)?;
        }
        Ok(pdu)
    }
}

impl serde::Serialize for Lldpdu {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Lldpdu::serialize(self, serializer)
    }
}

/// The error returned when a TLV will not fit in an [`Lldpdu`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("adding {added} octets to a {current} octet LLDPDU would exceed the {max} octet maximum")]
pub struct LldpduTooLong {
    /// The length of the LLDPDU before the TLV was added.
    pub current: u16,
    /// The number of octets the TLV would have added.
    pub added: u16,
    /// The largest LLDPDU permitted.
    pub max: u16,
}

/// Errors which can occur while parsing an [`Lldpdu`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum LldpduError {
    /// The mandatory chassis ID TLV was missing or malformed.
    #[error("invalid chassis ID TLV: {0}")]
    ChassisId(ChassisIdError),
    /// The mandatory port ID TLV was missing or malformed.
    #[error("invalid port ID TLV: {0}")]
    PortId(PortIdError),
    /// The mandatory time to live TLV was missing or malformed.
    #[error("invalid time to live TLV: {0}")]
    TimeToLive(TimeToLiveError),
    /// The end of LLDPDU TLV was malformed.
    #[error("invalid end of LLDPDU TLV: {0}")]
    EndOfLldpdu(EndOfLldpduError),
    /// An optional TLV was malformed.
    #[error(transparent)]
    OptionalTlv(OptionalTlvError),
    /// The buffer ran out before an end of LLDPDU TLV was found.
    ///
    /// The standard requires the marker, so this parser requires it too.  A
    /// station which omits it is not merely lax: without the marker a receiver
    /// cannot tell a truncated LLDPDU from a complete one followed by padding.
    #[error("reached the end of the buffer without an end of LLDPDU TLV")]
    MissingEndOfLldpdu,
    /// The TLVs added up to more than an LLDPDU may carry.
    #[error(transparent)]
    TooLong(LldpduTooLong),
}

impl Parse for Lldpdu {
    type Error = LldpduError;

    fn parse(buf: &[u8]) -> Result<(Lldpdu, NonZero<u16>), ParseError<LldpduError>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }

        let (chassis_id, consumed) = ChassisId::parse(buf).map_err(lift(LldpduError::ChassisId))?;
        let mut offset = consumed.get() as usize;

        let (port_id, consumed) =
            PortId::parse(&buf[offset..]).map_err(lift(LldpduError::PortId))?;
        offset += consumed.get() as usize;

        let (ttl, consumed) =
            TimeToLive::parse(&buf[offset..]).map_err(lift(LldpduError::TimeToLive))?;
        offset += consumed.get() as usize;

        let mut pdu = Lldpdu::new(chassis_id, port_id, ttl);
        loop {
            if offset >= buf.len() {
                return Err(ParseError::Invalid(LldpduError::MissingEndOfLldpdu));
            }
            // Peek at the type so the end marker can be recognized without
            // consuming it as an ordinary optional TLV.
            let (header, _) = TlvHeader::parse(&buf[offset..]).map_err(never)?;
            if header.typ() == TlvType::END_OF_LLDPDU {
                let (_, consumed) =
                    EndOfLldpdu::parse(&buf[offset..]).map_err(lift(LldpduError::EndOfLldpdu))?;
                offset += consumed.get() as usize;
                break;
            }
            let (tlv, consumed) =
                OptionalTlv::parse(&buf[offset..]).map_err(lift(LldpduError::OptionalTlv))?;
            offset += consumed.get() as usize;
            pdu.try_push(tlv)
                .map_err(|e| ParseError::Invalid(LldpduError::TooLong(e)))?;
        }

        let consumed = u16::try_from(offset)
            .ok()
            .and_then(NonZero::new)
            .unwrap_or_else(|| unreachable!("at least the mandatory TLVs were consumed"));
        Ok((pdu, consumed))
    }
}

impl DeParse for Lldpdu {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        NonZero::new(self.length())
            .unwrap_or_else(|| unreachable!("an LLDPDU always carries at least four TLVs"))
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let total = self.size();
        if buf.len() < total.into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: total.into_non_zero_usize(),
                actual: buf.len(),
            }));
        }

        let mut offset = 0usize;
        offset += usize::from(self.chassis_id.write(&mut buf[offset..]));
        offset += usize::from(self.port_id.write(&mut buf[offset..]));
        offset += usize::from(self.ttl.write(&mut buf[offset..]));
        for tlv in &self.optional {
            offset += usize::from(tlv.write(&mut buf[offset..]));
        }
        offset += usize::from(EndOfLldpdu.write(&mut buf[offset..]));
        debug_assert_eq!(offset, total.into_non_zero_usize().get());

        Ok(total)
    }
}

/// Erases the differing `DeParse::Error` types of the TLVs an LLDPDU contains.
///
/// [`Lldpdu::deparse`] length checks the whole buffer up front, so by the time
/// a fragment is written the only error it could report is impossible.
trait DeParseFragment {
    fn write(&self, buf: &mut [u8]) -> u16;
}

impl<T: DeParse<Error = ()>> DeParseFragment for T {
    fn write(&self, buf: &mut [u8]) -> u16 {
        self.deparse(buf)
            .unwrap_or_else(|e| unreachable!("LLDPDU buffer was length checked up front: {e:?}"))
            .get()
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::Lldpdu;
    use bolero::{Driver, TypeGenerator};

    /// How many optional TLVs to offer the LLDPDU.  Ones which do not fit are
    /// skipped rather than ending generation, so a large TLV early on does not
    /// stop smaller ones from being exercised.
    const OPTIONAL_TLV_ATTEMPTS: usize = 6;

    impl TypeGenerator for Lldpdu {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let mut pdu = Lldpdu::new(u.produce()?, u.produce()?, u.produce()?);
            for _ in 0..OPTIONAL_TLV_ATTEMPTS {
                let _ = pdu.try_push(u.produce()?);
            }
            Some(pdu)
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Lldpdu, LldpduError};
    use crate::eth::mac::Mac;
    use crate::lldp::capabilities::{SystemCapabilities, SystemCapability};
    use crate::lldp::chassis_id::{ChassisId, IdOctets};
    use crate::lldp::optional::{OptionalTlv, OptionalTlvError, Text, UnrecognizedTlv};
    use crate::lldp::org::{Dot1Tlv, OrganizationallySpecific, VlanId};
    use crate::lldp::port_id::PortId;
    use crate::lldp::tlv::{RawTlv, TlvType, TlvValue};
    use crate::lldp::ttl::TimeToLive;
    use crate::parse::{DeParse, DeParseError, IntoNonZeroUSize, Parse, ParseError};

    fn deparse(pdu: &Lldpdu) -> Vec<u8> {
        let mut buf = vec![0u8; pdu.size().get() as usize];
        let written = pdu.deparse(&mut buf).unwrap();
        assert_eq!(written, pdu.size());
        buf
    }

    fn minimal() -> Lldpdu {
        Lldpdu::new(
            ChassisId::MacAddress(Mac([0x02, 0, 0, 0, 0, 1])),
            PortId::InterfaceName(IdOctets::new(b"swp1").unwrap()),
            TimeToLive::new(120),
        )
    }

    fn text(value: &[u8]) -> Text {
        Text::new(value).unwrap()
    }

    #[test]
    fn round_trips() {
        bolero::check!().with_type().for_each(|pdu: &Lldpdu| {
            let buf = deparse(pdu);
            let (parsed, consumed) = Lldpdu::parse(&buf).unwrap();
            assert_eq!(&parsed, pdu);
            assert_eq!(consumed, pdu.size());
        });
    }

    #[test]
    fn round_trips_with_trailing_padding() {
        bolero::check!().with_type().for_each(|pdu: &Lldpdu| {
            let mut buf = deparse(pdu);
            let unpadded = buf.len();
            buf.resize(unpadded + 17, 0);
            let (parsed, consumed) = Lldpdu::parse(&buf).unwrap();
            assert_eq!(&parsed, pdu);
            assert_eq!(
                consumed.get() as usize,
                unpadded,
                "padding after the end marker must not be consumed"
            );
        });
    }

    #[test]
    fn parse_of_arbitrary_octets_is_byte_exact() {
        bolero::check!().with_type().for_each(|raw: &Vec<u8>| {
            let Ok((pdu, consumed)) = Lldpdu::parse(raw) else {
                return;
            };
            assert_eq!(consumed, pdu.size());
            assert_eq!(&deparse(&pdu)[..], &raw[..consumed.get() as usize]);
        });
    }

    /// Uniformly random octets essentially never form a valid LLDPDU, so
    /// [`parse_of_arbitrary_octets_is_byte_exact`] rarely gets past the first
    /// TLV.  Mutating a single octet of a valid LLDPDU keeps the parser in
    /// interesting territory: whatever still parses must still be byte exact.
    #[test]
    fn a_mutated_lldpdu_is_rejected_or_byte_exact() {
        bolero::check!()
            .with_type()
            .for_each(|(pdu, index, replacement): &(Lldpdu, usize, u8)| {
                let mut buf = deparse(pdu);
                let index = index % buf.len();
                buf[index] = *replacement;
                let Ok((parsed, consumed)) = Lldpdu::parse(&buf) else {
                    return;
                };
                assert_eq!(consumed, parsed.size());
                assert_eq!(&deparse(&parsed)[..], &buf[..consumed.get() as usize]);
            });
    }

    #[test]
    fn every_truncation_of_a_valid_lldpdu_is_rejected() {
        bolero::check!().with_type().for_each(|pdu: &Lldpdu| {
            let buf = deparse(pdu);
            for cut in 0..buf.len() {
                assert!(
                    Lldpdu::parse(&buf[..cut]).is_err(),
                    "a {cut} octet prefix of a {len} octet LLDPDU parsed",
                    len = buf.len()
                );
            }
        });
    }

    #[test]
    fn a_missing_end_marker_is_rejected() {
        let pdu = minimal();
        let buf = deparse(&pdu);
        let truncated = &buf[..buf.len() - 2];
        match Lldpdu::parse(truncated) {
            Err(ParseError::Invalid(LldpduError::MissingEndOfLldpdu)) => {}
            other => unreachable!("expected a missing end marker error, got {other:?}"),
        }
    }

    #[test]
    fn mandatory_tlvs_must_be_in_order() {
        let pdu = minimal();
        let buf = deparse(&pdu);
        let chassis_len = pdu.chassis_id().size().get() as usize;
        let port_len = pdu.port_id().size().get() as usize;

        // Swap the chassis ID and port ID TLVs.
        let mut swapped = Vec::with_capacity(buf.len());
        swapped.extend_from_slice(&buf[chassis_len..chassis_len + port_len]);
        swapped.extend_from_slice(&buf[..chassis_len]);
        swapped.extend_from_slice(&buf[chassis_len + port_len..]);

        match Lldpdu::parse(&swapped) {
            Err(ParseError::Invalid(LldpduError::ChassisId(_))) => {}
            other => unreachable!("expected a chassis ID error, got {other:?}"),
        }
    }

    #[test]
    fn a_repeated_mandatory_tlv_is_rejected() {
        let pdu = minimal();
        let buf = deparse(&pdu);
        let chassis_len = pdu.chassis_id().size().get() as usize;

        // Splice a second chassis ID TLV in ahead of the end marker.
        let mut doubled = buf[..buf.len() - 2].to_vec();
        doubled.extend_from_slice(&buf[..chassis_len]);
        doubled.extend_from_slice(&buf[buf.len() - 2..]);

        match Lldpdu::parse(&doubled) {
            Err(ParseError::Invalid(LldpduError::OptionalTlv(OptionalTlvError::Structural(
                found,
            )))) => assert_eq!(found, TlvType::CHASSIS_ID),
            other => unreachable!("expected a structural rejection, got {other:?}"),
        }
    }

    #[test]
    fn optional_tlvs_are_preserved_in_order() {
        let mut pdu = minimal();
        let names = [&b"one"[..], &b"two"[..], &b"three"[..]];
        for name in names {
            pdu.try_push(OptionalTlv::SystemName(text(name))).unwrap();
        }
        let buf = deparse(&pdu);
        let (parsed, _) = Lldpdu::parse(&buf).unwrap();
        let round_tripped: Vec<&[u8]> = parsed
            .optional()
            .iter()
            .map(|tlv| match tlv {
                OptionalTlv::SystemName(name) => name.as_bytes(),
                other => unreachable!("expected a system name, got {other:?}"),
            })
            .collect();
        assert_eq!(round_tripped, names);
    }

    #[test]
    fn a_typed_optional_tlv_survives_a_round_trip() {
        let mut pdu = minimal();
        pdu.try_push(OptionalTlv::SystemName(text(b"leaf-01")))
            .unwrap();
        pdu.try_push(OptionalTlv::SystemCapabilities(SystemCapabilities::new(
            SystemCapability::BRIDGE | SystemCapability::ROUTER,
            SystemCapability::ROUTER,
        )))
        .unwrap();
        pdu.try_push(OptionalTlv::OrganizationallySpecific(
            OrganizationallySpecific::Dot1(Dot1Tlv::PortVlanId(VlanId::new(100))),
        ))
        .unwrap();

        let buf = deparse(&pdu);
        let (parsed, consumed) = Lldpdu::parse(&buf).unwrap();
        assert_eq!(parsed, pdu);
        assert_eq!(consumed, pdu.size());

        let Some(OptionalTlv::OrganizationallySpecific(OrganizationallySpecific::Dot1(
            Dot1Tlv::PortVlanId(vlan_id),
        ))) = parsed.optional().get(2)
        else {
            unreachable!("expected a port VLAN ID TLV, got {:?}", parsed.optional());
        };
        assert_eq!(vlan_id.vid().unwrap().as_u16(), 100);
    }

    #[test]
    fn an_unrecognized_tlv_survives_a_round_trip() {
        let mut pdu = minimal();
        let typ = TlvType::new_checked(42).unwrap();
        let payload = TlvValue::new(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        let raw = RawTlv::new(typ, payload.clone());
        pdu.try_push(OptionalTlv::Unrecognized(
            UnrecognizedTlv::new(raw).unwrap(),
        ))
        .unwrap();

        let buf = deparse(&pdu);
        let (parsed, _) = Lldpdu::parse(&buf).unwrap();
        assert_eq!(parsed.optional().len(), 1);
        let OptionalTlv::Unrecognized(unrecognized) = &parsed.optional()[0] else {
            unreachable!("expected an unrecognized TLV");
        };
        assert_eq!(unrecognized.tlv().typ(), typ);
        assert_eq!(unrecognized.tlv().value(), &payload);
        assert_eq!(parsed, pdu);
    }

    #[test]
    fn an_over_long_lldpdu_is_refused() {
        let mut pdu = minimal();
        let big = OptionalTlv::SystemDescription(text(&[b'x'; 255]));
        let mut pushed = 0;
        while pdu.try_push(big.clone()).is_ok() {
            pushed += 1;
            assert!(pushed < 16, "try_push never refused a TLV");
        }
        assert!(pdu.size().get() <= Lldpdu::MAX_LENGTH);
        let error = pdu.try_push(big).unwrap_err();
        assert_eq!(error.current, pdu.size().get());
        assert_eq!(error.added, 257);
        assert_eq!(error.max, Lldpdu::MAX_LENGTH);
    }

    #[test]
    fn serde_round_trips() {
        bolero::check!().with_type().for_each(|pdu: &Lldpdu| {
            let json = serde_json::to_string(pdu).unwrap();
            let parsed: Lldpdu = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, pdu);
        });
    }

    /// Serde is a second way into these types, so it has to enforce the same
    /// invariants the constructors do.  Each of these representations is
    /// well-formed JSON of the right shape and still has to be refused.
    #[test]
    fn deserialize_enforces_the_invariants_the_constructors_do() {
        let cases = [
            // An identifier longer than the 255 octets a chassis ID TLV allots.
            (
                "over long chassis identifier",
                format!(
                    r#"{{"chassis_id":{{"InterfaceName":{ids}}},"port_id":{{"InterfaceName":[1]}},"ttl":30,"optional":[]}}"#,
                    ids = serde_json::to_string(&vec![0u8; 256]).unwrap()
                ),
            ),
            // An empty identifier, which a chassis ID TLV may not carry.
            (
                "empty chassis identifier",
                r#"{"chassis_id":{"InterfaceName":[]},"port_id":{"InterfaceName":[1]},"ttl":30,"optional":[]}"#
                    .to_string(),
            ),
            // A system name smuggled in as an unrecognized TLV, which would
            // give the same octets two representations.
            (
                "recognized type kept verbatim",
                r#"{"chassis_id":{"InterfaceName":[1]},"port_id":{"InterfaceName":[1]},"ttl":30,
                    "optional":[{"Unrecognized":{"typ":5,"value":[104,105]}}]}"#
                    .to_string(),
            ),
            // A TLV type beyond the seven bits the wire format allows.
            (
                "out of range TLV type",
                r#"{"chassis_id":{"InterfaceName":[1]},"port_id":{"InterfaceName":[1]},"ttl":30,
                    "optional":[{"Unrecognized":{"typ":200,"value":[]}}]}"#
                    .to_string(),
            ),
            // An IEEE 802.1 TLV smuggled in under the "some other organization"
            // variant.
            (
                "modelled OUI as other",
                r#"{"chassis_id":{"InterfaceName":[1]},"port_id":{"InterfaceName":[1]},"ttl":30,
                    "optional":[{"OrganizationallySpecific":{"Other":{"oui":[0,128,194],"subtype":9,"info":[]}}}]}"#
                    .to_string(),
            ),
            // An 802.1 port VLAN ID smuggled in under that OUI's catch-all.
            (
                "modelled subtype as other",
                r#"{"chassis_id":{"InterfaceName":[1]},"port_id":{"InterfaceName":[1]},"ttl":30,
                    "optional":[{"OrganizationallySpecific":{"Dot1":{"Other":{"subtype":1,"info":[0,100]}}}}]}"#
                    .to_string(),
            ),
        ];

        for (name, json) in cases {
            assert!(
                serde_json::from_str::<Lldpdu>(&json).is_err(),
                "deserialize accepted {name}"
            );
        }
    }

    /// The length bound is a property of the whole LLDPDU rather than of any
    /// one TLV, so it needs re-checking as the TLVs are put back.
    #[test]
    fn deserialize_rejects_an_over_long_lldpdu() {
        let mut pdu = minimal();
        let big = OptionalTlv::SystemDescription(text(&[b'x'; 255]));
        while pdu.try_push(big.clone()).is_ok() {}

        // Tack one more TLV onto the serialized form than `try_push` allowed.
        let mut value: serde_json::Value = serde_json::to_value(&pdu).unwrap();
        let optional = value["optional"].as_array_mut().unwrap();
        let extra = optional[0].clone();
        optional.push(extra);

        assert!(serde_json::from_value::<Lldpdu>(value).is_err());
    }

    #[test]
    fn size_is_never_greater_than_the_maximum() {
        bolero::check!().with_type().for_each(|pdu: &Lldpdu| {
            assert!(pdu.size().get() <= Lldpdu::MAX_LENGTH);
            assert_eq!(pdu.size().get() as usize, deparse(pdu).len());
        });
    }

    #[test]
    fn deparse_into_insufficient_buffer_fails_gracefully() {
        bolero::check!().with_type().for_each(|pdu: &Lldpdu| {
            let mut buf = vec![0u8; pdu.size().get() as usize - 1];
            match pdu.deparse(&mut buf) {
                Err(DeParseError::Length(e)) => {
                    assert_eq!(e.expected, pdu.size().into_non_zero_usize());
                    assert_eq!(e.actual, buf.len());
                }
                other => unreachable!("expected a length error, got {other:?}"),
            }
        });
    }

    #[test]
    fn a_known_lldpdu_encodes_as_expected() {
        let mut pdu = minimal();
        pdu.try_push(OptionalTlv::SystemName(text(b"leaf-01")))
            .unwrap();
        assert_eq!(
            deparse(&pdu),
            vec![
                // chassis ID: type 1, length 7, subtype 4 (MAC), 02:00:00:00:00:01
                0x02, 0x07, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                // port ID: type 2, length 5, subtype 5 (interface name), "swp1"
                0x04, 0x05, 0x05, b's', b'w', b'p', b'1',
                // time to live: type 3, length 2, 120 seconds
                0x06, 0x02, 0x00, 0x78, //
                // system name: type 5, length 7, "leaf-01"
                0x0a, 0x07, b'l', b'e', b'a', b'f', b'-', b'0', b'1',
                // end of LLDPDU: type 0, length 0
                0x00, 0x00,
            ]
        );
    }
}
