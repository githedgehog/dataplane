// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The chassis ID TLV, which identifies the system that sent an LLDPDU.
//!
//! Exactly one chassis ID TLV appears in every LLDPDU, and it is always the
//! first one.  `Lldpdu` enforces that by storing it in a
//! dedicated field rather than in a list of TLVs.

use core::num::NonZero;

use crate::eth::mac::Mac;
use crate::lldp::address::{NetworkAddress, NetworkAddressError};
use crate::lldp::octets::{Octets, OctetsError};
use crate::lldp::tlv::{TlvHeader, TlvType, UnexpectedTlvType, split_tlv, write_tlv};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};

/// The identifier portion of a chassis ID TLV.
///
/// [IEEE Std 802.1AB] bounds this at 255 octets, and requires it to be
/// non-empty.
///
/// [IEEE Std 802.1AB]: https://standards.ieee.org/ieee/802.1AB/6047/
pub type IdOctets = Octets<1, 255>;

/// How the identifier in a chassis ID TLV should be interpreted.
///
/// Subtype 0 and subtypes 8 through 255 are reserved by the standard, so they
/// have no representation here and are rejected at parse time.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    strum_macros::Display,
    strum_macros::EnumCount,
    serde::Serialize,
    serde::Deserialize,
)]
#[repr(u8)]
pub enum ChassisIdSubtype {
    /// An `entPhysicalAlias` naming a chassis component.
    ChassisComponent = 1,
    /// An `ifAlias` naming an interface.
    InterfaceAlias = 2,
    /// An `entPhysicalAlias` naming a port or backplane component.
    PortComponent = 3,
    /// An IEEE 802 MAC address.
    MacAddress = 4,
    /// An address in some address family.
    NetworkAddress = 5,
    /// An `ifName` naming an interface.
    InterfaceName = 6,
    /// A locally assigned identifier.
    LocallyAssigned = 7,
}

impl ChassisIdSubtype {
    /// The raw value of this subtype.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for ChassisIdSubtype {
    type Error = ReservedChassisIdSubtype;

    fn try_from(value: u8) -> Result<ChassisIdSubtype, ReservedChassisIdSubtype> {
        match value {
            1 => Ok(ChassisIdSubtype::ChassisComponent),
            2 => Ok(ChassisIdSubtype::InterfaceAlias),
            3 => Ok(ChassisIdSubtype::PortComponent),
            4 => Ok(ChassisIdSubtype::MacAddress),
            5 => Ok(ChassisIdSubtype::NetworkAddress),
            6 => Ok(ChassisIdSubtype::InterfaceName),
            7 => Ok(ChassisIdSubtype::LocallyAssigned),
            other => Err(ReservedChassisIdSubtype(other)),
        }
    }
}

/// The error returned when a chassis ID subtype is one the standard reserves.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("chassis ID subtype {0} is reserved")]
pub struct ReservedChassisIdSubtype(pub u8);

/// The chassis ID TLV.
///
/// The subtype is not a separate field: it is implied by the variant, so a
/// chassis ID cannot claim to be a MAC address while carrying something that is
/// not one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ChassisId {
    /// An `entPhysicalAlias` naming a chassis component.
    ChassisComponent(IdOctets),
    /// An `ifAlias` naming an interface.
    InterfaceAlias(IdOctets),
    /// An `entPhysicalAlias` naming a port or backplane component.
    PortComponent(IdOctets),
    /// An IEEE 802 MAC address.
    MacAddress(Mac),
    /// An address in some address family.
    NetworkAddress(NetworkAddress),
    /// An `ifName` naming an interface.
    InterfaceName(IdOctets),
    /// A locally assigned identifier.
    LocallyAssigned(IdOctets),
}

impl ChassisId {
    /// The TLV type of a chassis ID.
    pub const TLV_TYPE: TlvType = TlvType::CHASSIS_ID;

    /// The subtype this chassis ID encodes as.
    #[must_use]
    pub const fn subtype(&self) -> ChassisIdSubtype {
        match self {
            ChassisId::ChassisComponent(_) => ChassisIdSubtype::ChassisComponent,
            ChassisId::InterfaceAlias(_) => ChassisIdSubtype::InterfaceAlias,
            ChassisId::PortComponent(_) => ChassisIdSubtype::PortComponent,
            ChassisId::MacAddress(_) => ChassisIdSubtype::MacAddress,
            ChassisId::NetworkAddress(_) => ChassisIdSubtype::NetworkAddress,
            ChassisId::InterfaceName(_) => ChassisIdSubtype::InterfaceName,
            ChassisId::LocallyAssigned(_) => ChassisIdSubtype::LocallyAssigned,
        }
    }

    /// The length of the TLV value, which is the subtype octet plus the
    /// identifier.
    ///
    /// This is bounded by 256, comfortably inside the 511 octet limit a TLV
    /// length field can express.
    fn value_length(&self) -> u16 {
        let id_len = match self {
            ChassisId::ChassisComponent(id)
            | ChassisId::InterfaceAlias(id)
            | ChassisId::PortComponent(id)
            | ChassisId::InterfaceName(id)
            | ChassisId::LocallyAssigned(id) => id.len(),
            ChassisId::MacAddress(_) => 6,
            ChassisId::NetworkAddress(address) => address.octet_len(),
        };
        // `IdOctets` caps the identifier at 255 octets and a network address at
        // 255, so the sum always fits in a `u16`.
        #[allow(clippy::cast_possible_truncation)] // bounded by 256
        {
            (1 + id_len) as u16
        }
    }
}

/// Errors which can occur while parsing a [`ChassisId`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ChassisIdError {
    /// The TLV at this position was not a chassis ID TLV.
    #[error(transparent)]
    UnexpectedTlvType(#[from] UnexpectedTlvType),
    /// The TLV value did not even contain a subtype octet.
    #[error("chassis ID TLV carries no value")]
    Empty,
    /// The subtype is one the standard reserves.
    #[error(transparent)]
    ReservedSubtype(ReservedChassisIdSubtype),
    /// A MAC address chassis ID was not six octets long.
    #[error("a MAC address chassis ID must be exactly 6 octets, found {0}")]
    InvalidMacLength(usize),
    /// A network address chassis ID could not be decoded.
    #[error(transparent)]
    NetworkAddress(NetworkAddressError),
    /// The identifier was empty or longer than the standard permits.
    #[error(transparent)]
    Id(OctetsError),
}

impl Parse for ChassisId {
    type Error = ChassisIdError;

    fn parse(buf: &[u8]) -> Result<(ChassisId, NonZero<u16>), ParseError<ChassisIdError>> {
        let (value, total) = split_tlv::<ChassisIdError>(buf, ChassisId::TLV_TYPE)?;
        let Some((&raw_subtype, id)) = value.split_first() else {
            return Err(ParseError::Invalid(ChassisIdError::Empty));
        };
        let subtype = ChassisIdSubtype::try_from(raw_subtype)
            .map_err(|e| ParseError::Invalid(ChassisIdError::ReservedSubtype(e)))?;
        let octets = || IdOctets::new(id).map_err(|e| ParseError::Invalid(ChassisIdError::Id(e)));
        let chassis_id = match subtype {
            ChassisIdSubtype::ChassisComponent => ChassisId::ChassisComponent(octets()?),
            ChassisIdSubtype::InterfaceAlias => ChassisId::InterfaceAlias(octets()?),
            ChassisIdSubtype::PortComponent => ChassisId::PortComponent(octets()?),
            ChassisIdSubtype::InterfaceName => ChassisId::InterfaceName(octets()?),
            ChassisIdSubtype::LocallyAssigned => ChassisId::LocallyAssigned(octets()?),
            ChassisIdSubtype::MacAddress => {
                let raw: [u8; 6] = id
                    .try_into()
                    .map_err(|_| ParseError::Invalid(ChassisIdError::InvalidMacLength(id.len())))?;
                ChassisId::MacAddress(Mac(raw))
            }
            ChassisIdSubtype::NetworkAddress => ChassisId::NetworkAddress(
                NetworkAddress::from_octets(id)
                    .map_err(|e| ParseError::Invalid(ChassisIdError::NetworkAddress(e)))?,
            ),
        };
        Ok((chassis_id, total))
    }
}

impl DeParse for ChassisId {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        TlvHeader::LENGTH.saturating_add(self.value_length())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        write_tlv(buf, ChassisId::TLV_TYPE, self.value_length(), |slot| {
            slot[0] = self.subtype().as_u8();
            match self {
                ChassisId::ChassisComponent(id)
                | ChassisId::InterfaceAlias(id)
                | ChassisId::PortComponent(id)
                | ChassisId::InterfaceName(id)
                | ChassisId::LocallyAssigned(id) => slot[1..].copy_from_slice(id.as_bytes()),
                ChassisId::MacAddress(mac) => slot[1..].copy_from_slice(&mac.0),
                ChassisId::NetworkAddress(address) => address.write_octets(&mut slot[1..]),
            }
        })
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{ChassisId, ChassisIdSubtype};
    use crate::eth::mac::Mac;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for ChassisId {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            match u.produce::<u8>()? % 7 {
                0 => Some(ChassisId::ChassisComponent(u.produce()?)),
                1 => Some(ChassisId::InterfaceAlias(u.produce()?)),
                2 => Some(ChassisId::PortComponent(u.produce()?)),
                3 => Some(ChassisId::MacAddress(u.produce::<Mac>()?)),
                4 => Some(ChassisId::NetworkAddress(u.produce()?)),
                5 => Some(ChassisId::InterfaceName(u.produce()?)),
                _ => Some(ChassisId::LocallyAssigned(u.produce()?)),
            }
        }
    }

    impl TypeGenerator for ChassisIdSubtype {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            ChassisIdSubtype::try_from((u.produce::<u8>()? % 7) + 1).ok()
        }
    }
}

/// The identifier's value; its subtype is what kind of value it is, which the value usually shows.
impl core::fmt::Display for ChassisId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChassisId::ChassisComponent(value)
            | ChassisId::InterfaceAlias(value)
            | ChassisId::PortComponent(value)
            | ChassisId::InterfaceName(value)
            | ChassisId::LocallyAssigned(value) => value.fmt(f),
            ChassisId::MacAddress(mac) => mac.fmt(f),
            ChassisId::NetworkAddress(address) => address.fmt(f),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{ChassisId, ChassisIdError, ChassisIdSubtype, IdOctets};
    use crate::eth::mac::Mac;
    use crate::lldp::address::{NetworkAddress, NetworkAddressError};
    use crate::lldp::octets::OctetsError;
    use crate::lldp::tlv::{RawTlv, TlvType, TlvValue};
    use crate::parse::{DeParse, Parse, ParseError};

    fn deparse(chassis_id: &ChassisId) -> Vec<u8> {
        let mut buf = vec![0u8; chassis_id.size().get() as usize];
        let written = chassis_id.deparse(&mut buf).unwrap();
        assert_eq!(written, chassis_id.size());
        buf
    }

    #[test]
    fn round_trips() {
        bolero::check!()
            .with_type()
            .for_each(|chassis_id: &ChassisId| {
                let buf = deparse(chassis_id);
                let (parsed, consumed) = ChassisId::parse(&buf).unwrap();
                assert_eq!(&parsed, chassis_id);
                assert_eq!(consumed, chassis_id.size());
                assert_eq!(parsed.subtype(), chassis_id.subtype());
            });
    }

    #[test]
    fn parse_of_arbitrary_octets_is_byte_exact() {
        bolero::check!().with_type().for_each(|raw: &Vec<u8>| {
            let Ok((chassis_id, consumed)) = ChassisId::parse(raw) else {
                return;
            };
            assert_eq!(consumed, chassis_id.size());
            let written = deparse(&chassis_id);
            assert_eq!(&written[..], &raw[..consumed.get() as usize]);
        });
    }

    #[test]
    fn a_mac_chassis_id_must_be_six_octets() {
        for length in [0usize, 5, 7, 16] {
            let mut value = vec![ChassisIdSubtype::MacAddress.as_u8()];
            value.extend(core::iter::repeat_n(0xab, length));
            let tlv = RawTlv::new(TlvType::CHASSIS_ID, TlvValue::new(&value).unwrap());
            let mut buf = vec![0u8; tlv.size().get() as usize];
            tlv.deparse(&mut buf).unwrap();
            match ChassisId::parse(&buf) {
                Err(ParseError::Invalid(ChassisIdError::InvalidMacLength(found))) => {
                    assert_eq!(found, length);
                }
                other => unreachable!("expected a MAC length error for {length}, got {other:?}"),
            }
        }
    }

    #[test]
    fn reserved_subtypes_are_rejected() {
        for raw_subtype in [0u8, 8, 100, 255] {
            let value = [raw_subtype, 0x01, 0x02];
            let tlv = RawTlv::new(TlvType::CHASSIS_ID, TlvValue::new(&value).unwrap());
            let mut buf = vec![0u8; tlv.size().get() as usize];
            tlv.deparse(&mut buf).unwrap();
            match ChassisId::parse(&buf) {
                Err(ParseError::Invalid(ChassisIdError::ReservedSubtype(e))) => {
                    assert_eq!(e.0, raw_subtype);
                }
                other => unreachable!("expected a reserved subtype error, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_empty_identifier_is_rejected() {
        let value = [ChassisIdSubtype::LocallyAssigned.as_u8()];
        let tlv = RawTlv::new(TlvType::CHASSIS_ID, TlvValue::new(&value).unwrap());
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match ChassisId::parse(&buf) {
            Err(ParseError::Invalid(ChassisIdError::Id(OctetsError::TooShort {
                len: 0,
                min: 1,
            }))) => {}
            other => unreachable!("expected an empty identifier error, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_value_is_rejected() {
        let tlv = RawTlv::new(TlvType::CHASSIS_ID, TlvValue::default());
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match ChassisId::parse(&buf) {
            Err(ParseError::Invalid(ChassisIdError::Empty)) => {}
            other => unreachable!("expected an empty value error, got {other:?}"),
        }
    }

    #[test]
    fn the_wrong_tlv_type_is_rejected() {
        let tlv = RawTlv::new(
            TlvType::PORT_ID,
            TlvValue::new(&[4, 1, 2, 3, 4, 5, 6]).unwrap(),
        );
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match ChassisId::parse(&buf) {
            Err(ParseError::Invalid(ChassisIdError::UnexpectedTlvType(e))) => {
                assert_eq!(e.expected, TlvType::CHASSIS_ID);
                assert_eq!(e.found, TlvType::PORT_ID);
            }
            other => unreachable!("expected a TLV type error, got {other:?}"),
        }
    }

    #[test]
    fn a_short_network_address_is_rejected() {
        let value = [ChassisIdSubtype::NetworkAddress.as_u8(), 1, 10, 0];
        let tlv = RawTlv::new(TlvType::CHASSIS_ID, TlvValue::new(&value).unwrap());
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match ChassisId::parse(&buf) {
            Err(ParseError::Invalid(ChassisIdError::NetworkAddress(
                NetworkAddressError::WrongAddressLength { found, .. },
            ))) => assert_eq!(found, 2),
            other => unreachable!("expected a network address error, got {other:?}"),
        }
    }

    #[test]
    fn known_encodings() {
        let mac = ChassisId::MacAddress(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
        assert_eq!(
            deparse(&mac),
            vec![0x02, 0x07, 0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
        );

        let name = ChassisId::InterfaceName(IdOctets::new(b"eth0").unwrap());
        assert_eq!(
            deparse(&name),
            vec![0x02, 0x05, 0x06, b'e', b't', b'h', b'0']
        );

        let ip = ChassisId::NetworkAddress(NetworkAddress::Ipv4([192, 0, 2, 1].into()));
        assert_eq!(deparse(&ip), vec![0x02, 0x06, 0x05, 0x01, 192, 0, 2, 1]);
    }

    #[test]
    fn deparse_into_insufficient_buffer_fails_gracefully() {
        bolero::check!()
            .with_type()
            .for_each(|chassis_id: &ChassisId| {
                let mut buf = vec![0u8; chassis_id.size().get() as usize - 1];
                assert!(chassis_id.deparse(&mut buf).is_err());
            });
    }
}
