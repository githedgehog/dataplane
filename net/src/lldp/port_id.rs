// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The port ID TLV, which identifies the port that sent an LLDPDU.
//!
//! Exactly one port ID TLV appears in every LLDPDU, immediately after the
//! chassis ID TLV.  `Lldpdu` enforces that by storing it
//! in a dedicated field rather than in a list of TLVs.
//!
//! The encoding mirrors the chassis ID TLV, but the subtypes are numbered
//! differently: a MAC address is subtype 4 in a chassis ID and subtype 3 in a
//! port ID.

use core::num::NonZero;

use crate::eth::mac::Mac;
use crate::lldp::address::{NetworkAddress, NetworkAddressError};
use crate::lldp::chassis_id::IdOctets;
use crate::lldp::octets::OctetsError;
use crate::lldp::tlv::{TlvHeader, TlvType, UnexpectedTlvType, split_tlv, write_tlv};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};

/// How the identifier in a port ID TLV should be interpreted.
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
pub enum PortIdSubtype {
    /// An `ifAlias` naming an interface.
    InterfaceAlias = 1,
    /// An `entPhysicalAlias` naming a port or backplane component.
    PortComponent = 2,
    /// An IEEE 802 MAC address.
    MacAddress = 3,
    /// An address in some address family.
    NetworkAddress = 4,
    /// An `ifName` naming an interface.
    InterfaceName = 5,
    /// An agent circuit ID, as defined by the DHCP relay agent option.
    AgentCircuitId = 6,
    /// A locally assigned identifier.
    LocallyAssigned = 7,
}

impl PortIdSubtype {
    /// The raw value of this subtype.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for PortIdSubtype {
    type Error = ReservedPortIdSubtype;

    fn try_from(value: u8) -> Result<PortIdSubtype, ReservedPortIdSubtype> {
        match value {
            1 => Ok(PortIdSubtype::InterfaceAlias),
            2 => Ok(PortIdSubtype::PortComponent),
            3 => Ok(PortIdSubtype::MacAddress),
            4 => Ok(PortIdSubtype::NetworkAddress),
            5 => Ok(PortIdSubtype::InterfaceName),
            6 => Ok(PortIdSubtype::AgentCircuitId),
            7 => Ok(PortIdSubtype::LocallyAssigned),
            other => Err(ReservedPortIdSubtype(other)),
        }
    }
}

/// The error returned when a port ID subtype is one the standard reserves.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("port ID subtype {0} is reserved")]
pub struct ReservedPortIdSubtype(pub u8);

/// The port ID TLV.
///
/// As with [`ChassisId`](crate::lldp::ChassisId), the subtype is implied by the
/// variant rather than stored alongside it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PortId {
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
    /// An agent circuit ID, as defined by the DHCP relay agent option.
    AgentCircuitId(IdOctets),
    /// A locally assigned identifier.
    LocallyAssigned(IdOctets),
}

impl PortId {
    /// The TLV type of a port ID.
    pub const TLV_TYPE: TlvType = TlvType::PORT_ID;

    /// The subtype this port ID encodes as.
    #[must_use]
    pub const fn subtype(&self) -> PortIdSubtype {
        match self {
            PortId::InterfaceAlias(_) => PortIdSubtype::InterfaceAlias,
            PortId::PortComponent(_) => PortIdSubtype::PortComponent,
            PortId::MacAddress(_) => PortIdSubtype::MacAddress,
            PortId::NetworkAddress(_) => PortIdSubtype::NetworkAddress,
            PortId::InterfaceName(_) => PortIdSubtype::InterfaceName,
            PortId::AgentCircuitId(_) => PortIdSubtype::AgentCircuitId,
            PortId::LocallyAssigned(_) => PortIdSubtype::LocallyAssigned,
        }
    }

    /// The length of the TLV value, which is the subtype octet plus the
    /// identifier.
    fn value_length(&self) -> u16 {
        let id_len = match self {
            PortId::InterfaceAlias(id)
            | PortId::PortComponent(id)
            | PortId::InterfaceName(id)
            | PortId::AgentCircuitId(id)
            | PortId::LocallyAssigned(id) => id.len(),
            PortId::MacAddress(_) => 6,
            PortId::NetworkAddress(address) => address.octet_len(),
        };
        // `IdOctets` caps the identifier at 255 octets and a network address at
        // 255, so the sum always fits in a `u16`.
        #[allow(clippy::cast_possible_truncation)] // bounded by 256
        {
            (1 + id_len) as u16
        }
    }
}

/// Errors which can occur while parsing a [`PortId`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum PortIdError {
    /// The TLV at this position was not a port ID TLV.
    #[error(transparent)]
    UnexpectedTlvType(#[from] UnexpectedTlvType),
    /// The TLV value did not even contain a subtype octet.
    #[error("port ID TLV carries no value")]
    Empty,
    /// The subtype is one the standard reserves.
    #[error(transparent)]
    ReservedSubtype(ReservedPortIdSubtype),
    /// A MAC address port ID was not six octets long.
    #[error("a MAC address port ID must be exactly 6 octets, found {0}")]
    InvalidMacLength(usize),
    /// A network address port ID could not be decoded.
    #[error(transparent)]
    NetworkAddress(NetworkAddressError),
    /// The identifier was empty or longer than the standard permits.
    #[error(transparent)]
    Id(OctetsError),
}

impl Parse for PortId {
    type Error = PortIdError;

    fn parse(buf: &[u8]) -> Result<(PortId, NonZero<u16>), ParseError<PortIdError>> {
        let (value, total) = split_tlv::<PortIdError>(buf, PortId::TLV_TYPE)?;
        let Some((&raw_subtype, id)) = value.split_first() else {
            return Err(ParseError::Invalid(PortIdError::Empty));
        };
        let subtype = PortIdSubtype::try_from(raw_subtype)
            .map_err(|e| ParseError::Invalid(PortIdError::ReservedSubtype(e)))?;
        let octets = || IdOctets::new(id).map_err(|e| ParseError::Invalid(PortIdError::Id(e)));
        let port_id = match subtype {
            PortIdSubtype::InterfaceAlias => PortId::InterfaceAlias(octets()?),
            PortIdSubtype::PortComponent => PortId::PortComponent(octets()?),
            PortIdSubtype::InterfaceName => PortId::InterfaceName(octets()?),
            PortIdSubtype::AgentCircuitId => PortId::AgentCircuitId(octets()?),
            PortIdSubtype::LocallyAssigned => PortId::LocallyAssigned(octets()?),
            PortIdSubtype::MacAddress => {
                let raw: [u8; 6] = id
                    .try_into()
                    .map_err(|_| ParseError::Invalid(PortIdError::InvalidMacLength(id.len())))?;
                PortId::MacAddress(Mac(raw))
            }
            PortIdSubtype::NetworkAddress => PortId::NetworkAddress(
                NetworkAddress::from_octets(id)
                    .map_err(|e| ParseError::Invalid(PortIdError::NetworkAddress(e)))?,
            ),
        };
        Ok((port_id, total))
    }
}

impl DeParse for PortId {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        TlvHeader::LENGTH.saturating_add(self.value_length())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        write_tlv(buf, PortId::TLV_TYPE, self.value_length(), |slot| {
            slot[0] = self.subtype().as_u8();
            match self {
                PortId::InterfaceAlias(id)
                | PortId::PortComponent(id)
                | PortId::InterfaceName(id)
                | PortId::AgentCircuitId(id)
                | PortId::LocallyAssigned(id) => slot[1..].copy_from_slice(id.as_bytes()),
                PortId::MacAddress(mac) => slot[1..].copy_from_slice(&mac.0),
                PortId::NetworkAddress(address) => address.write_octets(&mut slot[1..]),
            }
        })
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{PortId, PortIdSubtype};
    use crate::eth::mac::Mac;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for PortId {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            match u.produce::<u8>()? % 7 {
                0 => Some(PortId::InterfaceAlias(u.produce()?)),
                1 => Some(PortId::PortComponent(u.produce()?)),
                2 => Some(PortId::MacAddress(u.produce::<Mac>()?)),
                3 => Some(PortId::NetworkAddress(u.produce()?)),
                4 => Some(PortId::InterfaceName(u.produce()?)),
                5 => Some(PortId::AgentCircuitId(u.produce()?)),
                _ => Some(PortId::LocallyAssigned(u.produce()?)),
            }
        }
    }

    impl TypeGenerator for PortIdSubtype {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            PortIdSubtype::try_from((u.produce::<u8>()? % 7) + 1).ok()
        }
    }
}

/// The identifier's value; its subtype is what kind of value it is, which the value usually shows.
impl core::fmt::Display for PortId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PortId::InterfaceAlias(value)
            | PortId::PortComponent(value)
            | PortId::InterfaceName(value)
            | PortId::AgentCircuitId(value)
            | PortId::LocallyAssigned(value) => value.fmt(f),
            PortId::MacAddress(mac) => mac.fmt(f),
            PortId::NetworkAddress(address) => address.fmt(f),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{PortId, PortIdError, PortIdSubtype};
    use crate::eth::mac::Mac;
    use crate::lldp::chassis_id::IdOctets;
    use crate::lldp::tlv::{RawTlv, TlvType, TlvValue};
    use crate::parse::{DeParse, Parse, ParseError};

    fn deparse(port_id: &PortId) -> Vec<u8> {
        let mut buf = vec![0u8; port_id.size().get() as usize];
        let written = port_id.deparse(&mut buf).unwrap();
        assert_eq!(written, port_id.size());
        buf
    }

    #[test]
    fn round_trips() {
        bolero::check!().with_type().for_each(|port_id: &PortId| {
            let buf = deparse(port_id);
            let (parsed, consumed) = PortId::parse(&buf).unwrap();
            assert_eq!(&parsed, port_id);
            assert_eq!(consumed, port_id.size());
            assert_eq!(parsed.subtype(), port_id.subtype());
        });
    }

    #[test]
    fn parse_of_arbitrary_octets_is_byte_exact() {
        bolero::check!().with_type().for_each(|raw: &Vec<u8>| {
            let Ok((port_id, consumed)) = PortId::parse(raw) else {
                return;
            };
            assert_eq!(consumed, port_id.size());
            let written = deparse(&port_id);
            assert_eq!(&written[..], &raw[..consumed.get() as usize]);
        });
    }

    #[test]
    fn reserved_subtypes_are_rejected() {
        for raw_subtype in [0u8, 8, 100, 255] {
            let value = [raw_subtype, 0x01, 0x02];
            let tlv = RawTlv::new(TlvType::PORT_ID, TlvValue::new(&value).unwrap());
            let mut buf = vec![0u8; tlv.size().get() as usize];
            tlv.deparse(&mut buf).unwrap();
            match PortId::parse(&buf) {
                Err(ParseError::Invalid(PortIdError::ReservedSubtype(e))) => {
                    assert_eq!(e.0, raw_subtype);
                }
                other => unreachable!("expected a reserved subtype error, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_wrong_tlv_type_is_rejected() {
        let tlv = RawTlv::new(
            TlvType::CHASSIS_ID,
            TlvValue::new(&[3, 1, 2, 3, 4, 5, 6]).unwrap(),
        );
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        match PortId::parse(&buf) {
            Err(ParseError::Invalid(PortIdError::UnexpectedTlvType(e))) => {
                assert_eq!(e.expected, TlvType::PORT_ID);
                assert_eq!(e.found, TlvType::CHASSIS_ID);
            }
            other => unreachable!("expected a TLV type error, got {other:?}"),
        }
    }

    /// A MAC address is subtype 4 in a chassis ID but subtype 3 in a port ID.
    /// Getting this backwards is the obvious mistake, so pin it down.
    #[test]
    fn mac_address_is_subtype_three() {
        let mac = PortId::MacAddress(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]));
        assert_eq!(mac.subtype().as_u8(), 3);
        assert_eq!(
            deparse(&mac),
            vec![0x04, 0x07, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn known_encodings() {
        let name = PortId::InterfaceName(IdOctets::new(b"swp1").unwrap());
        assert_eq!(
            deparse(&name),
            vec![0x04, 0x05, 0x05, b's', b'w', b'p', b'1']
        );
    }

    #[test]
    fn every_subtype_round_trips_through_u8() {
        for subtype in [
            PortIdSubtype::InterfaceAlias,
            PortIdSubtype::PortComponent,
            PortIdSubtype::MacAddress,
            PortIdSubtype::NetworkAddress,
            PortIdSubtype::InterfaceName,
            PortIdSubtype::AgentCircuitId,
            PortIdSubtype::LocallyAssigned,
        ] {
            assert_eq!(PortIdSubtype::try_from(subtype.as_u8()).unwrap(), subtype);
        }
    }

    #[test]
    fn deparse_into_insufficient_buffer_fails_gracefully() {
        bolero::check!().with_type().for_each(|port_id: &PortId| {
            let mut buf = vec![0u8; port_id.size().get() as usize - 1];
            assert!(port_id.deparse(&mut buf).is_err());
        });
    }
}
