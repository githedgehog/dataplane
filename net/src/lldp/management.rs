// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The management address TLV, which advertises an address a neighbour can use
//! to manage the sending station, and the interface that address is reached
//! through.

use core::num::NonZero;

use crate::lldp::address::{NetworkAddress, NetworkAddressError};
use crate::lldp::octets::{Octets, OctetsError};
use crate::lldp::tlv::{TlvHeader, TlvType, UnexpectedTlvType, split_tlv, write_tlv};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};

/// The BER encoded object identifier of the MIB object which describes the
/// interface a management address is reached through.
///
/// This library does not interpret the encoding; it bounds and preserves it.
pub type ObjectIdentifier = Octets<0, 128>;

/// What the interface number in a management address TLV counts.
///
/// Subtype 0 and subtypes 4 through 255 are reserved by the standard, so they
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
pub enum InterfaceNumbering {
    /// The interface is not known, and the interface number carries no meaning.
    Unknown = 1,
    /// An `ifIndex`, as defined by RFC 2863.
    IfIndex = 2,
    /// A system port number.
    SystemPortNumber = 3,
}

impl InterfaceNumbering {
    /// The raw value of this subtype.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for InterfaceNumbering {
    type Error = ReservedInterfaceNumbering;

    fn try_from(value: u8) -> Result<InterfaceNumbering, ReservedInterfaceNumbering> {
        match value {
            1 => Ok(InterfaceNumbering::Unknown),
            2 => Ok(InterfaceNumbering::IfIndex),
            3 => Ok(InterfaceNumbering::SystemPortNumber),
            other => Err(ReservedInterfaceNumbering(other)),
        }
    }
}

/// The error returned when an interface numbering subtype is one the standard
/// reserves.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("interface numbering subtype {0} is reserved")]
pub struct ReservedInterfaceNumbering(pub u8);

/// The interface a management address is reached through.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct InterfaceNumber {
    numbering: InterfaceNumbering,
    number: u32,
}

impl InterfaceNumber {
    /// The number of octets an interface number occupies: one for the
    /// numbering subtype and four for the number itself.
    pub const OCTET_LEN: usize = 5;

    /// Build an interface number.
    #[must_use]
    pub const fn new(numbering: InterfaceNumbering, number: u32) -> InterfaceNumber {
        InterfaceNumber { numbering, number }
    }

    /// An interface number which says nothing.
    #[must_use]
    pub const fn unknown() -> InterfaceNumber {
        InterfaceNumber::new(InterfaceNumbering::Unknown, 0)
    }

    /// What this number counts.
    #[must_use]
    pub const fn numbering(self) -> InterfaceNumbering {
        self.numbering
    }

    /// The number itself.
    #[must_use]
    pub const fn number(self) -> u32 {
        self.number
    }
}

/// The management address TLV.
///
/// # Layout
///
/// ```text
/// +--------+---------+---------+-----------+--------+--------+-----+
/// | addr   | address | address | interface | if     | OID    | OID |
/// | strlen | subtype |         | numbering | number | length |     |
/// | 1      | 1       | 1..=31  | 1         | 4      | 1      | 0.. |
/// +--------+---------+---------+-----------+--------+--------+-----+
/// ```
///
/// The address subtype and address together are exactly the encoding
/// [`NetworkAddress`] models, so that is what this type stores.  The leading
/// length is derived on write rather than stored, which is what keeps it from
/// disagreeing with the address it describes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
pub struct ManagementAddress {
    address: NetworkAddress,
    interface: InterfaceNumber,
    object_identifier: ObjectIdentifier,
}

impl ManagementAddress {
    /// The TLV type of a management address.
    pub const TLV_TYPE: TlvType = TlvType::MANAGEMENT_ADDRESS;

    /// The fewest octets the address string may occupy: a subtype and a one
    /// octet address.
    pub const MIN_ADDRESS_STRING_LEN: usize = 2;

    /// The most octets the address string may occupy: a subtype and a 31 octet
    /// address.
    pub const MAX_ADDRESS_STRING_LEN: usize = 32;

    /// Build a management address TLV.
    ///
    /// # Errors
    ///
    /// Returns [`AddressTooLong`] if `address` needs more octets than the
    /// standard allots it.  IPv4 and IPv6 addresses always fit; only an address
    /// in an unrecognized family can be too long.
    pub fn new(
        address: NetworkAddress,
        interface: InterfaceNumber,
        object_identifier: ObjectIdentifier,
    ) -> Result<ManagementAddress, AddressTooLong> {
        let len = address.octet_len();
        if len > ManagementAddress::MAX_ADDRESS_STRING_LEN {
            return Err(AddressTooLong {
                len,
                max: ManagementAddress::MAX_ADDRESS_STRING_LEN,
            });
        }
        Ok(ManagementAddress {
            address,
            interface,
            object_identifier,
        })
    }

    /// The address at which the sending station may be managed.
    #[must_use]
    pub const fn address(&self) -> &NetworkAddress {
        &self.address
    }

    /// The interface that address is reached through.
    #[must_use]
    pub const fn interface(&self) -> InterfaceNumber {
        self.interface
    }

    /// The object identifier of the MIB object describing that interface.
    #[must_use]
    pub const fn object_identifier(&self) -> &ObjectIdentifier {
        &self.object_identifier
    }

    /// The length of the TLV value.
    ///
    /// Bounded by 1 + 32 + 5 + 1 + 128 = 167, comfortably inside the 511 octet
    /// limit a TLV length field can express.
    fn value_length(&self) -> u16 {
        let len = 1
            + self.address.octet_len()
            + InterfaceNumber::OCTET_LEN
            + 1
            + self.object_identifier.len();
        #[allow(clippy::cast_possible_truncation)] // bounded by 167
        {
            len as u16
        }
    }
}

/// Deserialization goes through the derived shape and then
/// [`ManagementAddress::new`], so an address longer than the standard allots
/// cannot be smuggled past the bound that keeps the TLV serializable.
impl<'de> serde::Deserialize<'de> for ManagementAddress {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ManagementAddress, D::Error> {
        let unchecked = ManagementAddress::deserialize(deserializer)?;
        ManagementAddress::new(
            unchecked.address,
            unchecked.interface,
            unchecked.object_identifier,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for ManagementAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ManagementAddress::serialize(self, serializer)
    }
}

/// The error returned when a management address needs more octets than the
/// standard allots it.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
#[error("a management address string of {len} octets is too long (max {max})")]
pub struct AddressTooLong {
    /// The number of octets the address string would have occupied.
    pub len: usize,
    /// The largest address string the standard permits.
    pub max: usize,
}

/// Errors which can occur while parsing a [`ManagementAddress`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ManagementAddressError {
    /// The TLV at this position was not a management address TLV.
    #[error(transparent)]
    UnexpectedTlvType(#[from] UnexpectedTlvType),
    /// The TLV value ended before a field this TLV requires.
    #[error("management address TLV is truncated: {0} octets is not enough for its {1} field")]
    Truncated(usize, &'static str),
    /// The leading address string length was outside the permitted range.
    #[error("management address string length {0} is outside {min}..={max}",
        min = ManagementAddress::MIN_ADDRESS_STRING_LEN,
        max = ManagementAddress::MAX_ADDRESS_STRING_LEN)]
    InvalidAddressStringLength(usize),
    /// The address itself could not be decoded.
    #[error(transparent)]
    Address(NetworkAddressError),
    /// The interface numbering subtype is one the standard reserves.
    #[error(transparent)]
    ReservedInterfaceNumbering(ReservedInterfaceNumbering),
    /// The object identifier was longer than the standard permits.
    #[error(transparent)]
    ObjectIdentifier(OctetsError),
    /// The TLV value carried octets past the end of the object identifier.
    #[error("management address TLV has {0} unaccounted octets after its object identifier")]
    TrailingOctets(usize),
}

impl Parse for ManagementAddress {
    type Error = ManagementAddressError;

    fn parse(
        buf: &[u8],
    ) -> Result<(ManagementAddress, NonZero<u16>), ParseError<ManagementAddressError>> {
        let (value, total) = split_tlv::<ManagementAddressError>(buf, ManagementAddress::TLV_TYPE)?;
        let invalid = ManagementAddressError::Truncated;

        let Some((&raw_string_len, rest)) = value.split_first() else {
            return Err(ParseError::Invalid(invalid(0, "address string length")));
        };
        let string_len = usize::from(raw_string_len);
        if !(ManagementAddress::MIN_ADDRESS_STRING_LEN..=ManagementAddress::MAX_ADDRESS_STRING_LEN)
            .contains(&string_len)
        {
            return Err(ParseError::Invalid(
                ManagementAddressError::InvalidAddressStringLength(string_len),
            ));
        }
        let Some(address_octets) = rest.get(..string_len) else {
            return Err(ParseError::Invalid(invalid(rest.len(), "address")));
        };
        let address = NetworkAddress::from_octets(address_octets)
            .map_err(|e| ParseError::Invalid(ManagementAddressError::Address(e)))?;

        let rest = &rest[string_len..];
        let Some(interface_octets) = rest.get(..InterfaceNumber::OCTET_LEN) else {
            return Err(ParseError::Invalid(invalid(rest.len(), "interface number")));
        };
        let numbering = InterfaceNumbering::try_from(interface_octets[0]).map_err(|e| {
            ParseError::Invalid(ManagementAddressError::ReservedInterfaceNumbering(e))
        })?;
        let number = u32::from_be_bytes(
            interface_octets[1..]
                .try_into()
                .unwrap_or_else(|e| unreachable!("slice is exactly four octets: {e:?}")),
        );

        let rest = &rest[InterfaceNumber::OCTET_LEN..];
        let Some((&raw_oid_len, rest)) = rest.split_first() else {
            return Err(ParseError::Invalid(invalid(0, "object identifier length")));
        };
        let oid_len = usize::from(raw_oid_len);
        let Some(oid_octets) = rest.get(..oid_len) else {
            return Err(ParseError::Invalid(invalid(
                rest.len(),
                "object identifier",
            )));
        };
        let object_identifier = ObjectIdentifier::new(oid_octets)
            .map_err(|e| ParseError::Invalid(ManagementAddressError::ObjectIdentifier(e)))?;

        let trailing = rest.len() - oid_len;
        if trailing != 0 {
            return Err(ParseError::Invalid(ManagementAddressError::TrailingOctets(
                trailing,
            )));
        }

        // The address string length was range checked above, so the only way
        // `new` could refuse this is if the check disagreed with itself.
        let management_address = ManagementAddress::new(
            address,
            InterfaceNumber::new(numbering, number),
            object_identifier,
        )
        .unwrap_or_else(|e| unreachable!("address string length was range checked: {e:?}"));
        Ok((management_address, total))
    }
}

impl DeParse for ManagementAddress {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        TlvHeader::LENGTH.saturating_add(self.value_length())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        write_tlv(
            buf,
            ManagementAddress::TLV_TYPE,
            self.value_length(),
            |slot| {
                let address_len = self.address.octet_len();
                // Bounded by `MAX_ADDRESS_STRING_LEN`, checked in `new`.
                #[allow(clippy::cast_possible_truncation)] // bounded by 32
                {
                    slot[0] = address_len as u8;
                }
                self.address.write_octets(&mut slot[1..=address_len]);

                let interface = &mut slot[1 + address_len..1 + address_len + 5];
                interface[0] = self.interface.numbering.as_u8();
                interface[1..].copy_from_slice(&self.interface.number.to_be_bytes());

                let oid = self.object_identifier.as_bytes();
                // Bounded by `ObjectIdentifier::MAX_LEN`.
                #[allow(clippy::cast_possible_truncation)] // bounded by 128
                {
                    slot[6 + address_len] = oid.len() as u8;
                }
                slot[7 + address_len..].copy_from_slice(oid);
            },
        )
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{InterfaceNumber, InterfaceNumbering, ManagementAddress};
    use crate::lldp::address::NetworkAddress;
    use bolero::{Driver, TypeGenerator};
    use core::net::{Ipv4Addr, Ipv6Addr};

    impl TypeGenerator for InterfaceNumbering {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            InterfaceNumbering::try_from((u.produce::<u8>()? % 3) + 1).ok()
        }
    }

    impl TypeGenerator for InterfaceNumber {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            Some(InterfaceNumber::new(u.produce()?, u.produce()?))
        }
    }

    impl TypeGenerator for ManagementAddress {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            // A management address is bounded far more tightly than a chassis
            // ID, so generate an address which is guaranteed to fit rather than
            // discarding most of what a bare `NetworkAddress` would produce.
            let address = match u.produce::<u8>()? % 3 {
                0 => NetworkAddress::Ipv4(Ipv4Addr::from(u.produce::<[u8; 4]>()?)),
                1 => NetworkAddress::Ipv6(Ipv6Addr::from(u.produce::<[u8; 16]>()?)),
                _ => {
                    let mut other: NetworkAddress = u.produce()?;
                    if other.octet_len() > ManagementAddress::MAX_ADDRESS_STRING_LEN {
                        other = NetworkAddress::Ipv4(Ipv4Addr::from(u.produce::<[u8; 4]>()?));
                    }
                    other
                }
            };
            ManagementAddress::new(address, u.produce()?, u.produce()?).ok()
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        InterfaceNumber, InterfaceNumbering, ManagementAddress, ManagementAddressError,
        ObjectIdentifier,
    };
    use crate::lldp::address::{AddressOctets, NetworkAddress, OtherNetworkAddress};
    use crate::lldp::tlv::{RawTlv, TlvType, TlvValue};
    use crate::parse::{DeParse, Parse, ParseError};

    fn deparse(address: &ManagementAddress) -> Vec<u8> {
        let mut buf = vec![0u8; address.size().get() as usize];
        let written = address.deparse(&mut buf).unwrap();
        assert_eq!(written, address.size());
        buf
    }

    fn tlv_bytes(value: &[u8]) -> Vec<u8> {
        let tlv = RawTlv::new(TlvType::MANAGEMENT_ADDRESS, TlvValue::new(value).unwrap());
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        buf
    }

    #[test]
    fn round_trips() {
        bolero::check!()
            .with_type()
            .for_each(|address: &ManagementAddress| {
                let buf = deparse(address);
                let (parsed, consumed) = ManagementAddress::parse(&buf).unwrap();
                assert_eq!(&parsed, address);
                assert_eq!(consumed, address.size());
            });
    }

    #[test]
    fn parse_of_arbitrary_octets_is_byte_exact() {
        bolero::check!().with_type().for_each(|raw: &Vec<u8>| {
            let Ok((address, consumed)) = ManagementAddress::parse(raw) else {
                return;
            };
            assert_eq!(consumed, address.size());
            assert_eq!(&deparse(&address)[..], &raw[..consumed.get() as usize]);
        });
    }

    #[test]
    fn an_ipv4_management_address_encodes_as_expected() {
        let address = ManagementAddress::new(
            NetworkAddress::Ipv4([192, 0, 2, 1].into()),
            InterfaceNumber::new(InterfaceNumbering::IfIndex, 7),
            ObjectIdentifier::new(&[]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            deparse(&address),
            vec![
                0x10, 0x0c, // type 8, length 12
                0x05, // address string length: subtype plus four octets
                0x01, 192, 0, 2, 1, // IPv4
                0x02, 0x00, 0x00, 0x00, 0x07, // ifIndex 7
                0x00, // no object identifier
            ]
        );
    }

    #[test]
    fn an_over_long_address_is_refused_at_construction() {
        let long = AddressOctets::new(&[0xab; 64]).unwrap();
        let address = NetworkAddress::Other(OtherNetworkAddress::new(99, long).unwrap());
        let error = ManagementAddress::new(
            address,
            InterfaceNumber::unknown(),
            ObjectIdentifier::new(&[]).unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.len, 65);
        assert_eq!(error.max, 32);
    }

    #[test]
    fn an_out_of_range_address_string_length_is_rejected() {
        for bad in [0u8, 1, 33, 255] {
            let buf = tlv_bytes(&[bad, 0x01, 192, 0, 2, 1, 0x02, 0, 0, 0, 1, 0]);
            match ManagementAddress::parse(&buf) {
                Err(ParseError::Invalid(ManagementAddressError::InvalidAddressStringLength(
                    found,
                ))) => assert_eq!(found, usize::from(bad)),
                other => unreachable!("expected a length error for {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_reserved_interface_numbering_is_rejected() {
        for bad in [0u8, 4, 255] {
            let buf = tlv_bytes(&[0x05, 0x01, 192, 0, 2, 1, bad, 0, 0, 0, 1, 0]);
            match ManagementAddress::parse(&buf) {
                Err(ParseError::Invalid(ManagementAddressError::ReservedInterfaceNumbering(e))) => {
                    assert_eq!(e.0, bad);
                }
                other => unreachable!("expected a numbering error for {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn trailing_octets_are_rejected() {
        let buf = tlv_bytes(&[0x05, 0x01, 192, 0, 2, 1, 0x02, 0, 0, 0, 1, 0, 0xff, 0xff]);
        match ManagementAddress::parse(&buf) {
            Err(ParseError::Invalid(ManagementAddressError::TrailingOctets(found))) => {
                assert_eq!(found, 2);
            }
            other => unreachable!("expected trailing octets, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_object_identifier_is_rejected() {
        let buf = tlv_bytes(&[0x05, 0x01, 192, 0, 2, 1, 0x02, 0, 0, 0, 1, 4, 0xaa]);
        match ManagementAddress::parse(&buf) {
            Err(ParseError::Invalid(ManagementAddressError::Truncated(found, field))) => {
                assert_eq!(found, 1);
                assert_eq!(field, "object identifier");
            }
            other => unreachable!("expected a truncation error, got {other:?}"),
        }
    }

    #[test]
    fn deparse_into_insufficient_buffer_fails_gracefully() {
        bolero::check!()
            .with_type()
            .for_each(|address: &ManagementAddress| {
                let mut buf = vec![0u8; address.size().get() as usize - 1];
                assert!(address.deparse(&mut buf).is_err());
            });
    }
}
