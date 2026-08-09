// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The system capabilities TLV, which says what functions a station is built
//! to perform and which of them are switched on.

use bitflags::bitflags;
use core::num::NonZero;

use crate::lldp::tlv::{TlvHeader, TlvType, UnexpectedTlvType, split_tlv, write_tlv};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};

bitflags! {
    /// The functions a station can perform, as a bitmap.
    ///
    /// Bits 11 through 15 are reserved.  They are preserved rather than masked
    /// away, both so that a capabilities TLV survives a parse and deparse cycle
    /// unchanged and so that a future revision of the standard which assigns
    /// them does not silently lose information here.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct SystemCapability: u16 {
        /// Some function not covered by another bit.
        const OTHER = 1 << 0;
        /// A repeater, as defined by IEEE Std 802.3 clause 9.
        const REPEATER = 1 << 1;
        /// A MAC bridge, as defined by IEEE Std 802.1Q.
        const BRIDGE = 1 << 2;
        /// A WLAN access point, as defined by IEEE Std 802.11.
        const WLAN_ACCESS_POINT = 1 << 3;
        /// A router, as defined by RFC 1812.
        const ROUTER = 1 << 4;
        /// A telephone, as defined by ITU-T Q.931.
        const TELEPHONE = 1 << 5;
        /// A DOCSIS cable device.
        const DOCSIS_CABLE_DEVICE = 1 << 6;
        /// A station which does not forward, as defined by IEEE Std 802.1AB.
        const STATION_ONLY = 1 << 7;
        /// The C-VLAN component of a VLAN bridge.
        const C_VLAN_COMPONENT = 1 << 8;
        /// The S-VLAN component of a VLAN bridge.
        const S_VLAN_COMPONENT = 1 << 9;
        /// A two-port MAC relay.
        const TWO_PORT_MAC_RELAY = 1 << 10;
    }
}

/// The system capabilities TLV.
///
/// Two bitmaps: the functions the station is capable of, and the subset of
/// those which are currently enabled.
///
/// # Consistency
///
/// [IEEE Std 802.1AB] describes the enabled set as a subset of the supported
/// set, but that is a statement about well behaved senders rather than a rule
/// this parser can usefully enforce: rejecting a whole LLDPDU because a
/// neighbour's firmware sets a stray enabled bit would lose information rather
/// than protect anything.  The relationship is exposed as a query,
/// [`SystemCapabilities::is_consistent`], instead.
///
/// [IEEE Std 802.1AB]: https://standards.ieee.org/ieee/802.1AB/6047/
#[derive(
    Copy, Clone, Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct SystemCapabilities {
    supported: SystemCapability,
    enabled: SystemCapability,
}

impl SystemCapabilities {
    /// The TLV type of a system capabilities TLV.
    pub const TLV_TYPE: TlvType = TlvType::SYSTEM_CAPABILITIES;

    /// The length of a system capabilities TLV value: two bitmaps of two octets
    /// each.
    pub const VALUE_LENGTH: u16 = 4;

    /// Build a system capabilities TLV.
    #[must_use]
    pub const fn new(supported: SystemCapability, enabled: SystemCapability) -> SystemCapabilities {
        SystemCapabilities { supported, enabled }
    }

    /// The functions this station is capable of.
    #[must_use]
    pub const fn supported(self) -> SystemCapability {
        self.supported
    }

    /// The functions this station currently has enabled.
    #[must_use]
    pub const fn enabled(self) -> SystemCapability {
        self.enabled
    }

    /// True if every enabled capability is also a supported one.
    ///
    /// See the note on the type; this is a property of the sender, not an
    /// invariant of this type.
    #[must_use]
    pub fn is_consistent(self) -> bool {
        self.supported.contains(self.enabled)
    }
}

/// Serialized as the raw bitmap, which is what the wire carries and what keeps
/// the reserved bits intact.  Every `u16` is a legal value, so there is nothing
/// to reject on the way back in.
impl serde::Serialize for SystemCapability {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u16(self.bits())
    }
}

impl<'de> serde::Deserialize<'de> for SystemCapability {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<SystemCapability, D::Error> {
        Ok(SystemCapability::from_bits_retain(
            serde::Deserialize::deserialize(deserializer)?,
        ))
    }
}

/// Errors which can occur while parsing a [`SystemCapabilities`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SystemCapabilitiesError {
    /// The TLV at this position was not a system capabilities TLV.
    #[error(transparent)]
    UnexpectedTlvType(#[from] UnexpectedTlvType),
    /// A system capabilities TLV carried something other than four octets.
    #[error(
        "a system capabilities TLV must carry exactly {expected} octets, found {0}",
        expected = SystemCapabilities::VALUE_LENGTH
    )]
    InvalidValueLength(u16),
}

impl Parse for SystemCapabilities {
    type Error = SystemCapabilitiesError;

    fn parse(
        buf: &[u8],
    ) -> Result<(SystemCapabilities, NonZero<u16>), ParseError<SystemCapabilitiesError>> {
        let (value, total) =
            split_tlv::<SystemCapabilitiesError>(buf, SystemCapabilities::TLV_TYPE)?;
        let raw: [u8; 4] = value.try_into().map_err(|_| {
            // A TLV length field is nine bits, so this always fits in a `u16`.
            #[allow(clippy::cast_possible_truncation)] // bounded by 511
            ParseError::Invalid(SystemCapabilitiesError::InvalidValueLength(
                value.len() as u16
            ))
        })?;
        Ok((
            SystemCapabilities {
                supported: SystemCapability::from_bits_retain(u16::from_be_bytes([raw[0], raw[1]])),
                enabled: SystemCapability::from_bits_retain(u16::from_be_bytes([raw[2], raw[3]])),
            },
            total,
        ))
    }
}

impl DeParse for SystemCapabilities {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        TlvHeader::LENGTH.saturating_add(SystemCapabilities::VALUE_LENGTH)
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        write_tlv(
            buf,
            SystemCapabilities::TLV_TYPE,
            SystemCapabilities::VALUE_LENGTH,
            |slot| {
                slot[..2].copy_from_slice(&self.supported.bits().to_be_bytes());
                slot[2..].copy_from_slice(&self.enabled.bits().to_be_bytes());
            },
        )
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{SystemCapabilities, SystemCapability};
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for SystemCapability {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            // `from_bits_retain` keeps the reserved bits, which is what the
            // parser does, so every `u16` is a legal value.
            Some(SystemCapability::from_bits_retain(u.produce()?))
        }
    }

    impl TypeGenerator for SystemCapabilities {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            Some(SystemCapabilities::new(u.produce()?, u.produce()?))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{SystemCapabilities, SystemCapabilitiesError, SystemCapability};
    use crate::lldp::tlv::{RawTlv, TlvType, TlvValue};
    use crate::parse::{DeParse, Parse, ParseError};

    fn deparse(capabilities: SystemCapabilities) -> Vec<u8> {
        let mut buf = vec![0u8; capabilities.size().get() as usize];
        let written = capabilities.deparse(&mut buf).unwrap();
        assert_eq!(written, capabilities.size());
        buf
    }

    #[test]
    fn round_trips() {
        bolero::check!()
            .with_type()
            .for_each(|capabilities: &SystemCapabilities| {
                let buf = deparse(*capabilities);
                let (parsed, consumed) = SystemCapabilities::parse(&buf).unwrap();
                assert_eq!(&parsed, capabilities);
                assert_eq!(consumed, capabilities.size());
            });
    }

    #[test]
    fn parse_of_arbitrary_octets_is_byte_exact() {
        bolero::check!().with_type().for_each(|raw: &Vec<u8>| {
            let Ok((capabilities, consumed)) = SystemCapabilities::parse(raw) else {
                return;
            };
            assert_eq!(consumed, capabilities.size());
            assert_eq!(&deparse(capabilities)[..], &raw[..consumed.get() as usize]);
        });
    }

    /// The reserved bits have to survive, or a station which sets one would see
    /// its TLV silently rewritten by anything that reads and re-emits it.
    #[test]
    fn reserved_bits_are_preserved() {
        let reserved = SystemCapability::from_bits_retain(0xf800);
        let capabilities = SystemCapabilities::new(reserved, reserved);
        let buf = deparse(capabilities);
        assert_eq!(buf, vec![0x0e, 0x04, 0xf8, 0x00, 0xf8, 0x00]);
        let (parsed, _) = SystemCapabilities::parse(&buf).unwrap();
        assert_eq!(parsed.supported().bits(), 0xf800);
    }

    #[test]
    fn a_bridging_router_encodes_as_expected() {
        let capabilities = SystemCapabilities::new(
            SystemCapability::BRIDGE | SystemCapability::ROUTER,
            SystemCapability::ROUTER,
        );
        assert_eq!(
            deparse(capabilities),
            vec![0x0e, 0x04, 0x00, 0x14, 0x00, 0x10]
        );
        assert!(capabilities.is_consistent());
    }

    #[test]
    fn enabled_without_supported_is_inconsistent_but_accepted() {
        let capabilities =
            SystemCapabilities::new(SystemCapability::BRIDGE, SystemCapability::ROUTER);
        assert!(!capabilities.is_consistent());
        let buf = deparse(capabilities);
        let (parsed, _) = SystemCapabilities::parse(&buf).unwrap();
        assert_eq!(parsed, capabilities);
    }

    #[test]
    fn a_value_of_the_wrong_length_is_rejected() {
        for length in [0usize, 2, 3, 5, 8] {
            let value = vec![0u8; length];
            let tlv = RawTlv::new(TlvType::SYSTEM_CAPABILITIES, TlvValue::new(&value).unwrap());
            let mut buf = vec![0u8; tlv.size().get() as usize];
            tlv.deparse(&mut buf).unwrap();
            match SystemCapabilities::parse(&buf) {
                Err(ParseError::Invalid(SystemCapabilitiesError::InvalidValueLength(found))) => {
                    assert_eq!(usize::from(found), length);
                }
                other => unreachable!("expected a length error for {length}, got {other:?}"),
            }
        }
    }
}
