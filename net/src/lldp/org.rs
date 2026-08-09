// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The organizationally specific TLV, and the IEEE 802.1 and IEEE 802.3
//! extensions carried inside it.
//!
//! TLV type 127 is the extension point of LLDP.  Its value begins with a three
//! octet [OUI] naming the organization which defined the rest, followed by a
//! one octet subtype naming which of that organization's TLVs this is.
//!
//! [OUI]: https://standards.ieee.org/products-programs/regauth/oui/

use bitflags::bitflags;
use core::fmt::{Display, Formatter};
use core::num::NonZero;

use crate::lldp::octets::{Octets, OctetsError};
use crate::lldp::tlv::{TlvHeader, TlvType, UnexpectedTlvType, split_tlv, write_tlv};
use crate::parse::{DeParse, DeParseError, Parse, ParseError};
use crate::vlan::Vid;

/// The payload of an organizationally specific TLV whose meaning this library
/// does not model.
///
/// A TLV value is at most 511 octets, of which the OUI and subtype claim four.
pub type OrgInfo = Octets<0, 507>;

/// The name of a VLAN, as carried in an IEEE 802.1 VLAN name TLV.
pub type VlanNameOctets = Octets<0, 32>;

/// An [IEEE Organizationally Unique Identifier][oui].
///
/// [oui]: https://standards.ieee.org/products-programs/regauth/oui/
#[repr(transparent)]
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct Oui(pub [u8; 3]);

impl Oui {
    /// The OUI under which IEEE Std 802.1 defines its LLDP extensions.
    pub const IEEE_802_1: Oui = Oui([0x00, 0x80, 0xc2]);

    /// The OUI under which IEEE Std 802.3 defines its LLDP extensions.
    pub const IEEE_802_3: Oui = Oui([0x00, 0x12, 0x0f]);

    /// The three octets of this OUI, in wire order.
    #[must_use]
    pub const fn octets(self) -> [u8; 3] {
        self.0
    }

    /// True if this library models the TLVs defined under this OUI.
    #[must_use]
    pub const fn is_modelled(self) -> bool {
        matches!(self, Oui::IEEE_802_1 | Oui::IEEE_802_3)
    }
}

impl Display for Oui {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let [a, b, c] = self.0;
        write!(f, "{a:02x}-{b:02x}-{c:02x}")
    }
}

/// A VLAN identifier as it appears in an IEEE 802.1 LLDP extension.
///
/// This is deliberately not a [`Vid`].  A `Vid` is a VLAN a frame can actually
/// be tagged with, whereas this field is an advertisement which also has to
/// carry zero, meaning "no port VLAN is configured", and which a neighbour may
/// populate with a reserved value.  Rejecting those would discard information
/// the receiver asked for; [`VlanId::vid`] is the way to ask for the stricter
/// type.
#[repr(transparent)]
#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct VlanId(u16);

impl VlanId {
    /// The number of octets a VLAN identifier occupies.
    pub const OCTET_LEN: usize = 2;

    /// The advertisement which says no port VLAN is configured.
    pub const NONE: VlanId = VlanId(0);

    /// Build a VLAN identifier from its raw value.
    #[must_use]
    pub const fn new(raw: u16) -> VlanId {
        VlanId(raw)
    }

    /// The raw value of this VLAN identifier.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// This identifier as a [`Vid`], if it is one.
    ///
    /// Returns `None` for zero, for the reserved identifier, and for values
    /// beyond the 12 bit VLAN identifier range.
    #[must_use]
    pub fn vid(self) -> Option<Vid> {
        Vid::new(self.0).ok()
    }
}

impl From<Vid> for VlanId {
    fn from(value: Vid) -> VlanId {
        VlanId(value.as_u16())
    }
}

bitflags! {
    /// The link aggregation state of a port, as a bitmap.
    ///
    /// Bits 2 through 7 are reserved, and are preserved rather than masked
    /// away so that the TLV survives a parse and deparse cycle unchanged.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub struct LinkAggregationStatus: u8 {
        /// The port is capable of being aggregated.
        const CAPABLE = 1 << 0;
        /// The port is currently part of an aggregation.
        const AGGREGATED = 1 << 1;
    }
}

/// Serialized as the raw bitmap, which keeps the reserved bits intact.  Every
/// `u8` is a legal value, so there is nothing to reject on the way back in.
impl serde::Serialize for LinkAggregationStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.bits())
    }
}

impl<'de> serde::Deserialize<'de> for LinkAggregationStatus {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<LinkAggregationStatus, D::Error> {
        Ok(LinkAggregationStatus::from_bits_retain(
            serde::Deserialize::deserialize(deserializer)?,
        ))
    }
}

/// The TLVs IEEE Std 802.1 defines under [`Oui::IEEE_802_1`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
pub enum Dot1Tlv {
    /// The port VLAN identifier (subtype 1): the VLAN untagged frames arriving
    /// on this port are assigned to.
    PortVlanId(VlanId),
    /// A VLAN name (subtype 3): the administrative name of a VLAN the port
    /// participates in.
    VlanName {
        /// The VLAN being named.
        vlan_id: VlanId,
        /// The name of that VLAN.
        name: VlanNameOctets,
    },
    /// A subtype this library does not model.
    ///
    /// Build one with [`Dot1Tlv::other`], which refuses the subtypes that have
    /// a dedicated variant.
    #[non_exhaustive]
    Other {
        /// The IEEE 802.1 subtype.
        subtype: u8,
        /// The octets which follow the subtype.
        info: OrgInfo,
    },
}

impl Dot1Tlv {
    /// The subtype of an IEEE 802.1 port VLAN ID TLV.
    pub const PORT_VLAN_ID: u8 = 1;
    /// The subtype of an IEEE 802.1 VLAN name TLV.
    pub const VLAN_NAME: u8 = 3;

    /// Build an IEEE 802.1 TLV of a subtype this library does not model.
    ///
    /// # Errors
    ///
    /// Returns [`ModelledOrgTlv`] if `subtype` is one with a dedicated variant.
    /// Allowing it here would give the same octets two representations, only
    /// one of which the parser produces.
    pub fn other(subtype: u8, info: OrgInfo) -> Result<Dot1Tlv, ModelledOrgTlv> {
        if matches!(subtype, Dot1Tlv::PORT_VLAN_ID | Dot1Tlv::VLAN_NAME) {
            return Err(ModelledOrgTlv::Subtype {
                oui: Oui::IEEE_802_1,
                subtype,
            });
        }
        Ok(Dot1Tlv::Other { subtype, info })
    }

    /// The IEEE 802.1 subtype of this TLV.
    #[must_use]
    pub const fn subtype(&self) -> u8 {
        match self {
            Dot1Tlv::PortVlanId(_) => Dot1Tlv::PORT_VLAN_ID,
            Dot1Tlv::VlanName { .. } => Dot1Tlv::VLAN_NAME,
            Dot1Tlv::Other { subtype, .. } => *subtype,
        }
    }

    /// The number of octets which follow the subtype.
    fn info_len(&self) -> usize {
        match self {
            Dot1Tlv::PortVlanId(_) => VlanId::OCTET_LEN,
            Dot1Tlv::VlanName { name, .. } => VlanId::OCTET_LEN + 1 + name.len(),
            Dot1Tlv::Other { info, .. } => info.len(),
        }
    }

    fn write_info(&self, buf: &mut [u8]) {
        match self {
            Dot1Tlv::PortVlanId(vlan_id) => buf.copy_from_slice(&vlan_id.0.to_be_bytes()),
            Dot1Tlv::VlanName { vlan_id, name } => {
                buf[..2].copy_from_slice(&vlan_id.0.to_be_bytes());
                // `VlanNameOctets` caps the name at 32 octets.
                #[allow(clippy::cast_possible_truncation)] // bounded by 32
                {
                    buf[2] = name.len() as u8;
                }
                buf[3..].copy_from_slice(name.as_bytes());
            }
            Dot1Tlv::Other { info, .. } => buf.copy_from_slice(info.as_bytes()),
        }
    }

    fn from_info(subtype: u8, info: &[u8]) -> Result<Dot1Tlv, OrgTlvError> {
        match subtype {
            Dot1Tlv::PORT_VLAN_ID => {
                let raw: [u8; 2] = info
                    .try_into()
                    .map_err(|_| OrgTlvError::InvalidInfoLength {
                        oui: Oui::IEEE_802_1,
                        subtype,
                        found: info.len(),
                    })?;
                Ok(Dot1Tlv::PortVlanId(VlanId(u16::from_be_bytes(raw))))
            }
            Dot1Tlv::VLAN_NAME => {
                let [high, low, name_len, name @ ..] = info else {
                    return Err(OrgTlvError::InvalidInfoLength {
                        oui: Oui::IEEE_802_1,
                        subtype,
                        found: info.len(),
                    });
                };
                if usize::from(*name_len) != name.len() {
                    return Err(OrgTlvError::VlanNameLengthMismatch {
                        declared: usize::from(*name_len),
                        found: name.len(),
                    });
                }
                Ok(Dot1Tlv::VlanName {
                    vlan_id: VlanId(u16::from_be_bytes([*high, *low])),
                    name: VlanNameOctets::new(name).map_err(OrgTlvError::Info)?,
                })
            }
            other => Ok(Dot1Tlv::Other {
                subtype: other,
                info: OrgInfo::new(info).map_err(OrgTlvError::Info)?,
            }),
        }
    }
}

/// Deserialization goes through the derived shape and then re-checks that an
/// `Other` variant does not carry a subtype which has a dedicated variant.
impl<'de> serde::Deserialize<'de> for Dot1Tlv {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Dot1Tlv, D::Error> {
        match Dot1Tlv::deserialize(deserializer)? {
            Dot1Tlv::Other { subtype, info } => {
                Dot1Tlv::other(subtype, info).map_err(serde::de::Error::custom)
            }
            checked => Ok(checked),
        }
    }
}

impl serde::Serialize for Dot1Tlv {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Dot1Tlv::serialize(self, serializer)
    }
}

/// The TLVs IEEE Std 802.3 defines under [`Oui::IEEE_802_3`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
pub enum Dot3Tlv {
    /// Link aggregation (subtype 3).
    LinkAggregation {
        /// Whether the port can be, and currently is, aggregated.
        status: LinkAggregationStatus,
        /// The identifier of the aggregated port, or zero if not aggregated.
        port_id: u32,
    },
    /// The maximum frame size (subtype 4) the port supports, in octets.
    MaximumFrameSize(u16),
    /// A subtype this library does not model.
    ///
    /// Build one with [`Dot3Tlv::other`], which refuses the subtypes that have
    /// a dedicated variant.
    #[non_exhaustive]
    Other {
        /// The IEEE 802.3 subtype.
        subtype: u8,
        /// The octets which follow the subtype.
        info: OrgInfo,
    },
}

impl Dot3Tlv {
    /// The subtype of an IEEE 802.3 link aggregation TLV.
    pub const LINK_AGGREGATION: u8 = 3;
    /// The subtype of an IEEE 802.3 maximum frame size TLV.
    pub const MAXIMUM_FRAME_SIZE: u8 = 4;

    /// Build an IEEE 802.3 TLV of a subtype this library does not model.
    ///
    /// # Errors
    ///
    /// Returns [`ModelledOrgTlv`] if `subtype` is one with a dedicated variant.
    pub fn other(subtype: u8, info: OrgInfo) -> Result<Dot3Tlv, ModelledOrgTlv> {
        if matches!(
            subtype,
            Dot3Tlv::LINK_AGGREGATION | Dot3Tlv::MAXIMUM_FRAME_SIZE
        ) {
            return Err(ModelledOrgTlv::Subtype {
                oui: Oui::IEEE_802_3,
                subtype,
            });
        }
        Ok(Dot3Tlv::Other { subtype, info })
    }

    /// The IEEE 802.3 subtype of this TLV.
    #[must_use]
    pub const fn subtype(&self) -> u8 {
        match self {
            Dot3Tlv::LinkAggregation { .. } => Dot3Tlv::LINK_AGGREGATION,
            Dot3Tlv::MaximumFrameSize(_) => Dot3Tlv::MAXIMUM_FRAME_SIZE,
            Dot3Tlv::Other { subtype, .. } => *subtype,
        }
    }

    /// The number of octets which follow the subtype.
    fn info_len(&self) -> usize {
        match self {
            Dot3Tlv::LinkAggregation { .. } => 5,
            Dot3Tlv::MaximumFrameSize(_) => 2,
            Dot3Tlv::Other { info, .. } => info.len(),
        }
    }

    fn write_info(&self, buf: &mut [u8]) {
        match self {
            Dot3Tlv::LinkAggregation { status, port_id } => {
                buf[0] = status.bits();
                buf[1..].copy_from_slice(&port_id.to_be_bytes());
            }
            Dot3Tlv::MaximumFrameSize(size) => buf.copy_from_slice(&size.to_be_bytes()),
            Dot3Tlv::Other { info, .. } => buf.copy_from_slice(info.as_bytes()),
        }
    }

    fn from_info(subtype: u8, info: &[u8]) -> Result<Dot3Tlv, OrgTlvError> {
        let wrong_length = || OrgTlvError::InvalidInfoLength {
            oui: Oui::IEEE_802_3,
            subtype,
            found: info.len(),
        };
        match subtype {
            Dot3Tlv::LINK_AGGREGATION => {
                let [status, port_id @ ..] = info else {
                    return Err(wrong_length());
                };
                let port_id: [u8; 4] = port_id.try_into().map_err(|_| wrong_length())?;
                Ok(Dot3Tlv::LinkAggregation {
                    status: LinkAggregationStatus::from_bits_retain(*status),
                    port_id: u32::from_be_bytes(port_id),
                })
            }
            Dot3Tlv::MAXIMUM_FRAME_SIZE => {
                let raw: [u8; 2] = info.try_into().map_err(|_| wrong_length())?;
                Ok(Dot3Tlv::MaximumFrameSize(u16::from_be_bytes(raw)))
            }
            other => Ok(Dot3Tlv::Other {
                subtype: other,
                info: OrgInfo::new(info).map_err(OrgTlvError::Info)?,
            }),
        }
    }
}

/// Deserialization goes through the derived shape and then re-checks that an
/// `Other` variant does not carry a subtype which has a dedicated variant.
impl<'de> serde::Deserialize<'de> for Dot3Tlv {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Dot3Tlv, D::Error> {
        match Dot3Tlv::deserialize(deserializer)? {
            Dot3Tlv::Other { subtype, info } => {
                Dot3Tlv::other(subtype, info).map_err(serde::de::Error::custom)
            }
            checked => Ok(checked),
        }
    }
}

impl serde::Serialize for Dot3Tlv {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Dot3Tlv::serialize(self, serializer)
    }
}

/// The organizationally specific TLV (type 127).
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(remote = "Self")]
pub enum OrganizationallySpecific {
    /// A TLV defined by IEEE Std 802.1.
    Dot1(Dot1Tlv),
    /// A TLV defined by IEEE Std 802.3.
    Dot3(Dot3Tlv),
    /// A TLV defined by some other organization.
    ///
    /// Build one with [`OrganizationallySpecific::other`], which refuses the
    /// OUIs that have a dedicated variant.
    #[non_exhaustive]
    Other {
        /// The OUI of the organization which defined this TLV.
        oui: Oui,
        /// That organization's subtype.
        subtype: u8,
        /// The octets which follow the subtype.
        info: OrgInfo,
    },
}

impl OrganizationallySpecific {
    /// The TLV type of an organizationally specific TLV.
    pub const TLV_TYPE: TlvType = TlvType::ORGANIZATIONALLY_SPECIFIC;

    /// The number of octets the OUI and subtype occupy.
    pub const HEADER_LEN: usize = 4;

    /// Build a TLV defined by an organization this library does not model.
    ///
    /// # Errors
    ///
    /// Returns [`ModelledOrgTlv`] if `oui` is one with a dedicated variant.
    pub fn other(
        oui: Oui,
        subtype: u8,
        info: OrgInfo,
    ) -> Result<OrganizationallySpecific, ModelledOrgTlv> {
        if oui.is_modelled() {
            return Err(ModelledOrgTlv::Oui(oui));
        }
        Ok(OrganizationallySpecific::Other { oui, subtype, info })
    }

    /// The OUI of the organization which defined this TLV.
    #[must_use]
    pub const fn oui(&self) -> Oui {
        match self {
            OrganizationallySpecific::Dot1(_) => Oui::IEEE_802_1,
            OrganizationallySpecific::Dot3(_) => Oui::IEEE_802_3,
            OrganizationallySpecific::Other { oui, .. } => *oui,
        }
    }

    /// That organization's subtype.
    #[must_use]
    pub const fn subtype(&self) -> u8 {
        match self {
            OrganizationallySpecific::Dot1(tlv) => tlv.subtype(),
            OrganizationallySpecific::Dot3(tlv) => tlv.subtype(),
            OrganizationallySpecific::Other { subtype, .. } => *subtype,
        }
    }

    /// The length of the TLV value: the OUI, the subtype, and the rest.
    ///
    /// [`OrgInfo`] caps the rest at 507 octets, so this is bounded by the 511
    /// octet limit a TLV length field can express.
    fn value_length(&self) -> u16 {
        let info_len = match self {
            OrganizationallySpecific::Dot1(tlv) => tlv.info_len(),
            OrganizationallySpecific::Dot3(tlv) => tlv.info_len(),
            OrganizationallySpecific::Other { info, .. } => info.len(),
        };
        #[allow(clippy::cast_possible_truncation)] // bounded by 511
        {
            (OrganizationallySpecific::HEADER_LEN + info_len) as u16
        }
    }
}

/// Deserialization goes through the derived shape and then re-checks that an
/// `Other` variant does not carry an OUI which has a dedicated variant.
impl<'de> serde::Deserialize<'de> for OrganizationallySpecific {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OrganizationallySpecific, D::Error> {
        match OrganizationallySpecific::deserialize(deserializer)? {
            OrganizationallySpecific::Other { oui, subtype, info } => {
                OrganizationallySpecific::other(oui, subtype, info)
                    .map_err(serde::de::Error::custom)
            }
            checked => Ok(checked),
        }
    }
}

impl serde::Serialize for OrganizationallySpecific {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        OrganizationallySpecific::serialize(self, serializer)
    }
}

/// The error returned when an escape hatch constructor is handed an OUI or
/// subtype which has a dedicated variant.
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ModelledOrgTlv {
    /// The OUI has a dedicated variant.
    #[error("OUI {0} has a dedicated OrganizationallySpecific variant")]
    Oui(Oui),
    /// The subtype has a dedicated variant.
    #[error("OUI {oui} subtype {subtype} has a dedicated variant")]
    Subtype {
        /// The OUI the subtype belongs to.
        oui: Oui,
        /// The subtype which has a dedicated variant.
        subtype: u8,
    },
}

/// Errors which can occur while parsing an [`OrganizationallySpecific`].
#[must_use]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum OrgTlvError {
    /// The TLV at this position was not an organizationally specific TLV.
    #[error(transparent)]
    UnexpectedTlvType(#[from] UnexpectedTlvType),
    /// The TLV value was too short to carry an OUI and a subtype.
    #[error(
        "an organizationally specific TLV needs at least {min} octets, found {0}",
        min = OrganizationallySpecific::HEADER_LEN
    )]
    Truncated(usize),
    /// A modelled subtype was paired with the wrong number of octets.
    #[error("OUI {oui} subtype {subtype} cannot carry {found} octets")]
    InvalidInfoLength {
        /// The OUI of the TLV.
        oui: Oui,
        /// The subtype of the TLV.
        subtype: u8,
        /// The number of octets found after the subtype.
        found: usize,
    },
    /// A VLAN name TLV declared a name length which disagreed with the octets
    /// that followed it.
    #[error("VLAN name TLV declares a {declared} octet name but carries {found} octets")]
    VlanNameLengthMismatch {
        /// The length the TLV declared.
        declared: usize,
        /// The number of octets actually present.
        found: usize,
    },
    /// The octets after the subtype could not be stored.
    #[error(transparent)]
    Info(OctetsError),
}

impl Parse for OrganizationallySpecific {
    type Error = OrgTlvError;

    fn parse(
        buf: &[u8],
    ) -> Result<(OrganizationallySpecific, NonZero<u16>), ParseError<OrgTlvError>> {
        let (value, total) = split_tlv::<OrgTlvError>(buf, OrganizationallySpecific::TLV_TYPE)?;
        let [a, b, c, subtype, info @ ..] = value else {
            return Err(ParseError::Invalid(OrgTlvError::Truncated(value.len())));
        };
        let oui = Oui([*a, *b, *c]);
        let tlv = match oui {
            Oui::IEEE_802_1 => OrganizationallySpecific::Dot1(
                Dot1Tlv::from_info(*subtype, info).map_err(ParseError::Invalid)?,
            ),
            Oui::IEEE_802_3 => OrganizationallySpecific::Dot3(
                Dot3Tlv::from_info(*subtype, info).map_err(ParseError::Invalid)?,
            ),
            other => OrganizationallySpecific::Other {
                oui: other,
                subtype: *subtype,
                info: OrgInfo::new(info).map_err(|e| ParseError::Invalid(OrgTlvError::Info(e)))?,
            },
        };
        Ok((tlv, total))
    }
}

impl DeParse for OrganizationallySpecific {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        TlvHeader::LENGTH.saturating_add(self.value_length())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        write_tlv(
            buf,
            OrganizationallySpecific::TLV_TYPE,
            self.value_length(),
            |slot| {
                slot[..3].copy_from_slice(&self.oui().octets());
                slot[3] = self.subtype();
                let info = &mut slot[OrganizationallySpecific::HEADER_LEN..];
                match self {
                    OrganizationallySpecific::Dot1(tlv) => tlv.write_info(info),
                    OrganizationallySpecific::Dot3(tlv) => tlv.write_info(info),
                    OrganizationallySpecific::Other { info: octets, .. } => {
                        info.copy_from_slice(octets.as_bytes());
                    }
                }
            },
        )
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{Dot1Tlv, Dot3Tlv, LinkAggregationStatus, OrganizationallySpecific, Oui};
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for LinkAggregationStatus {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            // The parser retains the reserved bits, so every `u8` is legal.
            Some(LinkAggregationStatus::from_bits_retain(u.produce()?))
        }
    }

    impl TypeGenerator for Dot1Tlv {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            match u.produce::<u8>()? % 3 {
                0 => Some(Dot1Tlv::PortVlanId(u.produce()?)),
                1 => Some(Dot1Tlv::VlanName {
                    vlan_id: u.produce()?,
                    name: u.produce()?,
                }),
                // Steer away from the modelled subtypes rather than rejecting,
                // so the driver does not waste budget retrying.
                _ => Dot1Tlv::other(u.produce::<u8>()? | 0x80, u.produce()?).ok(),
            }
        }
    }

    impl TypeGenerator for Dot3Tlv {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            match u.produce::<u8>()? % 3 {
                0 => Some(Dot3Tlv::LinkAggregation {
                    status: u.produce()?,
                    port_id: u.produce()?,
                }),
                1 => Some(Dot3Tlv::MaximumFrameSize(u.produce()?)),
                _ => Dot3Tlv::other(u.produce::<u8>()? | 0x80, u.produce()?).ok(),
            }
        }
    }

    impl TypeGenerator for OrganizationallySpecific {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            match u.produce::<u8>()? % 3 {
                0 => Some(OrganizationallySpecific::Dot1(u.produce()?)),
                1 => Some(OrganizationallySpecific::Dot3(u.produce()?)),
                _ => {
                    let mut oui: Oui = u.produce()?;
                    if oui.is_modelled() {
                        oui = Oui([0xde, 0xad, 0xbe]);
                    }
                    OrganizationallySpecific::other(oui, u.produce()?, u.produce()?).ok()
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        Dot1Tlv, Dot3Tlv, LinkAggregationStatus, ModelledOrgTlv, OrgInfo, OrgTlvError,
        OrganizationallySpecific, Oui, VlanId, VlanNameOctets,
    };
    use crate::lldp::tlv::{RawTlv, TlvType, TlvValue};
    use crate::parse::{DeParse, Parse, ParseError};

    fn deparse(tlv: &OrganizationallySpecific) -> Vec<u8> {
        let mut buf = vec![0u8; tlv.size().get() as usize];
        let written = tlv.deparse(&mut buf).unwrap();
        assert_eq!(written, tlv.size());
        buf
    }

    fn tlv_bytes(value: &[u8]) -> Vec<u8> {
        let tlv = RawTlv::new(
            TlvType::ORGANIZATIONALLY_SPECIFIC,
            TlvValue::new(value).unwrap(),
        );
        let mut buf = vec![0u8; tlv.size().get() as usize];
        tlv.deparse(&mut buf).unwrap();
        buf
    }

    #[test]
    fn round_trips() {
        bolero::check!()
            .with_type()
            .for_each(|tlv: &OrganizationallySpecific| {
                let buf = deparse(tlv);
                let (parsed, consumed) = OrganizationallySpecific::parse(&buf).unwrap();
                assert_eq!(&parsed, tlv);
                assert_eq!(consumed, tlv.size());
                assert_eq!(parsed.oui(), tlv.oui());
                assert_eq!(parsed.subtype(), tlv.subtype());
            });
    }

    #[test]
    fn parse_of_arbitrary_octets_is_byte_exact() {
        bolero::check!().with_type().for_each(|raw: &Vec<u8>| {
            let Ok((tlv, consumed)) = OrganizationallySpecific::parse(raw) else {
                return;
            };
            assert_eq!(consumed, tlv.size());
            assert_eq!(&deparse(&tlv)[..], &raw[..consumed.get() as usize]);
        });
    }

    #[test]
    fn a_port_vlan_id_encodes_as_expected() {
        let tlv = OrganizationallySpecific::Dot1(Dot1Tlv::PortVlanId(VlanId::new(100)));
        assert_eq!(
            deparse(&tlv),
            vec![0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, 0x00, 0x64]
        );
    }

    #[test]
    fn a_maximum_frame_size_encodes_as_expected() {
        let tlv = OrganizationallySpecific::Dot3(Dot3Tlv::MaximumFrameSize(9216));
        assert_eq!(
            deparse(&tlv),
            vec![0xfe, 0x06, 0x00, 0x12, 0x0f, 0x04, 0x24, 0x00]
        );
    }

    #[test]
    fn a_vlan_name_encodes_as_expected() {
        let tlv = OrganizationallySpecific::Dot1(Dot1Tlv::VlanName {
            vlan_id: VlanId::new(100),
            name: VlanNameOctets::new(b"tenants").unwrap(),
        });
        assert_eq!(
            deparse(&tlv),
            vec![
                0xfe, 0x0e, 0x00, 0x80, 0xc2, 0x03, 0x00, 0x64, 0x07, b't', b'e', b'n', b'a', b'n',
                b't', b's',
            ]
        );
    }

    #[test]
    fn link_aggregation_reserved_bits_are_preserved() {
        let tlv = OrganizationallySpecific::Dot3(Dot3Tlv::LinkAggregation {
            status: LinkAggregationStatus::from_bits_retain(0xfc),
            port_id: 1,
        });
        let buf = deparse(&tlv);
        let (parsed, _) = OrganizationallySpecific::parse(&buf).unwrap();
        assert_eq!(parsed, tlv);
    }

    #[test]
    fn vlan_id_zero_is_not_a_vid() {
        assert_eq!(VlanId::NONE.as_u16(), 0);
        assert!(VlanId::NONE.vid().is_none());
        assert!(VlanId::new(4095).vid().is_none());
        assert_eq!(VlanId::new(100).vid().unwrap().as_u16(), 100);
    }

    #[test]
    fn modelled_subtypes_are_refused_by_the_escape_hatch() {
        let info = OrgInfo::new(&[]).unwrap();
        assert_eq!(
            Dot1Tlv::other(Dot1Tlv::PORT_VLAN_ID, info.clone()).unwrap_err(),
            ModelledOrgTlv::Subtype {
                oui: Oui::IEEE_802_1,
                subtype: 1
            }
        );
        assert_eq!(
            Dot3Tlv::other(Dot3Tlv::MAXIMUM_FRAME_SIZE, info.clone()).unwrap_err(),
            ModelledOrgTlv::Subtype {
                oui: Oui::IEEE_802_3,
                subtype: 4
            }
        );
        assert!(Dot1Tlv::other(2, info.clone()).is_ok());
        assert!(Dot3Tlv::other(1, info).is_ok());
    }

    #[test]
    fn modelled_ouis_are_refused_by_the_escape_hatch() {
        let info = OrgInfo::new(&[]).unwrap();
        for oui in [Oui::IEEE_802_1, Oui::IEEE_802_3] {
            assert_eq!(
                OrganizationallySpecific::other(oui, 1, info.clone()).unwrap_err(),
                ModelledOrgTlv::Oui(oui)
            );
        }
        assert!(OrganizationallySpecific::other(Oui([1, 2, 3]), 1, info).is_ok());
    }

    #[test]
    fn a_short_value_is_rejected() {
        for length in 0usize..4 {
            let buf = tlv_bytes(&vec![0u8; length]);
            match OrganizationallySpecific::parse(&buf) {
                Err(ParseError::Invalid(OrgTlvError::Truncated(found))) => {
                    assert_eq!(found, length);
                }
                other => unreachable!("expected truncation for {length}, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_modelled_subtype_of_the_wrong_length_is_rejected() {
        // Port VLAN ID with three octets instead of two.
        let buf = tlv_bytes(&[0x00, 0x80, 0xc2, 0x01, 0x00, 0x64, 0x00]);
        match OrganizationallySpecific::parse(&buf) {
            Err(ParseError::Invalid(OrgTlvError::InvalidInfoLength {
                oui,
                subtype,
                found,
            })) => {
                assert_eq!(oui, Oui::IEEE_802_1);
                assert_eq!(subtype, 1);
                assert_eq!(found, 3);
            }
            other => unreachable!("expected a length error, got {other:?}"),
        }
    }

    #[test]
    fn a_vlan_name_with_a_lying_length_is_rejected() {
        let buf = tlv_bytes(&[0x00, 0x80, 0xc2, 0x03, 0x00, 0x64, 0x09, b'a', b'b']);
        match OrganizationallySpecific::parse(&buf) {
            Err(ParseError::Invalid(OrgTlvError::VlanNameLengthMismatch { declared, found })) => {
                assert_eq!(declared, 9);
                assert_eq!(found, 2);
            }
            other => unreachable!("expected a mismatch, got {other:?}"),
        }
    }

    #[test]
    fn oui_displays_as_dashed_hex() {
        assert_eq!(Oui::IEEE_802_1.to_string(), "00-80-c2");
        assert_eq!(Oui::IEEE_802_3.to_string(), "00-12-0f");
    }
}
