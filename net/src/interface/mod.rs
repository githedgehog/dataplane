// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Data structures and methods for interacting with / describing network interfaces

mod bridge;
mod vrf;
mod vtep;

use crate::eth::mac::SourceMac;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use rtnetlink::packet_route::link::{
    InfoBridge, InfoData, InfoVrf, InfoVxlan, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
    State,
};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use tracing::error;


use crate::eth::ethtype::EthType;
use crate::route::RouteTableId;
use crate::vxlan::InvalidVni;
pub use bridge::*;
pub use vrf::*;
pub use vtep::*;

/// A network interface id (also known as ifindex in linux).
///
/// These are 32-bit values that are generally assigned by the linux kernel.
/// You can't generally meaningfully persist or assign them.
/// They don't typically mean anything "between" machines or even reboots.
#[repr(transparent)]
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "u32", into = "u32")]
pub struct InterfaceIndex(u32);

impl Debug for InterfaceIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Debug>::fmt(&self.0, f)
    }
}

impl Display for InterfaceIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Display>::fmt(&self.0, f)
    }
}

impl InterfaceIndex {
    /// Treat the provided `u32` as an [`InterfaceIndex`].
    #[must_use]
    pub fn new(raw: u32) -> InterfaceIndex {
        InterfaceIndex(raw)
    }

    /// Treat this [`InterfaceIndex`] as a `u32`.
    #[must_use]
    pub fn to_u32(self) -> u32 {
        self.0
    }
}

impl From<u32> for InterfaceIndex {
    fn from(value: u32) -> InterfaceIndex {
        InterfaceIndex::new(value)
    }
}

impl From<InterfaceIndex> for u32 {
    fn from(value: InterfaceIndex) -> Self {
        value.to_u32()
    }
}

const MAX_INTERFACE_NAME_LEN: usize = 16;

/// A string which has been checked to be a legal linux network interface name.
///
/// Legal network interface names are composed only of alphanumeric ASCII characters, `.`, `-`, and
/// `_` and which are terminated with a null (`\0`) character.
///
/// The maximum legal length of an `InterfaceName` is 16 bytes (including the terminating null).
/// Thus, the _effective_ maximum length is 15 bytes (not characters).
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct InterfaceName(String);

impl Display for InterfaceName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl InterfaceName {
    /// The maximum legal length of a linux network interface name (including the trailing NUL)
    pub const MAX_LEN: usize = MAX_INTERFACE_NAME_LEN;
}

/// Errors which may occur when mapping a general `String` into an `InterfaceName`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
pub enum IllegalInterfaceName {
    /// A string which is longer than 15 characters was submitted.
    #[error("interface name must be at least one character")]
    Empty,
    /// A string which is longer than 15 characters was submitted.
    #[error("interface name {0} is too long")]
    TooLong(String),
    /// The string must not contain an interior null character.
    #[error("interface name {0} contains interior null characters")]
    InteriorNull(String),
    /// The supplied string is not legal ASCII.
    #[error("interface name {0} is not ascii")]
    NotAscii(String),
    /// The supplied string contains an illegal character.
    #[error(
        "interface name {0} contains illegal characters (only alphanumeric ASCII and .-_ are permitted)"
    )]
    IllegalCharacters(String),
}

impl TryFrom<String> for InterfaceName {
    type Error = IllegalInterfaceName;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        const LEGAL_PUNCT: [char; 3] = ['.', '-', '_'];
        if value.is_empty() {
            return Err(IllegalInterfaceName::Empty);
        }
        if value.contains('\0') {
            return Err(IllegalInterfaceName::InteriorNull(value));
        }
        if !value.is_ascii() {
            return Err(IllegalInterfaceName::NotAscii(value));
        }
        if !value
            .chars()
            .all(|c| c.is_alphanumeric() || LEGAL_PUNCT.contains(&c))
        {
            return Err(IllegalInterfaceName::IllegalCharacters(value));
        }
        if value.len() > InterfaceName::MAX_LEN {
            return Err(IllegalInterfaceName::TooLong(value));
        }
        Ok(InterfaceName(value))
    }
}

impl TryFrom<&str> for InterfaceName {
    type Error = IllegalInterfaceName;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_string())
    }
}

impl From<InterfaceName> for String {
    fn from(value: InterfaceName) -> Self {
        value.0.as_str().to_string()
    }
}

impl AsRef<str> for InterfaceName {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

/// The administrative state of a network interface.
///
/// Basically, this describes the intended state of a network interface (as opposed to its
/// [`OperationalState`]).
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AdminState {
    /// The interface is set to down
    Down = 0,
    /// The interface is set to the up state.
    Up = 1,
}

/// The observed state of a network interface.
///
/// Basically, this describes what state a network interface is actually in (as opposed to the state
/// we would like it to be in, i.e., the [`AdminState`])
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub enum OperationalState {
    /// The interface is down
    Down,
    /// The interface is up
    Up,
    /// The interface condition is unknown.  This is common for L3 interfaces.
    Unknown,
    /// Complex: the interface is in some other more complex state (which should be regarded as down
    /// mostly)
    Complex,
}

#[derive(
    Builder,
    Clone,
    Debug,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Interface {
    #[multi_index(ordered_unique)]
    pub index: InterfaceIndex,
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    #[multi_index(hashed_non_unique)]
    pub mac: Option<SourceMac>,
    pub admin_state: AdminState,
    pub operational_state: OperationalState,
    pub controller: Option<InterfaceIndex>,
    pub properties: InterfaceProperties,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum InterfaceProperties {
    Bridge(BridgeProperties),
    Vtep(VtepProperties),
    Vrf(VrfProperties),
    Other,
}

fn extract_vrf_data(builder: &mut VrfPropertiesBuilder, info: &LinkInfo) {
    if let LinkInfo::Data(InfoData::Vrf(datas)) = info {
        for data in datas {
            if let InfoVrf::TableId(raw) = data {
                builder.route_table_id(RouteTableId::from(*raw));
            }
        }
    }
}

fn extract_vxlan_info(builder: &mut VtepPropertiesBuilder, info: &LinkInfo) {
    if let LinkInfo::Data(InfoData::Vxlan(datas)) = info {
        for data in datas {
            match data {
                InfoVxlan::Id(vni) => {
                    match (*vni).try_into() {
                        Ok(vni) => {
                            builder.vni(Some(vni));
                        }
                        Err(InvalidVni::ReservedZero) => {
                            builder.vni(None); // likely an external vtep
                        }
                        Err(InvalidVni::TooLarge(wrong)) => {
                            error!("found too large VNI: {wrong}");
                        }
                    }
                }
                InfoVxlan::Local(local) => {
                    builder.local(Some(*local));
                }
                InfoVxlan::Ttl(ttl) => {
                    builder.ttl(Some(*ttl));
                }
                _ => {}
            }
        }
    }
}

fn extract_bridge_info(builder: &mut BridgePropertiesBuilder, info: &LinkInfo) -> bool {
    let mut is_bridge = false;
    if let LinkInfo::Data(InfoData::Bridge(datas)) = info {
        is_bridge = true;
        for data in datas {
            match data {
                InfoBridge::VlanFiltering(f) => {
                    builder.vlan_filtering(*f);
                }
                InfoBridge::VlanProtocol(p) => {
                    builder.vlan_protocol(EthType::from(*p));
                }
                _ => {}
            }
        }
    }
    is_bridge
}

impl TryFrom<LinkMessage> for Interface {
    type Error = InterfaceBuilderError;

    fn try_from(message: LinkMessage) -> Result<Self, Self::Error> {
        let mut builder = InterfaceBuilder::default();
        builder.index(message.header.index.into());
        let mut vtep_builder = VtepPropertiesBuilder::default();
        let mut vrf_builder = VrfPropertiesBuilder::default();
        let mut bridge_builder = BridgePropertiesBuilder::default();
        let mut is_bridge = false;
        builder.admin_state(if message.header.flags.contains(LinkFlags::Up) {
            AdminState::Up
        } else {
            AdminState::Down
        });
        builder.controller(None);
        builder.mac(None);

        for attr in &message.attributes {
            match attr {
                LinkAttribute::Address(addr) => {
                    builder.mac(SourceMac::try_from(addr).ok());
                }
                LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        extract_vrf_data(&mut vrf_builder, info);
                        extract_vxlan_info(&mut vtep_builder, info);
                        is_bridge = extract_bridge_info(&mut bridge_builder, info);
                    }
                }
                LinkAttribute::IfName(name) => match InterfaceName::try_from(name.clone()) {
                    Ok(name) => {
                        builder.name(name);
                    }
                    Err(illegal_name) => {
                        error!("{illegal_name:?}");
                    }
                },
                LinkAttribute::Controller(c) => {
                    builder.controller(Some(InterfaceIndex::new(*c)));
                }
                LinkAttribute::OperState(state) => match state {
                    State::Up => {
                        builder.operational_state(OperationalState::Up);
                    }
                    State::Unknown => {
                        builder.operational_state(OperationalState::Unknown);
                    }
                    State::Down => {
                        builder.operational_state(OperationalState::Down);
                    }
                    _ => {
                        builder.operational_state(OperationalState::Complex);
                    }
                },
                _ => {}
            }
        }

        match (vrf_builder.build(), vtep_builder.build()) {
            (Ok(vrf), Err(_)) => {
                builder.properties(InterfaceProperties::Vrf(vrf));
            }
            (Err(_), Ok(vtep)) => {
                builder.properties(InterfaceProperties::Vtep(vtep));
            }
            (Err(_), Err(_)) => {
                if is_bridge {
                    match bridge_builder.build() {
                        Ok(bridge) => {
                            builder.properties(InterfaceProperties::Bridge(bridge));
                        }
                        Err(err) => {
                            error!("{err:?}");
                        }
                    }
                }
            }
            (Ok(vrf), Ok(vtep)) => {
                error!("multiple link types satisfied at once: {vrf:?}, {vtep:?}");
            }
        }
        builder.build()
    }
}
