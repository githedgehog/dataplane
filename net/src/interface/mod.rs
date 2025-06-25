// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// multi-index-map generated code is not documented and it angers clippy
#![allow(missing_docs)]
// multi-index-map can't be convinced to attach this to the derived types
#![allow(clippy::unsafe_derive_deserialize)]

//! Data structures and methods for interacting with / describing network interfaces

use crate::eth::mac::SourceMac;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::num::NonZero;
use tracing::error;

mod bridge;
pub mod display;
mod mtu;
mod vrf;
mod vtep;

#[allow(unused_imports)] // re-export
pub use bridge::*;
#[allow(unused_imports)] // re-export
pub use mtu::*;
#[allow(unused_imports)] // re-export
pub use vrf::*;
#[allow(unused_imports)] // re-export
pub use vtep::*;

#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// A network interface id (also known as ifindex in linux).
///
/// These are 32-bit values that are generally assigned by the linux kernel.
/// You can't generally meaningfully persist or assign them.
/// They don't typically mean anything "between" machines or even reboots.
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u32", into = "u32")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceIndex(NonZero<u32>);

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

#[derive(Debug, thiserror::Error)]
pub enum InterfaceIndexError {
    /// The provided value was zero.
    #[error("interface index must not be zero")]
    Zero,
}

impl InterfaceIndex {
    /// Treat the provided `NonZero<u32>` as an [`InterfaceIndex`].
    #[must_use]
    pub fn new(raw: NonZero<u32>) -> InterfaceIndex {
        InterfaceIndex(raw)
    }

    /// Treat the provided `u32` as an [`InterfaceIndex`].
    ///
    /// # Errors
    ///
    /// Returns an error if the provided value is zero.
    pub fn try_new(raw: u32) -> Result<Self, InterfaceIndexError> {
        raw.try_into()
    }

    /// Treat this [`InterfaceIndex`] as a `u32`.
    #[must_use]
    pub fn to_u32(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for InterfaceIndex {
    type Error = InterfaceIndexError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match NonZero::new(value) {
            Some(raw) => Ok(InterfaceIndex::new(raw)),
            None => Err(InterfaceIndexError::Zero),
        }
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
    /// You can't make an interface named ., ..
    #[error("name must not be . or ..")]
    MustNotIncludeOnlyDots(String),
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
        if value == "." || value == ".." {
            return Err(IllegalInterfaceName::MustNotIncludeOnlyDots(value));
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
/// Basically, this describes the intended state of a network interface. (as opposed to its
/// [`OperationalState`])
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

/// An "observed" network interface.
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
    /// The index of the interface.
    #[multi_index(hashed_unique)]
    pub index: InterfaceIndex,
    /// The name of the interface.
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    /// The MAC (if any) associated with this network interface.
    pub mac: Option<SourceMac>,
    /// The MTU of the interface.
    pub mtu: Option<Mtu>,
    /// The `AdminState` of the interface.
    pub admin_state: AdminState,
    /// The observed `OperationalState` of the network interface.
    pub operational_state: OperationalState,
    /// The controller (i.e., the bridge, bond, or VRF which this interface is a member of).
    pub controller: Option<InterfaceIndex>,
    /// The type-specific properties of this interface.
    pub properties: InterfaceProperties,
}

impl Interface {
    /// Tell if [`Interface`] is a VRF
    #[must_use]
    pub fn is_vrf(&self) -> bool {
        matches!(self.properties, InterfaceProperties::Vrf(_))
    }
    /// Tell if [`Interface`] is a vxlan interface
    #[must_use]
    pub fn is_vtep(&self) -> bool {
        matches!(self.properties, InterfaceProperties::Vtep(_))
    }
    /// Tell if [`Interface`] is a bridge interface
    #[must_use]
    pub fn is_bridge(&self) -> bool {
        matches!(self.properties, InterfaceProperties::Bridge(_))
    }
    /// Provide a reference to [`VrfProperties`] if the interface has
    /// such a property
    #[must_use]
    pub fn get_vrf_properties(&self) -> Option<&VrfProperties> {
        match &self.properties {
            InterfaceProperties::Vrf(properties) => Some(properties),
            _ => None,
        }
    }
}

/// Interface-specific properties.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum InterfaceProperties {
    /// Properties of bridges
    Bridge(BridgeProperties),
    /// Properties of VTEPs (vxlan devices)
    Vtep(VtepProperties),
    /// Properties of VRFs
    Vrf(VrfProperties),
    /// Properties of something we don't currently support manipulating
    Other,
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::interface::{
        AdminState, Interface, InterfaceIndex, InterfaceName, InterfaceProperties, OperationalState,
    };
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for InterfaceIndex {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self(driver.produce()?))
        }
    }

    impl TypeGenerator for AdminState {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? {
                x if x % 2 == 0 => Some(AdminState::Down),
                _ => Some(AdminState::Up),
            }
        }
    }

    impl TypeGenerator for OperationalState {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? {
                x if x % 4 == 0 => Some(OperationalState::Up),
                x if x % 4 == 1 => Some(OperationalState::Down),
                x if x % 4 == 2 => Some(OperationalState::Unknown),
                x if x % 4 == 3 => Some(OperationalState::Complex),
                _ => unreachable!(),
            }
        }
    }

    pub struct LegalInterfaceName;

    impl TypeGenerator for InterfaceName {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            const NUM_LEGAL_CHARS: u8 = 65;
            const LEGAL_CHARS: [char; NUM_LEGAL_CHARS as usize] = [
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
                'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
                'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '.', '_',
                '-',
            ];
            #[allow(clippy::cast_possible_truncation)] // const eval
            let target_length =
                (1 + (driver.produce::<u8>()? % (InterfaceName::MAX_LEN as u8 - 2))) as usize;
            let mut base_string = String::with_capacity(target_length + 1);
            for _ in 0..target_length {
                let selected_char_index = (driver.produce::<u8>()? % NUM_LEGAL_CHARS) as usize;
                let selected_char = LEGAL_CHARS[selected_char_index];
                base_string.push(selected_char);
            }
            if base_string == "." || base_string == ".." {
                base_string.push('_');
            }
            #[allow(clippy::unwrap_used)] // safe by contract
            Some(InterfaceName::try_from(base_string.as_str()).unwrap())
        }
    }

    impl TypeGenerator for InterfaceProperties {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            match driver.produce::<u8>()? {
                x if x % 4 == 0 => Some(InterfaceProperties::Bridge(driver.produce()?)),
                x if x % 4 == 1 => Some(InterfaceProperties::Vtep(driver.produce()?)),
                x if x % 4 == 2 => Some(InterfaceProperties::Vrf(driver.produce()?)),
                x if x % 4 == 3 => Some(InterfaceProperties::Other),
                _ => unreachable!(),
            }
        }
    }

    impl TypeGenerator for Interface {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                admin_state: driver.produce()?,
                controller: driver.produce()?,
                index: driver.produce()?,
                mac: driver.produce()?,
                mtu: driver.produce()?,
                name: driver.produce()?,
                operational_state: driver.produce()?,
                properties: driver.produce()?,
            })
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn interface_name_validates() {
        bolero::check!()
            .with_type()
            .cloned()
            .for_each(|x: InterfaceName| {
                InterfaceName::try_from(x.0).unwrap();
            });
    }

    #[test]
    fn interface_name_with_illegal_char_rejects() {
        bolero::check!().with_type().for_each(|x: &InterfaceName| {
            let mut illegal_name = x.0.clone();
            illegal_name.push('/');
            match InterfaceName::try_from(illegal_name.as_str()) {
                Err(IllegalInterfaceName::IllegalCharacters(wrong)) => {
                    assert_eq!(illegal_name, wrong);
                }
                _ => unreachable!(),
            }
        });
    }

    #[test]
    fn interface_name_with_null_char_rejects() {
        bolero::check!().with_type().for_each(|x: &InterfaceName| {
            let mut illegal_name = x.0.clone();
            illegal_name.push('\0');
            match InterfaceName::try_from(illegal_name.as_str()) {
                Err(IllegalInterfaceName::InteriorNull(wrong)) => {
                    assert_eq!(illegal_name, wrong);
                }
                _ => unreachable!(),
            }
        });
    }

    #[test]
    fn empty_interface_name_is_rejected() {
        match InterfaceName::try_from("").unwrap_err() {
            IllegalInterfaceName::Empty => {}
            _ => unreachable!(),
        }
    }

    #[test]
    fn too_long_interface_name_rejected() {
        bolero::check!().with_type().for_each(|x: &InterfaceName| {
            let legal_name = x.0.clone();
            let repeats = 1 + InterfaceName::MAX_LEN / legal_name.len();
            let illegal_name = legal_name.repeat(repeats);
            match InterfaceName::try_from(illegal_name.as_str()).unwrap_err() {
                IllegalInterfaceName::TooLong(wrong) => {
                    assert_eq!(illegal_name, wrong);
                    assert!(illegal_name.len() > InterfaceName::MAX_LEN);
                }
                _ => unreachable!(),
            }
        });
    }
}
