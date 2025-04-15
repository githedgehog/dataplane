// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(missing_docs)] // multi-index-map generated code is not documented and it angers clippy

//! Data structures and methods for interacting with / describing network interfaces

use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};

/// A network interface id (also known as ifindex in linux).
///
/// These are 32-bit values that are generally assigned by the linux kernel.
/// You can't generally meaningfully persist or assign them.
/// They don't typically mean anything "between" machines or even reboots.
#[repr(transparent)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u32", into = "u32")]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
/// Basically, this describes the intended state of a network interface.
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AdminState {
    /// The interface is set to down
    Down = 0,
    /// The interface is set to the up state.
    Up = 1,
}
