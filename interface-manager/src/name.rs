// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use arrayvec::ArrayString;
use std::convert::TryFrom;

const MAX_LEN: usize = 16;

/// A string which has been checked to be a legal linux network interface name.
///
/// Legal network interface names are composed only of alphanumeric ASCII characters, `.`, `-`, and
/// `_` and which are terminated with a null (`\0`) character.
///
/// The maximum legal length of an `InterfaceName` is 16 characters (including the terminating null).
/// Thus, the _effective_ maximum length is 15 characters.
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceName(ArrayString<MAX_LEN>);

impl InterfaceName {
    /// The maximum legal length of a linux network interface name (including the trailing NUL)
    pub const MAX_LEN: usize = MAX_LEN;
}

/// Errors which may occur when mapping a general `String` into an `InterfaceName`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
pub enum IllegalInterfaceName {
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
        if value.contains('\0') {
            return Err(IllegalInterfaceName::InteriorNull(value));
        }
        if !value.is_ascii() {
            return Err(IllegalInterfaceName::NotAscii(value));
        }
        if value
            .chars()
            .any(|c| !c.is_alphanumeric() || !LEGAL_PUNCT.contains(&c))
        {
            return Err(IllegalInterfaceName::IllegalCharacters(value));
        }
        if let Ok(ok) = ArrayString::from(value.as_str()) {
            Ok(InterfaceName(ok))
        } else {
            Err(IllegalInterfaceName::TooLong(value))
        }
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
