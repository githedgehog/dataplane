// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! PCI bus representation.
//!
//! This module provides the [`self::bus::Bus`] type for representing PCI bus numbers.
//! PCI buses are identified by an 8-bit number (0x00-0xFF) within a domain.
//!
//! # Examples
//!
//! ```
//! use dataplane_hardware::pci::bus::Bus;
//!
//! // Create a bus from a u8 value
//! let bus = Bus::from(0x03);
//! assert_eq!(format!("{}", bus), "03");
//!
//! // Parse from a hex string
//! let parsed = Bus::try_from("0a").unwrap();
//! assert_eq!(format!("{:x}", parsed), "0a");
//! ```

/// A PCI bus number.
///
/// PCI buses are numbered from 0x00 to 0xFF within each domain. The bus number
/// identifies a specific bus within the PCI hierarchy.
///
/// # Display
///
/// The `Display` and `LowerHex` implementations format the bus as a 2-digit
/// hexadecimal value with leading zeros.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    bytecheck::CheckBytes,
    num_derive::FromPrimitive,
    num_derive::ToPrimitive,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[repr(transparent)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct Bus(u8);

impl Bus {
    /// Creates a new bus number.
    #[must_use]
    pub fn new(bus: u8) -> Self {
        Self(bus)
    }

    /// Returns the raw bus number value.
    #[must_use]
    pub fn value(self) -> u8 {
        self.0
    }
}

impl std::fmt::LowerHex for Bus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

impl std::fmt::Display for Bus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:02x}")
    }
}

impl From<u8> for Bus {
    /// Creates a bus from a raw u8 value.
    ///
    /// All u8 values are valid bus numbers.
    fn from(value: u8) -> Self {
        Bus(value)
    }
}

/// Error type for bus parsing failures.
#[derive(Debug, thiserror::Error)]
pub enum BusParseError {
    /// Invalid bus syntax (not a 2-digit hex string).
    #[error("invalid bus syntax: {0}")]
    Syntax(String),
}

impl TryFrom<&str> for Bus {
    type Error = BusParseError;

    /// Parses a bus number from a hexadecimal string.
    ///
    /// The string must be exactly 2 hexadecimal digits.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::bus::Bus;
    ///
    /// assert!(Bus::try_from("00").is_ok());
    /// assert!(Bus::try_from("ff").is_ok());
    /// assert!(Bus::try_from("0").is_err());    // Too short
    /// assert!(Bus::try_from("100").is_err());  // Too long
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(BusParseError::Syntax(format!(
                "invalid bus syntax: {value}"
            )));
        }
        let bus = u8::from_str_radix(value, 16)
            .map_err(|_| BusParseError::Syntax(format!("invalid bus syntax: {value}")))?;
        Ok(Bus(bus))
    }
}
