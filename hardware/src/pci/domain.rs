// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! PCI domain (segment) representation.
//!
//! This module provides the [`self::domain::Domain`] type for representing PCI domains,
//! also known as PCI segments. Domains allow systems to have multiple independent
//! PCI bus hierarchies.
//!
//! # Examples
//!
//! ```
//! # use dataplane_hardware::pci::domain::Domain;
//! #
//! // Create from u16
//! let domain = Domain::new(0);
//! assert_eq!(format!("{}", domain), "0000");
//!
//! // Parse from hex string
//! let parsed = Domain::try_from("00ff").unwrap();
//! assert_eq!(format!("{:x}", parsed), "00ff");
//! ```

/// A PCI domain number (also known as segment).
///
/// PCI domains allow systems to have multiple independent PCI hierarchies.
/// Each domain can have its own set of 256 buses. The domain is a 16-bit
/// value typically displayed as 4 hexadecimal digits.
///
/// Most desktop systems only have domain 0000, but larger systems may have
/// multiple domains.
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
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[repr(transparent)]
#[rkyv(attr(derive(Debug, PartialEq, Eq)))]
pub struct Domain(u16);

impl Domain {
    /// Creates a new domain number.
    #[must_use]
    pub fn new(domain: u16) -> Self {
        Self(domain)
    }

    /// Returns the raw domain number value.
    #[must_use]
    pub fn value(self) -> u16 {
        self.0
    }
}

impl From<u16> for Domain {
    /// Creates a domain from a raw u16 value.
    ///
    /// All u16 values are valid domain numbers.
    fn from(value: u16) -> Self {
        Domain(value)
    }
}

impl std::fmt::LowerHex for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:04x}")
    }
}

/// Error type for domain parsing failures.
#[derive(Debug, thiserror::Error)]
pub enum PciDomainParseError {
    /// Invalid syntax when parsing domain string.
    #[error("Invalid PCI domain syntax (must be four hex digits): {0}")]
    Syntax(std::num::ParseIntError),
}

impl TryFrom<&str> for Domain {
    type Error = PciDomainParseError;

    /// Parses a domain number from a hexadecimal string.
    ///
    /// The string should be 1-4 hexadecimal digits. Leading zeros
    /// are not required.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dataplane_hardware::pci::domain::Domain;
    /// #
    /// assert!(Domain::try_from("0000").is_ok());
    /// assert!(Domain::try_from("0").is_ok());      // Leading zeros optional
    /// assert!(Domain::try_from("ffff").is_ok());
    /// assert!(Domain::try_from("10000").is_err()); // Too large
    /// ```
    fn try_from(value: &str) -> Result<Self, PciDomainParseError> {
        let domain = u16::from_str_radix(value, 16).map_err(PciDomainParseError::Syntax)?;
        Ok(Domain(domain))
    }
}
