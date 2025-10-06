// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! PCI device addressing.
//!
//! This module provides types and utilities for working with PCI addresses
//! in the standard extended BDF (Bus Device Function) format, also known
//! as EBDF format: `domain:bus:device.function` (e.g., `0000:03:00.0`).
//!
//! # Address Components
//!
//! A PCI address consists of:
//! - **Domain**: 16-bit value (0x0000-0xFFFF)
//! - **Bus**: 8-bit value (0x00-0xFF)
//! - **Device**: 5-bit value (0x00-0x1F), represented as 8-bit
//! - **Function**: 3-bit value (0x0-0x7), represented as 8-bit
//!
//! # Examples
//!
//! ```
//! use dataplane_hardware::pci::address::PciAddress;
//! use std::str::FromStr;
//!
//! // Parse a PCI address
//! let addr = PciAddress::try_from("0000:03:00.0").unwrap();
//! println!("Domain: {:04x}", addr.domain);
//! println!("Bus: {:02x}", addr.bus);
//! println!("Device: {:02x}", addr.device);
//! println!("Function: {:01x}", addr.function);
//!
//! // Convert to EBDF string
//! let ebdf = addr.as_ebdf();
//! assert_eq!(ebdf.to_string(), "0000:03:00.0");
//! ```

use crate::pci::{
    bus::{Bus, BusParseError},
    device::{Device, DeviceParseError},
    domain::{Domain, PciDomainParseError},
    function::{Function, FunctionParseError},
};

/// A PCI device address in the standard format.
///
/// Represents a complete PCI address with all four components:
/// domain, bus, device, and function. Can be parsed from and formatted
/// as a string in the standard format `DDDD:BB:DD.F`.
///
/// # Examples
///
/// ```
/// use dataplane_hardware::pci::address::PciAddress;
/// use dataplane_hardware::pci::{domain::Domain, bus::Bus, device::Device, function::Function};
///
/// // Create from components
/// let addr = PciAddress::new(
///     Domain::new(1),
///     Bus::new(2),
///     Device::try_from(3).unwrap(),
///     Function::try_from(4).unwrap(),
/// );
///
/// // Parse from string
/// let parsed = PciAddress::try_from("0001:02:03.4").unwrap();
/// assert_eq!(addr, parsed);
/// ```
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "&str", into = "String")
)]
pub struct PciAddress {
    /// PCI domain (segment) number.
    pub domain: Domain,
    /// PCI bus number.
    pub bus: Bus,
    /// Device number on the bus.
    pub device: Device,
    /// Function number within the device.
    pub function: Function,
}

impl PciAddress {
    /// Creates a new PCI address from its components.
    #[must_use]
    pub fn new(domain: Domain, bus: Bus, device: Device, function: Function) -> Self {
        Self {
            domain,
            bus,
            device,
            function,
        }
    }

    /// Converts this address to an EBDF string representation.
    #[must_use]
    pub fn as_ebdf(&self) -> PciEbdfString {
        PciEbdfString::from(*self)
    }
}

impl std::fmt::Display for PciAddress {
    /// Formats the PCI address in the standard EBDF format.
    ///
    /// The format is `DDDD:BB:DD.F` where:
    /// - DDDD is the 4-digit hex domain
    /// - BB is the 2-digit hex bus
    /// - DD is the 2-digit hex device
    /// - F is the 1-digit hex function
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:04x}:{:02x}:{:02x}.{:01x}",
            self.domain, self.bus, self.device, self.function
        )
    }
}

/// Errors that can occur when parsing a PCI address.
#[derive(Debug, thiserror::Error)]
pub enum InvalidPciAddress {
    /// Invalid address syntax.
    #[error("Invalid syntax: {0}")]
    Syntax(String),
    /// Invalid domain component.
    #[error(transparent)]
    Domain(PciDomainParseError),
    /// Invalid bus component.
    #[error(transparent)]
    Bus(BusParseError),
    /// Invalid device component.
    #[error(transparent)]
    Device(DeviceParseError),
    /// Invalid function component.
    #[error(transparent)]
    Function(FunctionParseError),
}

impl TryFrom<&str> for PciAddress {
    type Error = InvalidPciAddress;

    /// Parses a PCI address from a string.
    ///
    /// The string must be in the format `DDDD:BB:DD.F` where each letter
    /// represents a hexadecimal digit.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The string contains non-ASCII characters
    /// - The string is not exactly 12 characters long
    /// - The format doesn't match `DDDD:BB:DD.F`
    /// - Any component value is out of range
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.is_ascii() {
            return Err(InvalidPciAddress::Syntax(format!(
                "Invalid ASCII characters in PCI address: {value}",
            )));
        }
        if value.len() != 12 {
            return Err(InvalidPciAddress::Syntax(format!(
                "Invalid PCI address: {value}  (length should be 12, was {})",
                value.len()
            )));
        }
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 3 {
            return Err(InvalidPciAddress::Syntax(format!(
                "Invalid PCI address format (should be domain:bus:device.function): {value} has incorrect shape",
            )));
        }
        let mut last_bit = parts[2].split('.');
        let Some(device_str) = last_bit.next() else {
            return Err(InvalidPciAddress::Syntax(format!(
                "(should be domain:bus:device.function): {value} has no device",
            )));
        };

        let Some(function_str) = last_bit.next() else {
            return Err(InvalidPciAddress::Syntax(format!(
                "(should be domain:bus:device.function): {value} has no function"
            )));
        };

        let domain_str = parts[0];
        let bus_str = parts[1];

        let domain = Domain::try_from(domain_str).map_err(InvalidPciAddress::Domain)?;
        let bus = Bus::try_from(bus_str).map_err(InvalidPciAddress::Bus)?;
        let device = Device::try_from(device_str).map_err(InvalidPciAddress::Device)?;
        let function = Function::try_from(function_str).map_err(InvalidPciAddress::Function)?;

        Ok(Self {
            domain,
            bus,
            device,
            function,
        })
    }
}

impl TryFrom<String> for PciAddress {
    type Error = InvalidPciAddress;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl From<PciAddress> for String {
    fn from(value: PciAddress) -> String {
        format!("{value}")
    }
}

/// A PCI "extended" bus device function string (e.g. "0000:00:03.0").
///
/// This type represents a validated EBDF string that is guaranteed to be
/// in the correct format. It can be converted to and from `PciAddress`.
///
/// # Examples
///
/// ```
/// use dataplane_hardware::pci::address::{PciEbdfString, PciAddress};
///
/// // Parse and validate an EBDF string
/// let ebdf = PciEbdfString::try_new("0000:03:00.0").unwrap();
///
/// // Convert to PciAddress
/// let addr = PciAddress::from(ebdf.clone());
///
/// // Convert back
/// let ebdf2 = addr.as_ebdf();
/// assert_eq!(ebdf, ebdf2);
/// ```
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct PciEbdfString(String);

/// Errors that can occur when parsing a PCI EBDF string.
#[derive(Debug, thiserror::Error)]
pub enum PciEbdfError {
    /// The PCI EBDF string is not valid.
    #[error("Invalid PCI EBDF format: {0}")]
    InvalidFormat(String),
}

impl PciEbdfString {
    /// Parse a string and confirm it is a valid PCI EBDF string.
    ///
    /// The string must be exactly in the format `DDDD:BB:DD.F` where:
    /// - DDDD is a 4-digit hexadecimal domain
    /// - BB is a 2-digit hexadecimal bus
    /// - DD is a 2-digit hexadecimal device
    /// - F is a 1-digit hexadecimal function
    ///
    /// # Errors
    ///
    /// Returns `PciEbdfError::InvalidFormat` if the string is not a valid PCI EBDF string.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::address::PciEbdfString;
    ///
    /// // Valid EBDF strings
    /// assert!(PciEbdfString::try_new("0000:00:00.0").is_ok());
    /// assert!(PciEbdfString::try_new("ffff:ff:1f.7").is_ok());
    ///
    /// // Invalid formats
    /// assert!(PciEbdfString::try_new("0:00:00.0").is_err());     // Domain too short
    /// assert!(PciEbdfString::try_new("0000:0:00.0").is_err());   // Bus too short
    /// assert!(PciEbdfString::try_new("0000:00:00.8").is_err());  // Function out of range
    /// ```
    pub fn try_new(s: impl AsRef<str>) -> Result<PciEbdfString, PciEbdfError> {
        use PciEbdfError::InvalidFormat;
        let s = s.as_ref().to_string();
        if !s.is_ascii() {
            return Err(InvalidFormat(s));
        }
        let split: Vec<_> = s.split(':').collect();
        if split.len() != 3 {
            return Err(InvalidFormat(s));
        }
        let domain = split[0];
        let bus = split[1];
        let dev_and_func = split[2];
        let split: Vec<_> = dev_and_func.split('.').collect();
        if split.len() != 2 {
            return Err(InvalidFormat(s));
        }
        let dev = split[0];
        let func = split[1];
        if domain.len() != 4 || bus.len() != 2 || dev.len() != 2 || func.len() != 1 {
            return Err(InvalidFormat(s));
        }
        if domain.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(InvalidFormat(s));
        }
        if bus.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(InvalidFormat(s));
        }
        if dev.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(InvalidFormat(s));
        }
        if func.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(InvalidFormat(s));
        }
        // check numeric bounds on fields
        match PciAddress::try_from(s.clone()) {
            Ok(_) => Ok(PciEbdfString(s)),
            Err(invalid) => Err(InvalidFormat(format!("{invalid}"))),
        }
    }
}

impl TryFrom<&str> for PciEbdfString {
    type Error = PciEbdfError;

    fn try_from(s: &str) -> Result<Self, PciEbdfError> {
        Self::try_new(s)
    }
}

impl std::fmt::Display for PciEbdfString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<PciAddress> for PciEbdfString {
    fn from(address: PciAddress) -> Self {
        PciEbdfString::try_new(address.to_string()).unwrap_or_else(|_| unreachable!())
    }
}

impl From<PciEbdfString> for PciAddress {
    fn from(ebdf: PciEbdfString) -> Self {
        PciAddress::try_from(ebdf.0).unwrap_or_else(|_| unreachable!())
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use bolero::{Driver, TypeGenerator};

    use crate::pci::address::{PciAddress, PciEbdfString};

    impl TypeGenerator for PciEbdfString {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let domain = driver.produce::<u16>()?;
            let bus = driver.produce::<u8>()?;
            let device = driver.produce::<u8>()?;
            let function = driver.produce::<u8>()?;
            let s = format!("{domain:04x}:{bus:02x}:{device:02x}.{function:02x}");
            PciEbdfString::try_new(s).ok()
        }
    }

    impl bolero::TypeGenerator for PciAddress {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(PciAddress {
                domain: driver.produce()?,
                bus: driver.produce()?,
                device: driver.produce()?,
                function: driver.produce()?,
            })
        }
    }
}
