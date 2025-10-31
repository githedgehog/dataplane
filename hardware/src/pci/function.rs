// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! PCI function numbers.
//!
//! This module provides the [`self::function::Function`] type for representing PCI
//! function numbers.
//! PCI devices can implement up to 8 functions (0-7), allowing a single physical
//! device to appear as multiple logical devices.
//!
//! # Multi-function Devices
//!
//! Many PCI devices implement multiple functions:
//! - Network cards might have multiple ports as different functions
//! - Graphics cards might separate display and audio functions
//! - Storage controllers might have different functions for different channels
//!
//! # Examples
//!
//! ```
//! # use dataplane_hardware::pci::function::Function;
//! #
//! // Create function 0 (most common)
//! let func0 = Function::try_from(0).unwrap();
//! assert_eq!(format!("{}", func0), "0");
//!
//! // Parse from hex string
//! let func3 = Function::try_from("3").unwrap();
//! assert_eq!(format!("{:x}", func3), "3");
//! ```

/// A PCI function number.
///
/// PCI functions are numbered 0-7, allowing up to 8 logical functions per
/// physical device. Function 0 is always present if the device exists.
/// Functions 1-7 are only present on multi-function devices.
///
/// The function number is a 3-bit value displayed as a single hexadecimal digit.
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
#[repr(transparent)]
#[rkyv(attr(derive(PartialEq, Eq, Debug)))]
pub struct Function(u8);

impl Function {
    /// Maximum valid function number (7, or 0b111).
    #[allow(dead_code)]
    const MAX: u8 = 0b111;

    /// Returns the raw function number value.
    #[must_use]
    pub fn value(self) -> u8 {
        self.0
    }
}

/// Error type for invalid function numbers.
#[derive(Debug, thiserror::Error)]
pub enum InvalidPciFunction {
    /// Function number exceeds the 3-bit maximum.
    #[error("Function maximum is 3 bits (0-7): {0} is too large")]
    TooLarge(u8),
}

impl std::fmt::LowerHex for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:01x}", self.0)
    }
}

impl std::fmt::Display for Function {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:01x}")
    }
}

impl TryFrom<u8> for Function {
    type Error = InvalidPciFunction;

    /// Creates a function from a u8 value.
    ///
    /// # Errors
    ///
    /// Returns `InvalidPciFunction::TooLarge` if the value exceeds 7.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 7 {
            Err(InvalidPciFunction::TooLarge(value))
        } else {
            Ok(Function(value))
        }
    }
}

/// Error type for function parsing failures.
#[derive(Debug, thiserror::Error)]
pub enum FunctionParseError {
    /// Invalid syntax in the function string.
    #[error("Invalid pci function syntax: {0}")]
    InvalidSyntax(String),
    /// Invalid function number value.
    #[error(transparent)]
    InvalidFunction(InvalidPciFunction),
}

impl TryFrom<&str> for Function {
    type Error = FunctionParseError;

    /// Parses a function number from a hexadecimal string.
    ///
    /// The string must be exactly 1 hexadecimal digit from 0-7.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::function::Function;
    ///
    /// assert!(Function::try_from("0").is_ok());
    /// assert!(Function::try_from("7").is_ok());
    /// assert!(Function::try_from("8").is_err());  // Too large
    /// assert!(Function::try_from("00").is_err()); // Wrong length
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == 1 {
            let value = u8::from_str_radix(value, 16).map_err(|_| {
                FunctionParseError::InvalidSyntax(format!(
                    "{value} is illegal; should be a single digit between 0 and 7"
                ))
            })?;
            Function::try_from(value).map_err(FunctionParseError::InvalidFunction)
        } else {
            Err(FunctionParseError::InvalidSyntax(format!(
                "length for pci function: {value} is illegal; should be a single digit between 0 and 7"
            )))
        }
    }
}

/// Test contract support for property-based testing.
#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::pci::function::Function;

    impl bolero::TypeGenerator for Function {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(
                Function::try_from(driver.produce::<u8>()? & Self::MAX)
                    .unwrap_or_else(|_| unreachable!()),
            )
        }
    }
}
