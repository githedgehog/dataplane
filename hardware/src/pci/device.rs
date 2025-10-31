// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! PCI device numbers and IDs.
//!
//! This module provides types for PCI device identification:
//! - [`self::device::Device`]: The device number on a bus (5-bit value, 0-31)
//! - [`self::device::DeviceId`]: The 16-bit device ID assigned by the vendor
//!
//! # Device vs Device IDs
//!
//! - **Device number** (`Device`): Identifies the logical position on a bus
//! - **Device ID** (`DeviceId`): Identifies the type/model of the device
//!
//! # Examples
//!
//! ```
//! # use dataplane_hardware::pci::device::{Device, DeviceId};
//! #
//! // Device number (slot on bus)
//! let device = Device::try_from(3).unwrap();
//! assert_eq!(format!("{}", device), "03");
//!
//! // Device ID (model identifier)
//! let device_id = DeviceId::new(0x1db6);  // GTX 1060
//! assert_eq!(format!("{:x}", device_id), "1db6");
//! ```

/// A 16-bit PCI device ID.
///
/// The device ID is assigned by the vendor and identifies the specific model
/// or type of device. Combined with the vendor ID, it uniquely identifies
/// the device type.
///
/// # Examples
///
/// ```
/// use dataplane_hardware::pci::device::DeviceId;
/// use num_traits::FromPrimitive;
///
/// // Create from u16
/// let device_id = DeviceId::new(0x1234);
///
/// // Parse from hex string
/// let parsed = DeviceId::try_from("1234".to_string()).unwrap();
/// assert_eq!(device_id, parsed);
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
    num_derive::FromPrimitive,
    num_derive::ToPrimitive,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "String", into = "String")
)]
#[repr(transparent)]
pub struct DeviceId(u16);

impl DeviceId {
    /// Creates a new device ID.
    #[must_use]
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the raw device ID value.
    #[must_use]
    pub fn value(self) -> u16 {
        self.0
    }
}

impl std::fmt::LowerHex for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

impl From<DeviceId> for String {
    fn from(id: DeviceId) -> Self {
        format!("{:04x}", id.0)
    }
}

impl TryFrom<String> for DeviceId {
    type Error = std::num::ParseIntError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let id = u16::from_str_radix(&value, 16)?;
        Ok(DeviceId(id))
    }
}

/// A PCI device number on a bus.
///
/// The device number identifies a specific device slot on a PCI bus.
/// Valid values are 0-31 (5 bits) as per the PCI specification.
///
/// # Examples
///
/// ```
/// use dataplane_hardware::pci::device::Device;
///
/// // Create from valid u8
/// let device = Device::try_from(15).unwrap();
/// assert_eq!(format!("{:x}", device), "0f");
///
/// // Values above 31 are invalid
/// assert!(Device::try_from(32).is_err());
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
pub struct Device(u8);

impl Device {
    /// Maximum valid device number (31, or 0x1F).
    #[allow(dead_code)]
    pub(crate) const MAX: u8 = 0b11111;

    /// Returns the raw device number value.
    #[must_use]
    pub fn value(self) -> u8 {
        self.0
    }
}

impl std::fmt::LowerHex for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:02x}", self.0)
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:02x}")
    }
}

/// Error type for invalid device numbers.
#[derive(Debug, thiserror::Error)]
pub enum InvalidDevice {
    /// Device number exceeds the 5-bit maximum.
    #[error("Device ID maximum is 5 bits: {0} is too large")]
    TooLarge(u8),
}

/// Error type for device parsing failures.
#[derive(Debug, thiserror::Error)]
pub enum DeviceParseError {
    /// Invalid syntax in the device string.
    #[error("Invalid PCI device syntax: {0}")]
    Syntax(String),
    /// Invalid device number value.
    #[error(transparent)]
    Invalid(InvalidDevice),
}

impl TryFrom<u8> for Device {
    type Error = InvalidDevice;

    /// Creates a device from a u8 value.
    ///
    /// # Errors
    ///
    /// Returns `InvalidDevice::TooLarge` if the value exceeds 31.
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value > 0x1F {
            Err(InvalidDevice::TooLarge(value))
        } else {
            Ok(Self(value))
        }
    }
}

impl TryFrom<&str> for Device {
    type Error = DeviceParseError;

    /// Parses a device number from a hexadecimal string.
    ///
    /// The string must be exactly 2 hexadecimal digits and represent
    /// a value from 00-1F.
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == 2 {
            let device_id = u8::from_str_radix(value, 16).map_err(|_| {
                DeviceParseError::Syntax(format!("Invalid PCI device syntax: {value}"))
            })?;
            Device::try_from(device_id).map_err(DeviceParseError::Invalid)
        } else {
            Err(DeviceParseError::Syntax(value.to_string()))
        }
    }
}

/// Test contract support for property-based testing.
#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::pci::device::Device;

    impl bolero::TypeGenerator for Device {
        fn generate<D: bolero::Driver>(driver: &mut D) -> Option<Self> {
            Some(
                Device::try_from(driver.produce::<u8>()? & Self::MAX)
                    .unwrap_or_else(|_| unreachable!()),
            )
        }
    }
}
