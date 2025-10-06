// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("README.md")]
#![allow(clippy::doc_markdown)] // abbreviations were trigging spurious backtick lints

/// Type of operating system device.
///
/// This enum categorizes OS-visible devices into different types based on
/// their functionality and how they're exposed by the operating system.
///
/// # String Representation
///
/// Device types use string representation (mostly for serialization)
/// - `"storage"` for storage devices
/// - `"gpu"` for graphics processors
/// - `"network"` for network interfaces
/// - etc.
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
    strum::IntoStaticStr,
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "type")
)]
pub enum OsDeviceType {
    /// Block storage devices (disks, SSDs, etc.).
    Storage,
    /// Graphics processing units.
    Gpu,
    /// Network interfaces (Ethernet, WiFi, etc.).
    Network,
    /// High-performance fabric devices (InfiniBand, OmniPath, etc.).
    OpenFabrics,
    /// Direct Memory Access engines.
    Dma,
    /// Specialized compute accelerators.
    CoProcessor,
    /// Memory-like devices (e.g., persistent memory).
    Memory,
}

impl From<OsDeviceType> for String {
    /// Converts the device type to its string representation.
    fn from(value: OsDeviceType) -> Self {
        let x: &'static str = value.into();
        x.into()
    }
}

/// Attributes for an operating system device.
///
/// Contains information about a device as exposed by the operating system,
/// primarily its type classification and os index.
///
/// # Examples
///
/// ```
/// # use dataplane_hardware::os::{OsDeviceType, OsDeviceAttributes};
/// #
/// let gpu = OsDeviceAttributes::new(OsDeviceType::Gpu);
/// println!("Device type: {}", gpu.device_type());
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
pub struct OsDeviceAttributes {
    /// The type of this OS device.
    device_type: OsDeviceType,
}

impl OsDeviceAttributes {
    /// Creates new OS device attributes.
    ///
    /// # Arguments
    ///
    /// * `device_type` - The type of OS device
    #[must_use]
    pub fn new(device_type: OsDeviceType) -> Self {
        Self { device_type }
    }

    /// Returns the type of this OS device.
    #[must_use]
    pub fn device_type(&self) -> &OsDeviceType {
        &self.device_type
    }
}

/// Hardware scanning integration for OS devices.
#[cfg(any(test, feature = "scan"))]
mod scan {
    use hwlocality::object::{attributes::OSDeviceAttributes, types::OSDeviceType};

    use crate::os::{OsDeviceAttributes, OsDeviceType};

    impl TryFrom<OSDeviceType> for OsDeviceType {
        type Error = ();

        /// Attempts to convert from `hwlocality`'s OSDeviceType.
        ///
        /// # Errors
        ///
        /// Returns `Err(())` if the device type is unknown.
        fn try_from(value: OSDeviceType) -> Result<Self, Self::Error> {
            Ok(match value {
                OSDeviceType::Storage => OsDeviceType::Storage,
                OSDeviceType::GPU => OsDeviceType::Gpu,
                OSDeviceType::Network => OsDeviceType::Network,
                OSDeviceType::OpenFabrics => OsDeviceType::OpenFabrics,
                OSDeviceType::DMA => OsDeviceType::Dma,
                OSDeviceType::CoProcessor => OsDeviceType::CoProcessor,
                OSDeviceType::Unknown(_) => Err(())?,
            })
        }
    }

    impl TryFrom<OSDeviceAttributes> for OsDeviceAttributes {
        type Error = ();

        /// Attempts to convert from hwlocality's OSDeviceAttributes.
        ///
        /// # Errors
        ///
        /// Returns `Err(())` if the device type cannot be converted.
        fn try_from(value: OSDeviceAttributes) -> Result<Self, Self::Error> {
            Ok(Self {
                device_type: value.device_type().try_into()?,
            })
        }
    }
}
