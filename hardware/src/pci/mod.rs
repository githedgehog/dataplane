// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("README.md")]

use crate::pci::{address::PciAddress, device::DeviceId, vendor::VendorId};

/// PCI addressing components and parsing.
pub mod address;
/// PCI bridge types and attributes.
pub mod bridge;
/// PCI bus representation.
pub mod bus;
/// PCI device IDs and related types.
pub mod device;
/// PCI domain (segment) representation.
pub mod domain;
/// PCI function numbers.
pub mod function;
/// PCI vendor IDs.
pub mod vendor;

/// Attributes for a PCI device.
///
/// Contains comprehensive information about a PCI device including its
/// address, vendor/device identification, and link speed.
///
/// # Examples
///
/// ```
/// # use dataplane_hardware::pci::PciDeviceAttributes;
/// #
/// fn print_pci_info(device: &PciDeviceAttributes) {
///     println!("PCI Device at {}", device.address());
///     println!("Vendor: {:04x} {}",
///         device.device_description().vendor_id,
///         device.device_description().vendor_name.as_deref().unwrap_or("Unknown"));
///     println!("Link Speed: {}", device.link_speed());
/// }
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
pub struct PciDeviceAttributes {
    address: PciAddress,
    revision: u8,
    link_speed: String,
}

impl PciDeviceAttributes {
    /// Returns the PCI address of this device.
    pub fn address(&self) -> PciAddress {
        self.address
    }

    /// Returns the revision number of this device.
    pub fn revision(&self) -> u8 {
        self.revision
    }

    /// Returns the PCIe link speed as a string (e.g., "8.0 GT/s").
    pub fn link_speed(&self) -> &str {
        &self.link_speed
    }
}

/// Description of a PCI device including vendor and device information.
///
/// This struct contains both the numeric IDs and optional human-readable
/// names for PCI devices. The names are typically resolved from the PCI ID
/// database when available.
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
pub struct PciDeviceDescription {
    /// The PCI vendor ID.
    pub vendor_id: VendorId,
    /// Human-readable vendor name, if known.
    pub vendor_name: Option<String>,
    /// The PCI device ID.
    pub device_id: DeviceId,
    /// Human-readable device name, if known.
    pub device_name: Option<String>,
}
