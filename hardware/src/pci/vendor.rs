// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! PCI vendor IDs.
//!
//! This module provides the [`VendorId`] type for representing 16-bit PCI
//! vendor identifiers. Vendor IDs are assigned by the PCI-SIG (PCI Special
//! Interest Group) to uniquely identify device manufacturers.
//!
//! # Examples
//!
//! ```
//! use dataplane_hardware::pci::vendor::VendorId;
//! use num_traits::FromPrimitive;
//!
//! // Intel vendor ID
//! let intel = VendorId::new(0x8086);
//! assert_eq!(format!("{}", intel), "8086");
//!
//! // Parse from hex string
//! let vendor = VendorId::try_from("10de".to_string()).unwrap();
//! assert_eq!(vendor, VendorId::new(0x10de));  // NVIDIA
//! ```

/// A 16-bit PCI vendor identifier.
///
/// Vendor IDs are assigned by the PCI-SIG to uniquely identify device
/// manufacturers. The special value `0xFFFF` is reserved and indicates
/// an invalid/non-existent device.
///
/// # Display
///
/// The `Display` and `LowerHex` implementations format the vendor ID
/// as a 4-digit hexadecimal value with leading zeros.
///
/// # Examples
///
/// ```
/// use dataplane_hardware::pci::vendor::VendorId;
///
/// let vendor = VendorId::new(0x8086);
/// assert_eq!(format!("{}", vendor), "8086");
/// assert_eq!(format!("{:x}", vendor), "8086");
///
/// // Convert to string
/// let s: String = vendor.into();
/// assert_eq!(s, "8086");
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
pub struct VendorId(u16);

impl VendorId {
    /// Creates a new vendor ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::vendor::VendorId;
    ///
    /// let vendor = VendorId::new(0x1022);  // AMD
    /// assert_eq!(vendor.value(), 0x1022);
    /// ```
    pub fn new(id: u16) -> Self {
        Self(id)
    }

    /// Returns the raw vendor ID value.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::vendor::VendorId;
    ///
    /// let vendor = VendorId::new(0x10de);  // NVIDIA
    /// assert_eq!(vendor.value(), 0x10de);
    /// ```
    pub fn value(self) -> u16 {
        self.0
    }

    /// Checks if this vendor ID is the reserved invalid value.
    ///
    /// The PCI specification reserves `0xFFFF` as an invalid vendor ID
    /// that indicates a non-existent or unconfigured device.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::vendor::VendorId;
    ///
    /// let valid = VendorId::new(0x8086);
    /// let invalid = VendorId::new(0xFFFF);
    ///
    /// assert!(!valid.is_invalid());
    /// assert!(invalid.is_invalid());
    /// ```
    pub fn is_invalid(self) -> bool {
        self.0 == 0xFFFF
    }
}

impl std::fmt::LowerHex for VendorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

impl std::fmt::Display for VendorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self)
    }
}

impl Into<String> for VendorId {
    /// Converts the vendor ID to a 4-digit hexadecimal string.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::vendor::VendorId;
    ///
    /// let vendor = VendorId::new(0x14e4);  // Broadcom
    /// let s: String = vendor.into();
    /// assert_eq!(s, "14e4");
    /// ```
    fn into(self) -> String {
        format!("{:04x}", self.0)
    }
}

impl TryFrom<String> for VendorId {
    type Error = std::num::ParseIntError;

    /// Parses a vendor ID from a hexadecimal string.
    ///
    /// The string should contain 1-4 hexadecimal digits. Leading zeros
    /// are not required.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::vendor::VendorId;
    ///
    /// // Parse with leading zeros
    /// let v1 = VendorId::try_from("8086".to_string()).unwrap();
    /// assert_eq!(v1, VendorId::new(0x8086));
    ///
    /// // Parse without leading zeros
    /// let v2 = VendorId::try_from("1022".to_string()).unwrap();
    /// assert_eq!(v2, VendorId::new(0x1022));
    ///
    /// // Invalid hex string
    /// assert!(VendorId::try_from("GGGG".to_string()).is_err());
    /// ```
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let id = u16::from_str_radix(&value, 16)?;
        Ok(VendorId(id))
    }
}
