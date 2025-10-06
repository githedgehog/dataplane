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
//! # use dataplane_hardware::pci::vendor::VendorId;
//! # use num_traits::FromPrimitive;
//!
//! // Intel vendor ID
//! let intel = VendorId::new(0x8086).unwrap();
//! assert_eq!(format!("{}", intel), "8086");
//!
//! // Parse from hex string
//! let vendor = VendorId::try_from("10de".to_string()).unwrap();
//! assert_eq!(vendor, VendorId::new(0x10de).unwrap());  // NVIDIA
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
/// # use dataplane_hardware::pci::vendor::VendorId;
/// #
/// let vendor = VendorId::new(0x8086).unwrap();
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

#[derive(Debug, thiserror::Error)]
#[error("The vendor 0xFFFF is reserved as an invalid vendor ID")]
pub struct InvalidVendorId;

impl VendorId {
    /// Creates a new vendor ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the vendor ID is `0xFFFF` (the invalid vendor ID).
    ///
    /// # Examples
    ///
    /// ```
    /// # use dataplane_hardware::pci::vendor::VendorId;
    /// #
    /// let vendor = VendorId::new(0x1022).unwrap();  // AMD
    /// assert_eq!(vendor.value(), 0x1022);
    /// ```
    pub fn new(id: u16) -> Result<Self, InvalidVendorId> {
        if id == u16::MAX {
            Err(InvalidVendorId)
        } else {
            Ok(Self(id))
        }
    }

    /// Returns the raw vendor ID value.
    ///
    /// # Examples
    ///
    /// ```
    /// use dataplane_hardware::pci::vendor::VendorId;
    ///
    /// let vendor = VendorId::new(0x10de).unwrap();  // NVIDIA
    /// assert_eq!(vendor.value(), 0x10de);
    /// ```
    #[must_use]
    pub fn value(self) -> u16 {
        self.0
    }
}

impl std::fmt::LowerHex for VendorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04x}", self.0)
    }
}

impl std::fmt::Display for VendorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:04x}")
    }
}

impl From<VendorId> for String {
    /// Converts the vendor ID to a 4-digit hexadecimal string.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dataplane_hardware::pci::vendor::VendorId;
    /// #
    /// let vendor = VendorId::new(0x14e4).unwrap();  // Broadcom
    /// let s: String = vendor.into();
    /// assert_eq!(s, "14e4");
    /// ```
    fn from(value: VendorId) -> String {
        format!("{:04x}", value.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VendorIdParseError {
    #[error(transparent)]
    InvalidSyntax(std::num::ParseIntError),
    #[error(transparent)]
    ReservedInvalid(InvalidVendorId),
}

impl TryFrom<String> for VendorId {
    type Error = VendorIdParseError;

    /// Parses a vendor ID from a hexadecimal string.
    ///
    /// The string should contain 1-4 hexadecimal digits. Leading zeros
    /// are not required.
    ///
    /// # Examples
    ///
    /// ```
    /// # use dataplane_hardware::pci::vendor::VendorId;
    /// #
    /// // Parse with leading zeros
    /// let v1 = VendorId::try_from("8086".to_string()).unwrap();
    /// assert_eq!(v1, VendorId::new(0x8086).unwrap());
    ///
    /// // Parse without leading zeros
    /// let v2 = VendorId::try_from("1022".to_string()).unwrap();
    /// assert_eq!(v2, VendorId::new(0x1022).unwrap());
    ///
    /// // Invalid hex string
    /// assert!(VendorId::try_from("GGGG".to_string()).is_err());
    /// ```
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let id = u16::from_str_radix(&value, 16).map_err(VendorIdParseError::InvalidSyntax)?;
        VendorId::new(id).map_err(VendorIdParseError::ReservedInvalid)
    }
}
