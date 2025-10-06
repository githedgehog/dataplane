// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! PCI bridge types and attributes.
//!
//! This module provides types for representing PCI bridges, which are devices
//! that connect different PCI buses together. Bridges can be either host bridges
//! (connecting the CPU to the PCI bus) or PCI-to-PCI bridges.
//!
//! # Bridge Types
//!
//! - **Host Bridge**: Connects the host CPU to the PCI bus system
//! - **PCI Bridge**: Connects one PCI bus to another PCI bus
//!
//! # Examples
//!
//! ```
//! use dataplane_hardware::pci::bridge::{BridgeType, BridgeAttributes};
//!
//! // Check bridge type
//! let bridge_type = BridgeType::Host;
//! assert!(bridge_type.is_host());
//! ```

use crate::pci::PciDeviceAttributes;

/// Type of PCI bridge.
///
/// Bridges in PCI systems connect different buses together. The two main types are:
/// - Host bridges that connect the CPU to the PCI bus system
/// - PCI-to-PCI bridges that connect PCI buses together
///
/// # String Representation
///
/// Bridge types use lowercase string representation:
/// - `"host"` for host bridges
/// - `"pci"` for PCI-to-PCI bridges
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
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
    strum::FromRepr,
    strum::IntoStaticStr,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "type")
)]
pub enum BridgeType {
    /// PCI-to-PCI bridge connecting two PCI buses.
    Pci,
    /// Host bridge connecting the CPU to the PCI bus.
    Host,
}

impl From<BridgeType> for String {
    fn from(value: BridgeType) -> Self {
        match value {
            BridgeType::Pci => "pci".to_string(),
            BridgeType::Host => "host".to_string(),
        }
    }
}

impl TryFrom<String> for BridgeType {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(match value.as_str() {
            "pci" => BridgeType::Pci,
            "host" => BridgeType::Host,
            _ => return Err(()),
        })
    }
}

/// Attributes for a PCI bridge device.
///
/// Contains information about the bridge including its upstream and downstream
/// connection types, and optional upstream device attributes if it's a PCI bridge.
///
/// # Examples
///
/// ```
/// use dataplane_hardware::pci::bridge::{BridgeType, BridgeAttributes};
///
/// // Create attributes for a PCI-to-PCI bridge
/// let bridge = BridgeAttributes::new(
///     BridgeType::Pci,
///     BridgeType::Pci,
///     None,
/// );
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
pub struct BridgeAttributes {
    upstream_type: BridgeType,
    downstream_type: BridgeType,
    upstream_attributes: Option<PciDeviceAttributes>,
}

impl BridgeAttributes {
    /// Creates new bridge attributes.
    ///
    /// # Arguments
    ///
    /// * `upstream_type` - Type of the upstream connection
    /// * `downstream_type` - Type of the downstream connection
    /// * `upstream_attributes` - Optional PCI device attributes for the upstream side
    #[must_use]
    pub fn new(
        upstream_type: BridgeType,
        downstream_type: BridgeType,
        upstream_attributes: Option<PciDeviceAttributes>,
    ) -> Self {
        Self {
            upstream_type,
            downstream_type,
            upstream_attributes,
        }
    }

    /// Returns the type of the upstream connection.
    #[must_use]
    pub fn upstream_type(&self) -> BridgeType {
        self.upstream_type
    }

    /// Returns the type of the downstream connection.
    #[must_use]
    pub fn downstream_type(&self) -> BridgeType {
        self.downstream_type
    }

    /// Returns the upstream PCI device attributes, if available.
    #[must_use]
    pub fn upstream_attributes(&self) -> Option<&PciDeviceAttributes> {
        self.upstream_attributes.as_ref()
    }
}

/// Hardware scanning integration for bridges.
#[cfg(any(test, feature = "scan"))]
mod scan {
    #[allow(clippy::wildcard_imports)] // transparently re-exported above
    use super::*;
    use hwlocality::object::attributes::UpstreamAttributes;

    impl TryFrom<hwlocality::object::attributes::BridgeAttributes> for BridgeAttributes {
        type Error = ();

        /// Attempts to convert from hwlocality's [`hwlocality::object::attributes::BridgeAttributes`].
        ///
        /// # Errors
        ///
        /// Returns `Err(())` if the bridge type cannot be converted.
        fn try_from(
            value: hwlocality::object::attributes::BridgeAttributes,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                upstream_type: value.upstream_type().try_into()?,
                downstream_type: value.downstream_type().try_into()?,
                upstream_attributes: value
                    .upstream_attributes()
                    .map(|UpstreamAttributes::PCI(&p)| p.into()),
            })
        }
    }

    impl TryFrom<hwlocality::object::types::BridgeType> for BridgeType {
        type Error = ();

        /// Attempts to convert from hwlocality's [`hwlocality::object::types::BridgeType`].
        ///
        /// # Errors
        ///
        /// Returns `Err(())` if the bridge type is unknown.
        fn try_from(value: hwlocality::object::types::BridgeType) -> Result<Self, Self::Error> {
            Ok(match value {
                hwlocality::object::types::BridgeType::PCI => BridgeType::Pci,
                hwlocality::object::types::BridgeType::Host => BridgeType::Host,
                hwlocality::object::types::BridgeType::Unknown(_) => Err(())?,
            })
        }
    }
}
