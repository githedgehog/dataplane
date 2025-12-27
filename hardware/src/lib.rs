// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
// # Hardware topology discovery and representation

//! The `hardware` crate provides a unified interface for discovering and representing
//! system hardware topology, including CPU architecture, memory hierarchy, PCI devices,
//! and operating system devices. It builds a hierarchical tree structure representing
//! the relationships between different hardware components.
//!
//! ## Overview
//!
//! This crate is designed to provide detailed information about system hardware topology
//! that is useful for:
//!
//! - **Performance optimization**: Understanding cache hierarchy and NUMA topology
//! - **Device management**: Enumerating and identifying PCI devices and OS devices
//! - **Resource allocation**: Making informed decisions about CPU affinity and memory
//!   allocation
//! - **System monitoring**: Gathering hardware configuration information
//!
//! ## Architecture
//!
//! The crate represents hardware topology as a tree of `Node`s, where each node has:
//!
//! - A unique identifier
//! - A type and optional subtype
//! - Optional attributes specific to the hardware component
//! - Zero or more child nodes
//!
//! Node types include:
//!
//! - **NUMA nodes**: Non-Uniform Memory Access regions
//! - **Caches**: L1, L2, L3 cache levels
//! - **PCI devices**: Graphics cards, network adapters, etc.
//! - **Bridges**: PCI bridges connecting different buses
//! - **Groups**: Logical groupings of hardware components
//! - **OS devices**: Block devices, network interfaces, etc.
//!
//! ## Features
//!
//! - `scan`: Enables hardware topology scanning using the `hwlocality` crate.
//!   This allows runtime discovery of the system's hardware configuration.
//! - `serde`: Adds serialization support for all types using serde.
//! - `bolero`: Enables fuzzing support for testing.

#![deny(clippy::pedantic, clippy::unwrap_used)]

use id::Id;
use std::collections::BTreeMap;
use std::num::NonZero;

use crate::group::GroupAttributes;
use crate::mem::cache::CacheAttributes;
use crate::mem::numa::NumaNodeAttributes;
use crate::os::OsDeviceAttributes;
use crate::pci::PciDeviceAttributes;
use crate::pci::bridge::BridgeAttributes;

pub mod group;
pub mod mem;
pub mod nic;
pub mod os;
pub mod pci;
pub mod support;

#[cfg(any(test, feature = "scan"))]
pub mod scan;

/// A non-zero byte count used throughout the crate for memory sizes.
///
/// Using `NonZero` ensures that zero-byte sizes are not representable,
/// which helps catch errors at compile time.
pub type ByteCount = NonZero<usize>;

/// Hardware component attributes for different node types.
///
/// This enum encapsulates the specific attributes associated with different
/// types of hardware components in the system topology. Each variant contains
/// the detailed information specific to that hardware type.
///
/// # Examples
///
/// ```
/// # use dataplane_hardware::NodeAttributes;
/// #
/// fn print_node_info(attrs: &NodeAttributes) {
///     match attrs {
///         NodeAttributes::NumaNode(numa) => {
///             println!("NUMA node with {:?} bytes of memory", numa.local_memory());
///         }
///         NodeAttributes::Cache(cache) => {
///             println!("Cache: {} ({} bytes)", cache.cache_type(), cache.size());
///         }
///         NodeAttributes::Pci(pci) => {
///             println!("PCI device: {:04x}:{:04x}", pci.vendor_id(), pci.device_id());
///         }
///         _ => {}
///     }
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
    strum::Display,
    strum::EnumIs,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "type")
)]
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
        __C::Error: rkyv::rancor::Source,
    )
))]
pub enum NodeAttributes {
    /// Attributes for a NUMA (Non-Uniform Memory Access) node.
    NumaNode(NumaNodeAttributes),
    /// Attributes for a CPU cache (L1, L2, L3, etc.).
    Cache(CacheAttributes),
    /// Attributes for a PCI device.
    Pci(PciDeviceAttributes),
    /// Attributes for a PCI bridge.
    Bridge(BridgeAttributes),
    /// Attributes for a logical hardware group.
    Group(GroupAttributes),
    /// Attributes for an operating system device.
    OsDevice(OsDeviceAttributes),
}

/// A node in the hardware topology tree.
///
/// Each node represents a hardware component in the system and can have:
/// - A unique identifier
/// - A type (e.g., `"Cache"`, `"NUMANode"`, `"PCIDevice"`)
/// - An optional subtype for more specific categorization
/// - Optional OS-assigned index
/// - Optional human-readable name
/// - Key-value properties for additional metadata
/// - Optional attributes specific to the node type
/// - Zero or more child nodes
///
/// The tree structure represents the hierarchical relationships between
/// hardware components. For example, a NUMA node might contain CPU cores,
/// which contain caches, and so on.
///
/// # Examples
///
/// ```
/// # use dataplane_hardware::Node;
/// #
/// fn count_caches(node: &Node) -> usize {
///     let mut count = 0;
///     if node.type_() == "Cache" {
///         count = 1;
///     }
///     for child in node.children() {
///         count += count_caches(child);
///     }
///     count
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
#[rkyv(serialize_bounds(
    __S: rkyv::ser::Writer + rkyv::ser::Allocator,
    __S::Error: rkyv::rancor::Source,
))]
#[rkyv(deserialize_bounds(__D::Error: rkyv::rancor::Source))]
#[rkyv(bytecheck(
    bounds(
        __C: rkyv::validation::ArchiveContext,
        __C::Error: rkyv::rancor::Source,
    )
))]
pub struct Node {
    id: Id<Node, u64>,
    #[cfg_attr(any(test, feature = "serde"), serde(rename = "type"))]
    type_: String,
    #[cfg_attr(
        any(test, feature = "serde"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    subtype: Option<String>,
    #[cfg_attr(
        any(test, feature = "serde"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    os_index: Option<usize>,
    #[cfg_attr(
        any(test, feature = "serde"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    name: Option<String>,
    #[cfg_attr(
        any(test, feature = "serde"),
        serde(skip_serializing_if = "BTreeMap::is_empty")
    )]
    properties: BTreeMap<String, String>,
    #[cfg_attr(
        any(test, feature = "serde"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    attributes: Option<NodeAttributes>,
    #[cfg_attr(
        any(test, feature = "serde"),
        serde(skip_serializing_if = "Vec::is_empty")
    )]
    #[rkyv(omit_bounds)]
    children: Vec<Node>,
}

impl Node {
    /// Returns the unique identifier for this node.
    #[must_use]
    pub fn id(&self) -> Id<Node, u64> {
        self.id
    }

    /// Returns the type of this node (e.g., `"Cache"`, `"NUMANode"`, `"PCIDevice"`).
    #[must_use]
    pub fn type_(&self) -> &str {
        &self.type_
    }

    /// Returns the optional subtype providing more specific categorization.
    #[must_use]
    pub fn subtype(&self) -> Option<&str> {
        self.subtype.as_deref()
    }

    /// Returns the OS-assigned index for this node, if available.
    ///
    /// This is typically used for components that have OS-visible indices,
    /// such as CPU cores or network interfaces.
    #[must_use]
    pub fn os_index(&self) -> Option<usize> {
        self.os_index
    }

    /// Returns the human-readable name of this node, if available.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the key-value properties associated with this node.
    ///
    /// Properties provide additional metadata that doesn't fit into the
    /// structured attributes, such as vendor-specific information.
    #[must_use]
    pub fn properties(&self) -> &BTreeMap<String, String> {
        &self.properties
    }

    /// Returns the specific attributes for this node type, if available.
    #[must_use]
    pub fn attributes(&self) -> Option<&NodeAttributes> {
        self.attributes.as_ref()
    }

    /// Returns a slice of this node's children.
    #[must_use]
    pub fn children(&self) -> &[Node] {
        &self.children
    }
}
