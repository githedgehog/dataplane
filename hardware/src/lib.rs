// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
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
pub mod os;
pub mod pci;

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
/// use dataplane_hardware::NodeAttributes;
///
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
/// - A type (e.g., "Cache", "NUMANode", "PCIDevice")
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
/// use dataplane_hardware::Node;
///
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
    pub fn id(&self) -> Id<Node, u64> {
        self.id
    }

    /// Returns the type of this node (e.g., "Cache", "NUMANode", "PCIDevice").
    pub fn type_(&self) -> &str {
        &self.type_
    }

    /// Returns the optional subtype providing more specific categorization.
    pub fn subtype(&self) -> Option<&str> {
        self.subtype.as_deref()
    }

    /// Returns the OS-assigned index for this node, if available.
    ///
    /// This is typically used for components that have OS-visible indices,
    /// such as CPU cores or network interfaces.
    pub fn os_index(&self) -> Option<usize> {
        self.os_index
    }

    /// Returns the human-readable name of this node, if available.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the key-value properties associated with this node.
    ///
    /// Properties provide additional metadata that doesn't fit into the
    /// structured attributes, such as vendor-specific information.
    pub fn properties(&self) -> &BTreeMap<String, String> {
        &self.properties
    }

    /// Returns the specific attributes for this node type, if available.
    pub fn attributes(&self) -> Option<&NodeAttributes> {
        self.attributes.as_ref()
    }

    /// Returns a slice of this node's children.
    pub fn children(&self) -> &[Node] {
        &self.children
    }

    /// Returns an iterator over all descendants of this node.
    pub fn descendants(&self) -> impl Iterator<Item = &Node> {
        self.children.iter()
    }
}

/// Hardware topology scanning support.
///
/// This module provides integration with the `hwlocality` crate for
/// discovering system hardware topology at runtime.
#[cfg(any(test, feature = "scan"))]
mod scan {
    use super::*;
    use hwlocality::object::{TopologyObject, attributes::ObjectAttributes};

    impl TryFrom<ObjectAttributes<'_>> for NodeAttributes {
        type Error = ();

        fn try_from(value: ObjectAttributes) -> Result<Self, ()> {
            Ok(match value {
                ObjectAttributes::NUMANode(&x) => Self::NumaNode(x.into()),
                ObjectAttributes::Cache(&x) => Self::Cache(x.try_into().map_err(|_| {
                    eprintln!("failed to convert cache attributes");
                })?),
                ObjectAttributes::Group(&x) => Self::Group(x.into()),
                ObjectAttributes::PCIDevice(&x) => Self::Pci(x.into()),
                ObjectAttributes::Bridge(&x) => Self::Bridge(x.try_into().map_err(|_| {
                    eprintln!("failed to convert bridge attributes");
                })?),
                ObjectAttributes::OSDevice(&x) => Self::OsDevice(x.try_into().map_err(|_| {
                    eprintln!("failed to convert os device attributes");
                })?),
            })
        }
    }

    impl<'a> From<&'a TopologyObject> for Node {
        fn from(value: &'a TopologyObject) -> Self {
            Node {
                id: Id::from(value.global_persistent_index()),
                os_index: value.os_index(),
                name: value.name().map(|x| x.to_string_lossy().to_string()),
                type_: value.object_type().to_string(),
                subtype: value.subtype().map(|x| x.to_string_lossy().to_string()),
                properties: value
                    .infos()
                    .iter()
                    .map(|x| {
                        (
                            x.name().to_string_lossy().to_string(),
                            x.value().to_string_lossy().to_string(),
                        )
                    })
                    .collect(),
                attributes: value
                    .attributes()
                    .and_then(|x| NodeAttributes::try_from(x).ok()),
                children: value.all_children().map(Node::from).collect(),
            }
        }
    }
}
