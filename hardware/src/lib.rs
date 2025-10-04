// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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

pub mod cpu;
pub mod group;
pub mod mem;
pub mod os;
pub mod pci;

pub type ByteCount = NonZero<usize>;

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
    NumaNode(NumaNodeAttributes),
    Cache(CacheAttributes),
    Pci(PciDeviceAttributes),
    Bridge(BridgeAttributes),
    Group(GroupAttributes),
    OsDevice(OsDeviceAttributes),
}

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
