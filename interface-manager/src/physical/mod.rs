// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::pedantic, clippy::unwrap_used)]

use hwlocality::object::TopologyObject;
use hwlocality::object::attributes::{
    NUMANodeAttributes, OSDeviceAttributes, ObjectAttributes, PCIDeviceAttributes,
    UpstreamAttributes,
};
use hwlocality::object::types::OSDeviceType;
use id::Id;
use num_traits::FromPrimitive;
use pci_ids::{Device, FromId, Vendor};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZero;

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
    serde::Deserialize,
    serde::Serialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct VendorId(u16);

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
    serde::Deserialize,
    serde::Serialize,
)]
#[repr(transparent)]
#[serde(transparent)]
pub struct DeviceId(u16);

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
    serde::Deserialize,
    serde::Serialize,
)]
pub struct NumaNodeAttributes {
    local_memory: Option<NonZero<u64>>,
    page_types: BTreeSet<MemoryPageType>,
}

impl<'a> From<NUMANodeAttributes<'a>> for NumaNodeAttributes {
    fn from(value: NUMANodeAttributes<'a>) -> Self {
        Self {
            local_memory: value.local_memory(),
            page_types: value.page_types().iter().map(|x| (*x).into()).collect(),
        }
    }
}

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
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(attr(derive(PartialEq, Eq, PartialOrd, Ord)))]
pub struct MemoryPageType {
    size: NonZero<u64>,
    count: u64,
}

impl From<hwlocality::object::attributes::MemoryPageType> for MemoryPageType {
    fn from(value: hwlocality::object::attributes::MemoryPageType) -> Self {
        Self {
            size: value.size(),
            count: value.count(),
        }
    }
}

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
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
    strum::FromRepr,
    strum::IntoStaticStr,
)]
#[serde(try_from = "&str", into = "&'static str")]
#[strum(serialize_all = "lowercase")]
pub enum CacheType {
    /// Unified cache
    Unified,
    /// Data cache
    Data,
    /// Instruction cache
    Instruction,
}

impl From<CacheType> for String {
    fn from(value: CacheType) -> Self {
        let value: &'static str = value.into();
        value.to_string()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[error("invalid cache type: {0:?}")]
pub struct InvalidCacheType(String);

impl TryFrom<hwlocality::object::types::CacheType> for CacheType {
    type Error = InvalidCacheType;

    fn try_from(value: hwlocality::object::types::CacheType) -> Result<Self, Self::Error> {
        Ok(match value {
            hwlocality::object::types::CacheType::Unified => CacheType::Unified,
            hwlocality::object::types::CacheType::Data => CacheType::Data,
            hwlocality::object::types::CacheType::Instruction => CacheType::Instruction,
            _ => return Err(InvalidCacheType("unknown".to_string()))?,
        })
    }
}

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
    serde::Deserialize,
    serde::Serialize,
)]
pub struct CacheAttributes {
    cache_type: CacheType,
    size: NonZero<u64>,
    line_size: Option<NonZero<usize>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InvalidCacheAttributes;

impl TryFrom<hwlocality::object::attributes::CacheAttributes> for CacheAttributes {
    type Error = InvalidCacheAttributes;

    fn try_from(
        value: hwlocality::object::attributes::CacheAttributes,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            cache_type: CacheType::try_from(value.cache_type())
                .map_err(|_| InvalidCacheAttributes)?,
            size: match value.size() {
                None => return Err(InvalidCacheAttributes),
                Some(size) => size,
            },
            line_size: value.line_size(),
        })
    }
}

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
    serde::Deserialize,
    serde::Serialize,
)]
#[serde(transparent)]
pub struct GroupAttributes {
    depth: usize,
}

impl From<hwlocality::object::attributes::GroupAttributes> for GroupAttributes {
    fn from(value: hwlocality::object::attributes::GroupAttributes) -> Self {
        Self {
            depth: value.depth(),
        }
    }
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
    serde::Deserialize,
    serde::Serialize,
)]
pub struct PciDeviceAttributes {
    vendor_name: Option<String>,
    device_name: Option<String>,
    vendor_id: VendorId,
    device_id: DeviceId,
    revision: u8,
    subvendor_id: VendorId,
    subdevice_id: DeviceId,
    sub_vendor_name: Option<String>,
    sub_device_name: Option<String>,
    bus_device: u8,
    bus_id: u8,
    domain: u16,
    function: u8,
    class_id: u16,
    link_speed: String,
}

pub mod pci_address {

    #[derive(
        Clone,
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
        serde::Deserialize,
        serde::Serialize,
    )]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct Domain(u16);

    impl std::fmt::Display for Domain {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:04x}", self.0)
        }
    }

    #[derive(
        Clone,
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
        serde::Deserialize,
        serde::Serialize,
    )]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct Bus(u8);

    impl std::fmt::Display for Bus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:02x}", self.0)
        }
    }

    #[derive(
        Clone,
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
        serde::Deserialize,
        serde::Serialize,
    )]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct Device(u8);

    impl std::fmt::Display for Device {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:02x}", self.0)
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum InvalidDevice {
        #[error("Device ID maximum is 5 bits: {0} is too large")]
        TooLarge(u8),
    }

    impl TryFrom<u8> for Device {
        type Error = InvalidDevice;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            if value > 0x1F {
                Err(InvalidDevice::TooLarge(value))
            } else {
                Ok(Self(value))
            }
        }
    }

    #[derive(
        Clone,
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
        serde::Deserialize,
        serde::Serialize,
    )]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct Function(u8);

    #[derive(Debug, thiserror::Error)]
    pub enum InvalidFunction {
        #[error("Function number maximum is 3 bits (0-7): {0} is too large")]
        TooLarge(u8),
    }

    impl std::fmt::Display for Function {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:02x}", self.0)
        }
    }

    impl TryFrom<u8> for Function {
        type Error = InvalidFunction;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            if value > 7 {
                Err(InvalidFunction::TooLarge(value))
            } else {
                Ok(Function(value))
            }
        }
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
        serde::Deserialize,
        serde::Serialize,
    )]
    pub struct PciAddress {
        pub domain: Domain,
        pub bus: Bus,
        pub device: Device,
        pub function: Function,
    }

    impl std::fmt::Display for PciAddress {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "{:04x}:{:02x}:{:02x}.{:1x}",
                self.domain, self.bus, self.device, self.function
            )
        }
    }
}

impl From<PCIDeviceAttributes> for PciDeviceAttributes {
    fn from(value: PCIDeviceAttributes) -> Self {
        Self {
            vendor_name: Vendor::from_id(value.vendor_id()).map(|x| x.name().to_string()),
            device_name: Device::from_vid_pid(value.vendor_id(), value.device_id())
                .map(|x| x.name().to_string()),
            vendor_id: VendorId::from_u16(value.vendor_id()).unwrap(),
            device_id: DeviceId::from_u16(value.device_id()).unwrap(),
            revision: value.revision(),
            subvendor_id: VendorId::from_u16(value.subvendor_id()).unwrap(),
            subdevice_id: DeviceId::from_u16(value.subdevice_id()).unwrap(),
            sub_vendor_name: Vendor::from_id(value.subvendor_id()).map(|x| x.name().to_string()),
            sub_device_name: Device::from_vid_pid(value.subvendor_id(), value.subdevice_id())
                .map(|x| x.name().to_string()),
            bus_device: value.bus_device(),
            bus_id: value.bus_id(),
            domain: value.domain(),
            function: value.function(),
            class_id: value.class_id(),
            link_speed: value.link_speed().to_string(),
        }
    }
}

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
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
    strum::FromRepr,
    strum::IntoStaticStr,
)]
#[serde(tag = "type")]
pub enum BridgeType {
    Pci,
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

impl TryFrom<hwlocality::object::types::BridgeType> for BridgeType {
    type Error = ();

    fn try_from(value: hwlocality::object::types::BridgeType) -> Result<Self, Self::Error> {
        Ok(match value {
            hwlocality::object::types::BridgeType::PCI => BridgeType::Pci,
            hwlocality::object::types::BridgeType::Host => BridgeType::Host,
            _ => Err(())?,
        })
    }
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
    serde::Deserialize,
    serde::Serialize,
)]
pub struct BridgeAttributes {
    upstream_type: BridgeType,
    downstream_type: BridgeType,
    upstream_attributes: Option<PciDeviceAttributes>,
}

impl TryFrom<hwlocality::object::attributes::BridgeAttributes> for BridgeAttributes {
    type Error = ();

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
    serde::Deserialize,
    serde::Serialize,
    strum::Display,
    strum::EnumIs,
)]
#[serde(tag = "type")]
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
    serde::Deserialize,
    serde::Serialize,
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
    physical_index: Id<Node, u64>,
    #[serde(rename = "type")]
    type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    properties: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attributes: Option<NodeAttributes>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[rkyv(omit_bounds)]
    children: Vec<Node>,
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
    serde::Deserialize,
    serde::Serialize,
    strum::IntoStaticStr,
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
)]
#[strum(serialize_all = "lowercase")]
#[serde(tag = "type")]
pub enum OsDeviceType {
    Storage,
    Gpu,
    Network,
    OpenFabrics,
    Dma,
    CoProcessor,
    Memory,
}

impl From<OsDeviceType> for String {
    fn from(value: OsDeviceType) -> Self {
        let x: &'static str = value.into();
        x.into()
    }
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
    serde::Deserialize,
    serde::Serialize,
)]
pub struct OsDeviceAttributes {
    pub device_type: OsDeviceType,
}

impl TryFrom<OSDeviceType> for OsDeviceType {
    type Error = ();

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

    fn try_from(value: OSDeviceAttributes) -> Result<Self, Self::Error> {
        Ok(Self {
            device_type: value.device_type().try_into()?,
        })
    }
}

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
            physical_index: Id::from(value.global_persistent_index()),
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

#[cfg(test)]
mod test {
    use crate::physical::Node;
    use caps::Capability::{CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_SYS_RAWIO};
    use fixin::wrap;
    use hwlocality::Topology;
    use hwlocality::object::TopologyObject;
    use hwlocality::object::attributes::{DownstreamAttributes, ObjectAttributes};
    use hwlocality::object::depth::NormalDepth;
    use hwlocality::object::types::ObjectType;
    use hwlocality::topology::builder::{BuildFlags, TypeFilter};
    use pci_ids::{Device, FromId, Vendor};
    use std::collections::BTreeMap;
    use std::io::Write;
    use test_utils::with_caps;

    #[test]
    #[wrap(with_caps([CAP_SYS_ADMIN]))]
    fn hwloc_test() {
        let topology = Topology::new().unwrap();

        for depth in NormalDepth::iter_range(NormalDepth::MIN, topology.depth()) {
            println!("*** Objects at depth {depth}");

            for (idx, object) in topology.objects_at_depth(depth).enumerate() {
                println!("{idx}: {object}");
            }
        }
    }

    struct TopologyFilter {
        bridge: TypeFilter,
        pci: TypeFilter,
        os: TypeFilter,
        machine: TypeFilter,
        core: TypeFilter,
        die: TypeFilter,
        l1_cache: TypeFilter,
        l1_i_cache: TypeFilter,
        l2cache: TypeFilter,
        l2_i_cache: TypeFilter,
        l3cache: TypeFilter,
        l3_i_cache: TypeFilter,
        l4cache: TypeFilter,
        l5cache: TypeFilter,
        memcache: TypeFilter,
        misc: TypeFilter,
        numanode: TypeFilter,
    }

    struct TopoFilter {
        filters: BTreeMap<ObjectType, TypeFilter>,
    }

    #[test]
    #[wrap(with_caps([CAP_SYS_RAWIO]))]
    fn print_children_test() {
        let topology = Topology::builder()
            .with_type_filter(ObjectType::Bridge, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::PCIDevice, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::OSDevice, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Machine, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Core, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Die, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L1Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L2Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L3Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L4Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L5Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::MemCache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Misc, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::NUMANode, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::PU, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Package, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L1ICache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L2ICache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L3ICache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L4Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::L5Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Group, TypeFilter::KeepStructure)
            .unwrap()
            .with_flags(BuildFlags::INCLUDE_DISALLOWED)
            .unwrap()
            .build()
            .unwrap();
        let features = topology.feature_support();
        println!("*** Features: {features:#?}");
        println!("*** flags: {:#?}", topology.build_flags());

        println!("*** Topology tree");
        let system = Node::from(topology.root_object());
        let mut hardware_file = std::fs::File::create("hardware.yml").unwrap();
        hardware_file
            .write_all(serde_yaml_ng::to_string(&system).unwrap().as_bytes())
            .unwrap();
    }

    fn print_children(obj: &TopologyObject, depth: usize) {
        // for _ in 0..depth {
        //     print!(" ");
        // }
        // print!("{obj}");
        // if let Some(os_idx) = obj.os_index() {
        //     print!(" #{os_idx}");
        // }
        // println!("\n{obj:#?}");
        let p = "\t".repeat(depth);
        let pp = format!("{p} * ");
        let pf = format!("{p}   ");

        println!("{pp}name: {:?}", obj.name());
        println!("{pf}depth: {}", obj.depth());
        println!("{pf}cpu set: {:?}", obj.cpuset());
        println!("{pf}complete cpu set: {:?}", obj.complete_cpuset());
        match obj.attributes() {
            Some(ObjectAttributes::NUMANode(n)) => {
                println!("{pf}numa node");
                println!("{pf}  local memory: {:?}", n.local_memory());
                if !n.page_types().is_empty() {
                    println!("{pf}  page type: [");
                    for page_type in n.page_types() {
                        println!("{pf}    {page_type:?}");
                    }
                    println!("{pf}  ]");
                }
            }
            Some(ObjectAttributes::Cache(c)) => {
                println!("{pf}cache:");
                println!("{pf}  type: {}", c.cache_type());
                println!("{pf}  size: {:?}", c.size());
                println!("{pf}  line_size: {:?}", c.line_size());
                println!("{pf}  depth: {}", c.depth());
                println!("{pf}  associativity: {:?}", c.associativity());
            }
            Some(ObjectAttributes::Group(g)) => {
                println!("{pf}group:");
                println!("{pf}  depth: {}", g.depth());
            }
            Some(ObjectAttributes::PCIDevice(d)) => {
                println!("{pf}pci device:");
                println!("{pf}  vendor: {:x}", d.vendor_id());
                match Vendor::from_id(d.vendor_id()) {
                    None => {
                        println!("{pf}  vendor name: unknown");
                    }
                    Some(vendor) => {
                        println!("{pf}  vendor name: {}", vendor.name());
                    }
                };
                println!("{pf}  device: {:x}", d.device_id());
                match Device::from_vid_pid(d.vendor_id(), d.device_id()) {
                    None => {
                        println!("{pf}  device name: unknown");
                    }
                    Some(device) => {
                        println!("{pf}  device name: {}", device.name());
                    }
                };
                println!("{pf}  revision: {:x}", d.revision());
                println!("{pf}  sub-vendor id: {}", d.subvendor_id());
                println!("{pf}  sub-device id: {}", d.subdevice_id());
                match Device::from_vid_pid(d.subvendor_id(), d.subdevice_id()) {
                    None => {
                        println!("{pf}  sub-device name: unknown");
                    }
                    Some(device) => {
                        println!("{pf}  sub-device name: {}", device.name());
                    }
                }
                println!("{pf}  bus device: {}", d.bus_device());
                println!("{pf}  bus: {}", d.bus_id());
                println!("{pf}  domain: {}", d.domain());
                println!("{pf}  function: {}", d.function());
                println!("{pf}  class: {}", d.class_id());
                println!("{pf}  link speed: {}", d.link_speed());
            }
            Some(ObjectAttributes::Bridge(b)) => {
                println!("{pf}bridge:");
                println!("{pf}  upstream type: {}", b.upstream_type());
                println!("{pf}  downstream type: {}", b.downstream_type());
                println!("{pf}  depth: {}", b.depth());
                if let Some(attr) = b.downstream_attributes() {
                    match attr {
                        DownstreamAttributes::PCI(attr) => {
                            println!("{pf}  downstream attributes: [");
                            println!("{pf}    domain: {}", attr.domain());
                            println!("{pf}    secondary bus: {}", attr.secondary_bus());
                            println!("{pf}    subordinate bus: {}", attr.subordinate_bus());
                            println!("{pf}  ]");
                        }
                    }
                }
            }
            Some(ObjectAttributes::OSDevice(o)) => {
                println!("{pf}os device:");
                println!("{pf}  device type: {}", o.device_type());
            }
            None => {}
        }
        for info in obj.infos() {
            println!(
                "{pf}{}: {}",
                info.name().to_string_lossy(),
                info.value().to_string_lossy()
            );
        }

        for child in obj.all_children() {
            print_children(child, depth + 1);
        }
    }
}
