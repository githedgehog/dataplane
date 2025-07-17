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
use net::buffer::PacketBufferMut;
use pci_ids::{Device, FromId, Vendor};
use pci_info::{PciDevice, PciEnumerator};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::num::NonZero;
use std::thread::Thread;

#[repr(u16)]
pub enum KnownNetworkCardVendor {
    Intel = 0x8086,
    Mellanox = 0x15b3,
}

impl From<KnownNetworkCardVendor> for String {
    fn from(value: KnownNetworkCardVendor) -> Self {
        match value {
            KnownNetworkCardVendor::Intel => "Intel Corporation".to_string(),
            KnownNetworkCardVendor::Mellanox => "Mellanox Technologies".to_string(),
        }
    }
}

mod vendor {
    use crate::physical::KnownNetworkCardVendor;
    pub(super) const MELLANOX: u16 = KnownNetworkCardVendor::Mellanox as u16;
    pub(super) const INTEL: u16 = KnownNetworkCardVendor::Intel as u16;
}

pub enum NetworkCardVendor {
    Known(KnownNetworkCardVendor),
    Unknown(UnknownNetworkCardVendor),
}

#[repr(transparent)]
pub struct UnknownNetworkCardVendor(u16);

impl From<KnownNetworkCardVendor> for u16 {
    fn from(value: KnownNetworkCardVendor) -> Self {
        value as u16
    }
}

impl From<u16> for NetworkCardVendor {
    fn from(value: u16) -> Self {
        match value {
            vendor::INTEL => NetworkCardVendor::Known(KnownNetworkCardVendor::Intel),
            vendor::MELLANOX => NetworkCardVendor::Known(KnownNetworkCardVendor::Mellanox),
            _ => NetworkCardVendor::Unknown(UnknownNetworkCardVendor(value)),
        }
    }
}

/// # Errors
///
/// TODO
///
/// # Panics
///
/// TODO
pub fn walk_pci() -> impl Iterator<Item = PciDevice> {
    pci_info::default_pci_enumerator()
        .unwrap()
        .enumerate_pci()
        .unwrap()
        .into_iter()
        .filter_map(Result::ok)
}

#[repr(transparent)]
pub struct ReadOnlyWrapper<T>(T);

impl<T> From<T> for ReadOnlyWrapper<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "&str", into = "String")]
pub enum CacheType {
    /// Unified cache
    Unified,
    /// Data cache
    Data,
    /// Instruction cache (filtered out by default)
    Instruction,
}

impl From<CacheType> for String {
    fn from(value: CacheType) -> Self {
        match value {
            CacheType::Unified => "unified",
            CacheType::Data => "data",
            CacheType::Instruction => "instruction",
        }
        .to_string()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[error("invalid cache type: {0:?}")]
pub struct InvalidCacheType(String);

impl<'a> TryFrom<&'a str> for CacheType {
    type Error = InvalidCacheType;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Ok(match value {
            "unified" => CacheType::Unified,
            "data" => CacheType::Data,
            "instruction" => CacheType::Instruction,
            x => Err(InvalidCacheType(x.to_string()))?,
        })
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PciDeviceAttributes {
    vendor_name: Option<String>,
    device_name: Option<String>,
    vendor_id: u16,
    device_id: u16,
    revision: u8,
    subvendor_id: u16,
    subdevice_id: u16,
    sub_vendor_name: Option<String>,
    sub_device_name: Option<String>,
    bus_device: u8,
    bus_id: u8,
    domain: u16,
    function: u8,
    class_id: u16,
    link_speed: String,
}

impl From<PCIDeviceAttributes> for PciDeviceAttributes {
    fn from(value: PCIDeviceAttributes) -> Self {
        Self {
            vendor_name: Vendor::from_id(value.vendor_id()).map(|x| x.name().to_string()),
            device_name: Device::from_vid_pid(value.vendor_id(), value.device_id())
                .map(|x| x.name().to_string()),
            vendor_id: value.vendor_id(),
            device_id: value.device_id(),
            revision: value.revision(),
            subvendor_id: value.subvendor_id(),
            subdevice_id: value.subdevice_id(),
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

#[derive(Debug, Copy, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NodeAttributes {
    NumaNode(NumaNodeAttributes),
    Cache(CacheAttributes),
    Pci(PciDeviceAttributes),
    Bridge(BridgeAttributes),
    Group(GroupAttributes),
    OsDevice(OsDeviceAttributes),
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Node {
    #[serde(rename = "type")]
    type_: String,
    physical_index: Id<Node, u64>,
    os_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subtype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(flatten)]
    properties: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attributes: Option<NodeAttributes>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
        match value {
            OsDeviceType::Storage => "storage".to_string(),
            OsDeviceType::Gpu => "gpu".to_string(),
            OsDeviceType::Network => "network".to_string(),
            OsDeviceType::OpenFabrics => "openfabrics".to_string(),
            OsDeviceType::Dma => "dma".to_string(),
            OsDeviceType::CoProcessor => "coprocessor".to_string(),
            OsDeviceType::Memory => "memory".to_string(),
        }
    }
}

impl TryFrom<String> for OsDeviceType {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(match value.as_str() {
            "storage" => OsDeviceType::Storage,
            "gpu" => OsDeviceType::Gpu,
            "network" => OsDeviceType::Network,
            "openfabrics" => OsDeviceType::OpenFabrics,
            "dma" => OsDeviceType::Dma,
            "coprocessor" => OsDeviceType::CoProcessor,
            "memory" => OsDeviceType::Memory,
            _ => Err(())?,
        })
    }
}

impl Display for OsDeviceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OsDeviceType::Storage => write!(f, "storage"),
            OsDeviceType::Gpu => write!(f, "gpu"),
            OsDeviceType::Network => write!(f, "network"),
            OsDeviceType::OpenFabrics => write!(f, "openfabrics"),
            OsDeviceType::Dma => write!(f, "dma"),
            OsDeviceType::CoProcessor => write!(f, "coprocessor"),
            OsDeviceType::Memory => write!(f, "memory"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

pub struct OsDevice {
    pub device_type: OSDeviceType,
}

impl TryFrom<OSDeviceAttributes> for OsDeviceAttributes {
    type Error = ();

    fn try_from(value: OSDeviceAttributes) -> Result<Self, Self::Error> {
        Ok(Self {
            device_type: value.device_type().try_into()?,
        })
    }
}

pub struct Core;
pub struct NumaNode;
pub struct CpuDie;
pub struct CpuSocket;

pub struct CpuCache<const N: usize>;

pub struct SystemLayout {
    sockets: BTreeSet<Id<CpuSocket>>,
    dies: BTreeSet<Id<CpuDie>>,
    numa_nodes: BTreeSet<Id<NumaNode>>,
    cores: BTreeSet<Id<Core>>,
    threads: BTreeSet<Id<Thread>>,
    l1_caches: BTreeSet<Id<CpuCache<1>>>,
    l2_caches: BTreeSet<Id<CpuCache<2>>>,
    l3_caches: BTreeSet<Id<CpuCache<3>>>,
}

pub trait Layout<const THREADING: usize = 2> {
    fn sockets(&self) -> impl Iterator<Item = Id<CpuSocket>>;
    fn dies(&self) -> impl Iterator<Item = Id<CpuDie>>;
    fn numa_nodes(&self) -> impl Iterator<Item = Id<NumaNode>>;
    fn cores(&self) -> impl Iterator<Item = Id<Core>>;
    fn threads(&self) -> impl Iterator<Item = Id<Thread>>;
    fn caches<const N: usize>(&self) -> impl Iterator<Item = Id<CpuCache<N>>>;
    fn sibling_threads(&self) -> impl Iterator<Item = (Id<Core>, [Id<Core>; THREADING])>;
}

impl TryFrom<ObjectAttributes<'_>> for NodeAttributes {
    type Error = ();

    fn try_from(value: ObjectAttributes) -> Result<Self, ()> {
        Ok(match value {
            ObjectAttributes::NUMANode(&x) => Self::NumaNode(x.into()),
            ObjectAttributes::Cache(&x) => Self::Cache(x.try_into().map_err(|_| {
                println!("failed to convert cache attributes");
            })?),
            ObjectAttributes::Group(&x) => Self::Group(x.into()),
            ObjectAttributes::PCIDevice(&x) => Self::Pci(x.into()),
            ObjectAttributes::Bridge(&x) => Self::Bridge(x.try_into().map_err(|_| {
                println!("failed to convert bridge attributes");
            })?),
            ObjectAttributes::OSDevice(&x) => Self::OsDevice(x.try_into().map_err(|_| {
                println!("failed to convert os device attributes");
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
    use crate::physical::{Node, walk_pci};
    use caps::Capability::CAP_SYS_ADMIN;
    use fixin::wrap;
    use hwlocality::Topology;
    use hwlocality::object::TopologyObject;
    use hwlocality::object::attributes::{DownstreamAttributes, ObjectAttributes};
    use hwlocality::object::depth::NormalDepth;
    use hwlocality::object::types::ObjectType;
    use hwlocality::topology::builder::{BuildFlags, TypeFilter};
    use pci_ids::{Device, FromId, Vendor};
    use pci_info::PciInfo;
    use std::collections::BTreeMap;
    use std::fs;
    use test_utils::with_caps;

    #[test]
    // #[wrap(with_caps([CAP_SYS_RAWIO]))]
    fn walk_pci_test() {
        walk_pci().for_each(|pci_device| println!("{pci_device:#?}"));
    }

    #[test]
    #[wrap(with_caps([CAP_SYS_ADMIN]))]
    fn pci_test() {
        // Enumerate the devices on the PCI bus using the default
        // enumerator for the current platform. The `unwrap()` panics if
        // the enumeration fatally fails.
        let info = PciInfo::enumerate_pci().unwrap();

        // Print out some properties of the enumerated devices.
        // Note that the collection contains both devices and errors
        // as the enumeration of PCI devices can fail entirely (in which
        // case `PciInfo::enumerate_pci()` would return error) or
        // partially (in which case an error would be inserted in the
        // result).
        info.iter().filter_map(Result::ok).for_each(|pci_device| {
            if let (Ok(Some(sub_vendor)), Ok(Some(sub_device))) = (
                pci_device.subsystem_vendor_id(),
                pci_device.subsystem_device_id(),
            ) {
                let sub_vendor = match Vendor::from_id(sub_vendor) {
                    None => {
                        return;
                    }
                    Some(vendor) => vendor,
                };
                let device = match Device::from_vid_pid(sub_vendor.id(), sub_device) {
                    None => {
                        println!(
                            "sub device: {}, {:#x}, location: {:?}, driver: {:?}",
                            sub_vendor.name(),
                            sub_device,
                            pci_device.location(),
                            pci_device.os_driver().unwrap()
                        );
                        return;
                    }
                    Some(device) => device,
                };
                println!("\nvendor: {}", device.vendor().name());
                println!("device name: {}", device.name());
                println!(
                    "sub device: {}, {:#x}, location: {:?}, driver: {:?}",
                    sub_vendor.name(),
                    sub_device,
                    pci_device.location(),
                    pci_device.os_driver().unwrap()
                );
            }
            let device = match Device::from_vid_pid(pci_device.vendor_id(), pci_device.device_id())
            {
                None => {
                    println!(
                        "Unknown device: {:#x}:{:#x}, location: {:?}, driver: {:?}",
                        pci_device.vendor_id(),
                        pci_device.device_id(),
                        pci_device.location(),
                        pci_device.os_driver().unwrap()
                    );
                    let location = match pci_device.location() {
                        Ok(location) => location,
                        Err(err) => {
                            eprintln!("{err}");
                            return;
                        }
                    };

                    match fs::read_link(format!("/sys/bus/pci/devices/{location}/physfn")) {
                        Ok(physfn) => {
                            println!(
                                "location: {}, physfn: {}",
                                location,
                                physfn
                                    .strip_prefix("../")
                                    .unwrap()
                                    .as_os_str()
                                    .to_string_lossy()
                            );
                        }
                        Err(_) => {
                            return;
                        }
                    }
                    return;
                }
                Some(device) => device,
            };
            println!("\nvendor: {}", device.vendor().name());
            println!("device name: {}", device.name());
            println!(
                "device: {:#x}:{:#x}, location, {:?}, driver: {:?}\n",
                pci_device.vendor_id(),
                pci_device.device_id(),
                pci_device.location(),
                pci_device.os_driver().unwrap()
            );
        });
    }

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
    // #[wrap(with_caps([CAP_SYS_ADMIN, CAP_SYS_RAWIO, CAP_NET_ADMIN]))]
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
        // let topology = Topology::new().unwrap();
        let features = topology.feature_support();
        println!("*** Features: {features:#?}");
        println!("*** flags: {:#?}", topology.build_flags());

        println!("*** Topology tree");
        let system = print_children2(topology.root_object());
        println!("{}", serde_yml::to_string(&system).unwrap());
        // print_children(
        //     topology.root_object(),
        //     0,
        //
        // for bridge in topology.bridges() {
        //     println!("*** io device {bridge}");
        //     print_children(bridge);
        // }
    }

    fn print_children2(obj: &TopologyObject) -> Node {
        Node::from(obj)
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
