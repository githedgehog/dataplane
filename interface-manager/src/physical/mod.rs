// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::pedantic, clippy::unwrap_used)]

use id::Id;
use multi_index_map::MultiIndexMap;
use net::buffer::PacketBufferMut;
use pci_info::{PciDevice, PciEnumerator};

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

pub type OsThreadId = u32;

pub struct HyperThreadedCore {
    id: Id<Self, u32>,
    sibling_id: Id<Self, u32>,
}
pub trait Core {
    type Id;
    fn id(&self) -> Self::Id;
}

pub trait Sibling {
    type Id;
    fn sibling_id(&self) -> Self::Id;
}

impl Core for HyperThreadedCore {
    type Id = Id<Self, u32>;

    fn id(&self) -> Id<Self, u32> {
        self.id
    }
}

impl Sibling for HyperThreadedCore {
    type Id = <Self as Core>::Id;

    fn sibling_id(&self) -> Self::Id {
        self.sibling_id
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Task<T> {
    Main(T),
    Worker(T),
    Assistant(T),
    Service(T),
}

#[derive(MultiIndexMap)]
pub struct Dispatch<C: Core + Clone + PartialEq + Eq + PartialOrd + Ord> {
    #[multi_index(ordered_unique)]
    task: Task<C>,
}

#[cfg(test)]
mod test {
    use crate::physical::walk_pci;
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
                        Err(err) => {
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
            .with_flags(BuildFlags::INCLUDE_DISALLOWED)
            .unwrap()
            .build()
            .unwrap();
        // let topology = Topology::new().unwrap();
        let features = topology.feature_support();
        println!("*** Features: {features:#?}");
        println!("*** flags: {:#?}", topology.build_flags());

        println!("*** Topology tree");
        print_children(topology.root_object(), 0);
        // for bridge in topology.bridges() {
        //     println!("*** io device {bridge}");
        //     print_children(bridge);
        // }
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

        println!("{p}name: {:?}", obj.name());
        println!("{p}depth: {}", obj.depth());
        println!("{p}cpu set: {:?}", obj.cpuset());
        println!("{p}complete cpu set: {:?}", obj.complete_cpuset());
        match obj.attributes() {
            Some(ObjectAttributes::NUMANode(n)) => {
                println!("{p}numa node");
                println!("{p}  local memory: {:?}", n.local_memory());
                if !n.page_types().is_empty() {
                    println!("{p}  page type: [");
                    for page_type in n.page_types() {
                        println!("{p}    {page_type:?}");
                    }
                    println!("{p}  ]");
                }
            }
            Some(ObjectAttributes::Cache(c)) => {
                println!("{p}cache:");
                println!("{p}  type: {}", c.cache_type());
                println!("{p}  size: {:?}", c.size());
                println!("{p}  line_size: {:?}", c.line_size());
                println!("{p}  depth: {}", c.depth());
                println!("{p}  associativity: {:?}", c.associativity());
            }
            Some(ObjectAttributes::Group(g)) => {
                println!("{p}group:");
                println!("{p}  depth: {}", g.depth());
            }
            Some(ObjectAttributes::PCIDevice(d)) => {
                println!("{p}pci device:");
                println!("{p}  vendor: {:x}", d.vendor_id());
                println!("{p}  device: {:x}", d.device_id());
                println!("{p}  revision: {:x}", d.revision());
                println!("{p}  sub-vendor id: {}", d.subvendor_id());
                println!("{p}  sub-device id: {}", d.subdevice_id());
                println!("{p}  bus device: {}", d.bus_device());
                println!("{p}  bus: {}", d.bus_id());
                println!("{p}  domain: {}", d.domain());
                println!("{p}  function: {}", d.function());
                println!("{p}  class: {}", d.class_id());
                println!("{p}  link speed: {}", d.link_speed());
            }
            Some(ObjectAttributes::Bridge(b)) => {
                println!("{p}bridge:");
                println!("{p}  upstream type: {}", b.upstream_type());
                println!("{p}  downstream type: {}", b.downstream_type());
                println!("{p}  depth: {}", b.depth());
                if let Some(attr) = b.downstream_attributes() {
                    match attr {
                        DownstreamAttributes::PCI(attr) => {
                            println!("{p}  downstream attributes: [");
                            println!("{p}    domain: {}", attr.domain());
                            println!("{p}    secondary bus: {}", attr.secondary_bus());
                            println!("{p}    subordinate bus: {}", attr.subordinate_bus());
                            println!("{p}  ]");
                        }
                    }
                }
            }
            Some(ObjectAttributes::OSDevice(o)) => {
                println!("{p}os device:");
                println!("{p}  device type: {}", o.device_type());
            }
            None => {}
        }
        for info in obj.infos() {
            println!(
                "{p}{}: {}",
                info.name().to_string_lossy(),
                info.value().to_string_lossy()
            );
        }

        for child in obj.all_children() {
            print_children(child, depth + 1);
        }
    }
}
