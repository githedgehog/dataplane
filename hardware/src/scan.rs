// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Hardware topology scanning support.
//!
//! This module provides integration with the `hwlocality` crate for
//! discovering system hardware topology at runtime.

#[allow(clippy::wildcard_imports)] // transparently re-exported above
use super::*;
use hwlocality::{
    object::{TopologyObject, attributes::ObjectAttributes},
    topology::builder::{BuildFlags, TopologyBuilder},
};
use tracing::error;

impl TryFrom<ObjectAttributes<'_>> for NodeAttributes {
    type Error = ();

    fn try_from(value: ObjectAttributes) -> Result<Self, ()> {
        Ok(match value {
            ObjectAttributes::NUMANode(&x) => Self::NumaNode(x.into()),
            ObjectAttributes::Cache(&x) => Self::Cache(x.try_into().map_err(|err| {
                error!("failed to convert cache attributes: {err}");
            })?),
            ObjectAttributes::Group(&x) => Self::Group(x.into()),
            ObjectAttributes::PCIDevice(&x) => Self::Pci(x.into()),
            ObjectAttributes::Bridge(&x) => Self::Bridge(x.try_into().map_err(|()| {
                error!("failed to convert bridge attributes");
            })?),
            ObjectAttributes::OSDevice(&x) => Self::OsDevice(x.try_into().map_err(|()| {
                error!("failed to convert os device attributes");
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

impl Node {
    /// Set up a scan of the hardware of the running machine and produce a top level node which includes
    /// (as children), all hardware nodes visible to this process.
    ///
    /// # Notes
    ///
    /// This function scans many components of the system which don't directly relate to our goals.
    /// The reason is to ensure that we cover the entire hardware topology and avoid filtering out
    /// our own objectives.
    ///
    /// # Panics
    ///
    /// This method is intended to run at startup and makes no attempt to recover from errors in
    /// `hwlocality`.
    ///
    /// There is little point propagating errors up, as the inability to find the target network card
    /// is most certainly fatal to the dataplane.
    #[must_use]
    #[allow(clippy::unwrap_used)]
    fn total_topology() -> TopologyBuilder {
        use hwlocality::Topology;
        use hwlocality::object::types::ObjectType;
        use hwlocality::topology::builder::TypeFilter;
        Topology::builder()
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
            .with_type_filter(ObjectType::L5Cache, TypeFilter::KeepAll)
            .unwrap()
            .with_type_filter(ObjectType::Group, TypeFilter::KeepStructure)
            .unwrap()
    }

    /// Scan the hardware of the running machine and produce a top level node which includes (as children),
    /// all hardware nodes visible to this process.
    ///
    /// # Notes
    ///
    /// ## Visibility
    ///
    /// This method deliberately (attempts to) side step cgroup / isolcpu type restrictions regarding
    /// nic / core / memory visibility.
    ///
    /// The intent is to scan the hardware, rather than to report the configuration used by the current
    /// process.
    ///
    /// ## Topology
    ///
    /// This function scans many components of the system which don't directly relate to our goals.
    /// The reason is to ensure that we cover the entire hardware topology and avoid filtering out
    /// our own objectives.
    ///
    /// # Panics
    ///
    /// This method is intended to run at startup and makes no attempt to recover from errors in
    /// `hwlocality`.
    ///
    /// There is little point propagating this error up, as the inability to find the target network card
    /// is most certainly fatal to the dataplane.
    #[must_use]
    #[allow(clippy::unwrap_used)]
    pub fn scan_all() -> Node {
        let total_system = Self::total_topology()
            // attempt to ignore mechanisms which might isolate us from the
            // NIC / cpu set the user needs us to use
            .with_flags(BuildFlags::INCLUDE_DISALLOWED)
            .unwrap()
            .build()
            .unwrap();
        Node::from(total_system.root_object())
    }

    /// Scan the hardware of the running machine and produce a top level node which includes (as children),
    /// all hardware nodes visible to this process.
    ///
    /// # Notes
    ///
    /// ## Visibility
    ///
    /// This method deliberately (does not attemtp to) side step cgroup / isolcpu type restrictions regarding
    /// nic / core / memory visibility.
    ///
    /// The intent is to scan the hardware, rather than to report the configuration used by the current
    /// process.
    ///
    /// # Panics
    ///
    /// This method is intended to run at startup and makes no attempt to recover from errors in
    /// `hwlocality`.
    ///
    /// There is little point propagating this error up, as the inability to find the target network card
    /// is most certainly fatal to the dataplane.
    #[must_use]
    #[allow(clippy::unwrap_used)]
    pub fn scan() -> Node {
        let total_system = Self::total_topology().build().unwrap();
        Node::from(total_system.root_object())
    }

    #[must_use]
    pub fn iter(&self) -> std::vec::IntoIter<&Node> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a Node {
    type Item = &'a Node;

    type IntoIter = std::vec::IntoIter<&'a Node>;

    fn into_iter(self) -> Self::IntoIter {
        let mut elems = vec![];
        elems.push(self);
        for child in self.children() {
            elems.extend(child.into_iter());
        }
        elems.into_iter()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Node, NodeAttributes,
        nic::{BindToVfioPci, PciNic},
        support::{SupportedDevice, SupportedVendor},
    };

    #[test]
    #[n_vm::in_vm]
    fn collect_them_all_and_bind_them() {
        let system = Node::scan_all();
        let nics: Vec<_> = system
            .iter()
            .filter_map(|node| match node.attributes() {
                Some(NodeAttributes::Pci(dev)) => {
                    if dev.vendor_id() == SupportedVendor::RedHat.vendor_id()
                        && SupportedDevice::VirtioNet
                            .device_ids()
                            .contains(&dev.device_id())
                    {
                        let mut nic = PciNic::new(dev.address()).unwrap();
                        nic.bind_to_vfio_pci().unwrap();
                        Some(nic)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();
        assert_eq!(nics.len(), 3, "expected exactly 3 virtio network cards");
    }

    #[test]
    #[n_vm::in_vm]
    fn bind_fabric_nics_and_skip_mgmt_nic() {
        let system = Node::scan_all();
        let mgmt_nic_pci_address = "0000:00:02.0".try_into().unwrap();
        let nics: Vec<_> = system
            .iter()
            .filter_map(|node| match node.attributes() {
                Some(NodeAttributes::Pci(dev)) => {
                    if dev.vendor_id() == SupportedVendor::RedHat.vendor_id()
                        && SupportedDevice::VirtioNet
                            .device_ids()
                            .contains(&dev.device_id())
                        && dev.address() != mgmt_nic_pci_address
                    {
                        let mut nic = PciNic::new(dev.address()).unwrap();
                        nic.bind_to_vfio_pci().unwrap();
                        Some(nic)
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .collect();
        assert_eq!(nics.len(), 2, "expected exactly 2 virtio network cards");
    }

    #[test]
    #[n_vm::in_vm]
    fn bind_nic_test() {
        let system = Node::scan_all();
        let target_pci_address = "0001:00:02.0".try_into().unwrap();
        let Some(mut nic) = system.iter().find_map(|node| match node.attributes() {
            Some(NodeAttributes::Pci(dev)) => {
                if dev.address() == target_pci_address
                    && dev.vendor_id() == SupportedVendor::RedHat.vendor_id()
                    && SupportedDevice::VirtioNet
                        .device_ids()
                        .contains(&dev.device_id())
                {
                    Some(PciNic::new(dev.address()).unwrap())
                } else {
                    None
                }
            }
            _ => None,
        }) else {
            panic!("target nic not found");
        };
        nic.bind_to_vfio_pci().unwrap();
    }
}
