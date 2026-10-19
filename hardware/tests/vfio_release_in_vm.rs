// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Verify that a NIC bound to vfio-pci can be handed back to its kernel driver.

use dataplane_hardware::nic::{BindToVfioPci, PciNic, ReleaseFromVfioPci, netdevs_of};
use dataplane_hardware::pci::address::PciAddress;
use dataplane_hardware::support::DpdkDriverType;
use n_vm::config::{NicModel, VmConfig};
use n_vm::kernel_profiles;
use std::fs;

/// e1000's interface hangs directly off its PCI function, unlike virtio-net's.
const E1000_QEMU: VmConfig = VmConfig::DEFAULT
    .to_builder()
    .kernel_profile(kernel_profiles::QEMU)
    .nic_model(NicModel::E1000)
    .build();

fn driver_of(address: PciAddress) -> Option<String> {
    let link = fs::read_link(format!("/sys/bus/pci/devices/{address}/driver")).ok()?;
    Some(link.file_name()?.to_str()?.to_owned())
}

#[n_vm::test(config = E1000_QEMU)]
fn a_nic_returns_to_its_kernel_driver() {
    let address = fs::read_dir("/sys/bus/pci/devices")
        .unwrap()
        .flatten()
        .filter_map(|entry| PciAddress::try_from(entry.file_name().to_str()?).ok())
        .find(|&address| {
            PciNic::new(address)
                .is_ok_and(|nic| DpdkDriverType::from(nic.device()) == DpdkDriverType::VfioPci)
                && netdevs_of(address).is_ok_and(|names| !names.is_empty())
        })
        .expect("the guest has an e1000 with a kernel interface");
    let kernel_driver = driver_of(address).unwrap();
    let mut nic = PciNic::new(address).unwrap();

    nic.bind_to_vfio_pci().unwrap();
    assert_eq!(driver_of(address).as_deref(), Some("vfio-pci"));
    assert_eq!(netdevs_of(address).unwrap(), Vec::<String>::new());

    nic.release_from_vfio_pci().unwrap();
    assert_eq!(driver_of(address), Some(kernel_driver));
    assert!(!netdevs_of(address).unwrap().is_empty());

    // Releasing a device its kernel driver already holds changes nothing.
    nic.release_from_vfio_pci().unwrap();
    assert!(!netdevs_of(address).unwrap().is_empty());
}
