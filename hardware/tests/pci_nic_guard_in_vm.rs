// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Verify that [`PciNic`] rejects non-network PCI devices in a QEMU guest.

use dataplane_hardware::nic::{PciNic, PciNicError};
use dataplane_hardware::pci::address::PciAddress;
use n_vm::config::VmConfig;
use n_vm::kernel_profiles;
use std::fs;

/// Includes storage and console devices that share the NICs' `virtio-pci` driver.
const QEMU: VmConfig = VmConfig::DEFAULT
    .to_builder()
    .kernel_profile(kernel_profiles::QEMU)
    .build();

/// PCI class code prefix of network controllers.
const NETWORK_CONTROLLER_CLASS: &str = "0x02";

/// Non-network devices must be rejected before their drivers can be unbound.
#[n_vm::test(config = QEMU)]
fn pci_nic_refuses_devices_that_are_not_network_cards() {
    let mut refused_with_driver = Vec::new();
    for entry in fs::read_dir("/sys/bus/pci/devices")
        .expect("read PCI devices")
        .flatten()
    {
        let name = entry
            .file_name()
            .into_string()
            .expect("PCI address is UTF-8");
        let class = fs::read_to_string(entry.path().join("class")).expect("read PCI class");
        if class.trim().starts_with(NETWORK_CONTROLLER_CLASS) {
            continue;
        }
        let address = PciAddress::try_from(name.as_str()).expect("parse PCI address");
        match PciNic::new(address) {
            Err(PciNicError::Unsupported { .. }) => {}
            other => panic!("{name} (class {}) was not refused: {other:?}", class.trim()),
        }
        if let Ok(driver) = fs::read_link(entry.path().join("driver")) {
            eprintln!(
                "refused {name} (class {}), bound to {driver:?}",
                class.trim()
            );
            refused_with_driver.push(name);
        }
    }
    assert!(
        !refused_with_driver.is_empty(),
        "the guest has no driver-bound device other than a NIC, so nothing was at risk"
    );
}
