// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! As `e1000_on_cloud_hypervisor`, for the other emulated Intel NIC, so that
//! `NicModel::requires_qemu` is covered for every variant it answers `true`
//! for rather than just the first one.

const E1000E_VM: n_vm::VmConfig = n_vm::VmConfig {
    nic_model: n_vm::NicModel::E1000E,
    ..n_vm::VmConfig::DEFAULT
};

#[n_vm::test(cloud_hypervisor, config = E1000E_VM)]
fn e1000e_on_cloud_hypervisor() {}

fn main() {}
