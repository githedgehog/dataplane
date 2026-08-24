// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The NIC/backend coherence check moved into `VmConfig::check` when the
// backend became a field. It must still be a build error: a NIC the pinned
// hypervisor cannot emulate is a contradiction in the test as written, true on
// every host, and it should not take a VM boot to discover.
const E1000E_VM: n_vm::VmConfig = n_vm::VmConfigBuilder::default()
    .nic_model(n_vm::NicModel::E1000E)
    .backend(n_vm::RequestedBackend::CloudHypervisor)
    .build();

#[n_vm::test(config = E1000E_VM)]
fn e1000e_on_cloud_hypervisor() {}

fn main() {}
