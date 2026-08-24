// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// A fabric that names its models one by one reaches the same coherence check
// as `nic_model` does. Worth its own case: the check reads a slice here rather
// than a single field, so "no emulated NIC in this VM" is a different question
// than it was, and getting it wrong would fail at boot instead of at build.
const MIXED_VM: n_vm::VmConfig = n_vm::VmConfigBuilder::default()
    .fabric_nic_models(&[n_vm::NicModel::VirtioNet, n_vm::NicModel::E1000])
    .backend(n_vm::RequestedBackend::CloudHypervisor)
    .build();

#[n_vm::test(config = MIXED_VM)]
fn mixed_fabric_on_cloud_hypervisor() {}

fn main() {}
