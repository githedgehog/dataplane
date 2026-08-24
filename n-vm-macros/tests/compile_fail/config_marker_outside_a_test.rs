// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The marker is consumed by `#[n_vm::test]`. Used anywhere it cannot reach,
// the registered attribute is what reports that, rather than the config being
// silently ignored and the VM booting with the default.
#[n_vm::config]
const _: n_vm::VmConfig = n_vm::VmConfigBuilder::default().iommu(true).build();

fn main() {}
