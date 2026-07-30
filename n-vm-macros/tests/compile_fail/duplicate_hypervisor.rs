// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[n_vm::test]
#[n_vm::hypervisor(iommu)]
#[n_vm::hypervisor(host_pages = "4k")]
fn duplicate_hypervisor() {}

fn main() {}