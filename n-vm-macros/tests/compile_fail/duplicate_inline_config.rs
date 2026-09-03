// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[n_vm::test]
fn duplicate_inline_config() {
    #[n_vm::config]
    const _: _ = n_vm::VmConfigBuilder::default().build();
    #[n_vm::config]
    const _: _ = n_vm::VmConfigBuilder::default().iommu(true).build();
}

fn main() {}
