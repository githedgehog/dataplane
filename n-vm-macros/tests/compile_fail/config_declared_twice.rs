// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

const NAMED: n_vm::VmConfig = n_vm::VmConfigBuilder::default().iommu(true).build();

#[n_vm::test(config = NAMED)]
fn config_declared_twice() {
    #[n_vm::config]
    const _: _ = n_vm::VmConfigBuilder::default().build();
}

fn main() {}
