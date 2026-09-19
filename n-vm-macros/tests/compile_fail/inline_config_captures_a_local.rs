// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The configuration is evaluated on the host tier, in another process, before
// the guest exists -- so it cannot see the body. `const` is what enforces
// that, and the initializer's spans are what put the error on the offending
// name rather than inside generated code.
#[n_vm::test]
fn inline_config_captures_a_local() {
    let wanted = true;
    #[n_vm::config]
    const _: _ = n_vm::VmConfigBuilder::default().iommu(wanted).build();
}

fn main() {}
