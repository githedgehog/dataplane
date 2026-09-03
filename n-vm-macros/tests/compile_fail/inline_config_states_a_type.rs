// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The type is discarded, so writing one would look checked and would not be.
#[n_vm::test]
fn inline_config_states_a_type() {
    #[n_vm::config]
    const _: n_vm::VmConfig = n_vm::VmConfigBuilder::default().build();
}

fn main() {}
