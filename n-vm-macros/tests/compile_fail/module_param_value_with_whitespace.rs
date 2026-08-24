// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The kernel command line is split on whitespace, so this would silently
// become two parameters.
const _: n_vm::VmConfig = n_vm::VmConfigBuilder::default()
    .module_params(&[n_vm::ModuleParam::new("mlx5_core", "prof_sel", "2 3")])
    .build();

fn main() {}
