// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// `n_it` is the namespace the init system reads its own boot parameters from.
// Setting it would redirect the guest's init protocol, which surfaces as a
// hang rather than as an error -- so it is refused at build time.
const _: n_vm::VmConfig = n_vm::VmConfigBuilder::default()
    .module_params(&[n_vm::ModuleParam::new("n_it", "result_port", "9")])
    .build();

fn main() {}
