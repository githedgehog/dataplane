// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[n_vm::in_vm(qemu)]
#[n_vm::network(nic_model = "rtl8139")]
fn unknown_nic_model() {}

fn main() {}