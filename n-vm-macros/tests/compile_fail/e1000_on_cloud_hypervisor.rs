// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Pinning cloud-hypervisor while asking for a NIC only QEMU can emulate is
//! a contradiction in the test as written, and stays a build error.
//!
//! The pin is load-bearing: an *unpinned* test that asks for e1000 is not an
//! error, it is a test that wants QEMU, and the harness selects QEMU for it.
//!
//! This is also the case that proves the check survived the move to a
//! `const VmConfig`.  The macro cannot read a config named by path -- but the
//! backend is one of its own arguments, so the two meet in a `const fn`
//! assertion that rustc evaluates.

const E1000_VM: n_vm::VmConfig = n_vm::VmConfig {
    nic_model: n_vm::NicModel::E1000,
    ..n_vm::VmConfig::DEFAULT
};

#[n_vm::test(cloud_hypervisor, config = E1000_VM)]
fn e1000_on_cloud_hypervisor() {}

fn main() {}
