// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The backend is part of the machine now. Kept as an error with a hint rather
// than dropped: left alone it would read as an unknown option, with nothing
// pointing at the field that replaced it.
#[n_vm::test(qemu)]
fn migrated_backend_option() {}

fn main() {}
