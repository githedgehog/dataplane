// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[n_vm::guest(hugepage_size = "2m", hugepage_count = 512)]
fn standalone_guest() {}

fn main() {}