// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[n_vm::in_vm]
#[n_vm::guest(hugepage_size = "none", hugepage_count = 4)]
fn hugepage_count_with_none() {}

fn main() {}