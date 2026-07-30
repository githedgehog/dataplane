// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// #[n_vm::test] injects #[test] itself; a hand-written one is redundant and
// would silently double up the harness attribute.
#[n_vm::test]
#[test]
fn redundant_test_attr() {}

fn main() {}
