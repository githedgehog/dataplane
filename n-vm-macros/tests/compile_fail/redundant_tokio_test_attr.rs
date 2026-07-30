// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// #[tokio::test] is rejected rather than ignored: it used to carry the
// runtime flavor, which now lives in #[n_vm::test(...)]'s own arguments.
// Silently dropping it would silently change which scheduler the test ran on.
#[n_vm::test]
#[tokio::test(flavor = "multi_thread")]
async fn redundant_tokio_test_attr() {}

fn main() {}
