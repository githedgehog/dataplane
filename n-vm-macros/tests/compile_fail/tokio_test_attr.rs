// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[n_vm::in_vm]
#[tokio::test(flavor = "bogus")]
async fn tokio_test_bad_flavor() {}

fn main() {}