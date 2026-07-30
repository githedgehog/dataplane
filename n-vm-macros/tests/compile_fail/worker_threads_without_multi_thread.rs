// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// A current-thread runtime has no worker pool, so sizing one is a
// contradiction rather than a no-op.
#[n_vm::test(worker_threads = 4)]
async fn worker_threads_without_multi_thread() {}

fn main() {}
