// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Run the production arming protocol under Loom without starting the dataplane or DPDK.
//! `cargo test -p dataplane --features loom --test doorbell_model`

#![cfg(feature = "loom")]

#[path = "../src/drivers/cpbridge/wakeup.rs"]
mod wakeup;
