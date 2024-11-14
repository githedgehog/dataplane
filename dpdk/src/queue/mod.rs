// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK queue abstractions.
pub mod hairpin;
pub mod rx;
pub mod tx;

/// The possible states of a DPDK queue
#[derive(Debug)]
pub enum QueueState {
    /// An unconfigured queue
    Unconfigured,
    /// A stopped queue
    Stopped,
    /// A started queue
    Started,
}
