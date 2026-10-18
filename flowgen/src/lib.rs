// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

//! A traffic generator for testing the dataplane: many flows, each packet signed so that what
//! comes back can be traced to what was sent, and an account of the difference.
//!
//! - [`space`]: the flows a stream can send, numbered, so that a million of them need no table.
//! - [`frame`]: building each flow's frame once and stamping it per packet; reading frames back.
//! - [`signature`]: what every packet's payload carries to name its flow and place.
//! - [`ledger`]: what was sent against what came back: loss, reordering, latency, and whether
//!   each flow came back the same way every time.
//! - `port` (with the `dpdk` feature): sending a stream on DPDK queues and receiving on them.
//!
//! Frames are built and read by this crate's own code, not the dataplane's, so that the two
//! cannot agree on a bug.

mod checksum;
pub mod frame;
pub mod ledger;
#[cfg(feature = "dpdk")]
pub mod port;
pub mod signature;
pub mod space;

#[cfg(test)]
mod tests;
