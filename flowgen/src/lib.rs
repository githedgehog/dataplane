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
//! - [`bgp`]: a minimal BGP speaker, to hold a session with a gateway over [`tcp`].
//! - [`bfd`]: a BFD peer, to hold a session with a gateway and say how it fared.
//! - [`tcp`]: real TCP hosts, from smoltcp, that open connections and check what comes back.
//! - [`space`]: the flows a stream can send, numbered, so that a million of them need no table.
//! - [`frame`]: building each flow's frame once and stamping it per packet; reading frames back.
//! - [`mutate`]: changing every frame of a stream in one place, to make it one a gateway should
//!   refuse.
//! - [`signature`]: what every packet's payload carries to name its flow and place.
//! - [`schedule`]: which flow each packet belongs to, as a window of flows slides on (churn).
//! - [`ledger`]: what was sent against what came back: loss, reordering, latency, and whether
//!   each flow came back the same way every time.
//! - [`prometheus`]: reading the gateway's own telemetry into a report sample.
//! - [`sender`]: what a stream sends, paced, frame by frame.
//! - [`drive`]: sending several streams at once, each over its own [`drive::Wire`], and counting
//!   what comes back on any of them.
//! - `port` (with the `dpdk` feature): DPDK queues as a wire.
//!
//! Frames are built and read by this crate's own code, not the dataplane's, so that the two
//! cannot agree on a bug.

pub mod bfd;
pub mod bgp;
mod checksum;
pub mod drive;
pub mod frame;
pub mod ledger;
pub mod mutate;
#[cfg(feature = "dpdk")]
pub mod port;
pub mod prometheus;
pub mod schedule;
pub mod sender;
pub mod signature;
pub mod space;
pub mod tcp;

#[cfg(test)]
mod tests;
