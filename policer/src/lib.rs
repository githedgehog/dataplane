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

//! Three color markers (RFC 2697 and RFC 2698) for policing traffic at line rate.
//!
//! A meter colors each packet green, yellow or red the moment it arrives; nothing is queued, so a
//! meter costs a few comparisons a packet whatever the rate. It can limit bytes, packets, or both.
//!
//! [`Meter`] is the exact meter, for one thread. [`SharedMeter`] is the one to use when the traffic
//! it limits is spread over several workers: each worker leases tokens in batches, so the workers do
//! not contend on every packet, at the cost of a bounded departure from the exact meter.

mod buckets;
mod meter;
mod profile;
mod shared;

#[cfg(test)]
mod tests;

pub use buckets::Color;
pub use meter::Meter;
pub use profile::{Limits, Profile, ProfileError, Rate, SingleRate, TwoRate};
pub use shared::{LocalMeter, SharedMeter};
