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

//! A three color marker (MEF 10, coupled) for policing traffic at line rate.
//!
//! A meter colors each packet green, yellow or red the moment it arrives; nothing is queued, so a
//! meter costs a few comparisons a packet whatever the rate. A [`Profile`] counts tokens: a meter
//! limits bytes or packets as its caller charges each packet one token per byte or one per packet.
//! Meters are color-aware, never coloring a packet better than it arrived, so that one meter can
//! follow another: a byte meter, then a packet meter on what the byte meter colored.
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
pub use profile::{Profile, ProfileError, Rate};
pub use shared::{LocalMeter, SharedMeter};
