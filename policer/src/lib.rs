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

//! Color-aware traffic policing with coupled MEF 10 token buckets.
//!
//! Callers choose the token cost of each packet, allowing byte or packet limits.
//! Meters never improve a packet's input color, so they can be chained.
//!
//! [`Meter`] implements the exact model for one thread.
//! [`SharedMeter`] leases tokens to workers to reduce contention, with bounded differences in bursts
//! and token availability.

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
