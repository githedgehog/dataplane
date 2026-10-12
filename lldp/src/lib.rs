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

//! LLDP transmission for the dataplane's ports.
//!
//! The dataplane owns its NICs, so the kernel and any LLDP daemon running beside it never see them.
//! Rather than bridge a daemon in, the dataplane speaks LLDP itself: one [`transmit`] task per port
//! advertises an [`Advertisement`] on the schedule IEEE 802.1AB lays out, follows the port's link state,
//! and tells neighbours when it stops.
//!
//! Frames are built with [`net::lldp`] and leave through a [`FrameSink`], so this crate knows nothing
//! about drivers.

mod advert;
mod neighbors;
mod sink;
mod timing;
mod transmitter;

#[cfg(test)]
mod tests;

pub use advert::Advertisement;
pub use neighbors::{Heard, Neighbor, Neighbors};
pub use sink::{FrameSink, Refused};
pub use timing::Timing;
pub use transmitter::{Inputs, Link, transmit};
