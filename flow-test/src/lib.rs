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

//! In-process TCP/UDP flow testing for the dataplane.
//!
//! This crate provides a test harness that bridges two smoltcp TCP/IP endpoints
//! through a user-supplied packet processing closure.
//! All smoltcp types are quarantined behind this crate's public API;
//! consumers interact exclusively with types from the [`net`] crate.

pub mod bridge;
mod device;
mod endpoint;
pub mod error;
pub mod harness;
pub mod tcp_flow;
pub mod tcp_state;
mod time;