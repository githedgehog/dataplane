// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library for working with and validating network data

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

extern crate alloc;
extern crate core;

/// testing
pub mod eth;
pub mod ipv4;
pub mod ipv6;
pub mod packet;
pub mod vlan;
pub mod vxlan;
mod header;
mod parse;
