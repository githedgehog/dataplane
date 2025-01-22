// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library for working with and validating network data

#![cfg_attr(not(test), no_std)]

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

#![allow(missing_docs, clippy::pedantic)] // temporary allowance (block merge)

extern crate alloc;
extern crate core;

/// testing
pub mod eth;
pub mod icmp4;
pub mod icmp6;
pub mod ip_auth;
pub mod ipv4;
pub mod ipv6;
pub mod packet;
pub mod parse;
pub mod tcp;
pub mod udp;
pub mod vlan;
pub mod vxlan;
pub mod encap;
