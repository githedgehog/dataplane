// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library for working with and validating network data

// This library should always compile without std (even if we never ship that way)
#![cfg_attr(not(test), no_std)]
// Validation logic should always be strictly safe if at all possible
#![deny(unsafe_code)]
// yeah, I'm that guy.  I'm not sorry.
#![deny(missing_docs, clippy::all, clippy::pedantic)]
// Do you know where your towel is?
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate alloc;

pub mod eth;
pub mod ipv4;
pub mod ipv6;
pub mod packet;
pub mod vlan;
pub mod vxlan;
