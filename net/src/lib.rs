// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library for working with and validating network data

#![cfg_attr(not(any(test, feature = "_no-panic")), no_std)] // This library should always compile without std (even if we never ship that way)
#![deny(unsafe_code)] // Validation logic should always be strictly safe
#![deny(missing_docs, clippy::all, clippy::pedantic)] // yeah, I'm that guy.  I'm not sorry.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Do you know where your towel is?

extern crate alloc;

pub mod vlan;
pub mod vxlan;
pub mod packet;
pub mod eth;
pub mod ipv4;
pub mod ipv6;
