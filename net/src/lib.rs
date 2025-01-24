// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg_attr(not(test), no_std)] // This library should always compile without std (even if we never ship that way)
#![forbid(unsafe_code)] // Validation logic should always be strictly safe
#![deny(missing_docs, clippy::all, clippy::pedantic)] // yeah, I'm that guy.  I'm not sorry.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Do you know where your towel is?

//! A library for working with and strictly validating network data

extern crate alloc;

pub mod vlan;
pub mod vxlan;
