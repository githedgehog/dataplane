// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Raw DPDK bindings for Rust.

// We don't need to throw down over differences in name style between C and Rust in the bindings.
#![allow(
    clippy::all,
    clippy::pedantic,
    deprecated,
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
)]

include!(concat!(env!("OUT_DIR"), "/generated.rs"));
