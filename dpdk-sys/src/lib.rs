// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Raw DPDK bindings for Rust.

// We don't need to throw down over differences in name style between C and Rust in the bindings.
#![allow(
    clippy::all,
    clippy::pedantic,
    deprecated,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
// Bindgen code currently isn't complying with 2024 edition style but not much we can do a about it
// on our side.
// Silence the warning messages for now.
#![allow(unsafe_op_in_unsafe_fn)]

include!(concat!(env!("OUT_DIR"), "/generated.rs"));
