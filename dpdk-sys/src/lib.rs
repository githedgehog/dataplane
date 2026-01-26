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
    non_upper_case_globals,
    // Rust v1.93 reports unnecessary transmutes in bindgen output, when processing the bitfields
    // for struct _IO_FILE's _flags2, from /usr/include/bits/types/struct_FILE.h.
    // Remove once bindgen is fixed.
    unnecessary_transmutes,
)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
