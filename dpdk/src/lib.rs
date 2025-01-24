// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Safe DPDK bindings for Rust.
//!
//! This crate provides safe bindings to the DPDK library.
//! Lower-level bindings are provided by the `dpdk-sys` crate.
//! This crate strives to provide a more rust-idiomatic interface,
//! making use of features like RAII (drop traits).
//!
//! Where possible, prefer using this crate over `dpdk-sys`.

//! # Safety
//!
//! This crate directly calls `dpdk-sys` and thus makes use of `unsafe` (read unchecked) code.
//!
//! That said, the _purpose_ of this crate is to provide a safe interface to DPDK.
//!
//! So both in general, and in this case in particular, please try to avoid panicking in library
//! code!
//!
//! At minimum, if you must panic (and there are times when that is the only reasonable option),
//! please do so with
//!
//! 1. an explicit `#[allow(...)]` with a comment explaining why the panic is necessary, and
//! 2. a `# Safety` note in the doc comments explaining the conditions that would cause a panic.
//!
//! This crate uses lints to discourage casual use of `unwrap`, `expect`, and `panic` to help
//! encourage this practice.

#![warn(clippy::all)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(private_bounds)]
extern crate alloc;
extern crate core;

pub mod dev;
pub mod eal;
pub mod flow;
pub mod mem;
pub mod queue;
pub mod socket;
