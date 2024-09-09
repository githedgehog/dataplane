//! Safe DPDK bindings for Rust.
//!
//! This crate provides safe bindings to the DPDK library.
//! Lower-level bindings are provided by the `dpdk-sys` crate.
//! This crate strives to provide a more rust-idiomatic interface,
//! making use of features like RAII (drop traits).
//!
//! Where possible, prefer using this crate over `dpdk-sys`.
//!
//! This _library_ is `no_std` by design, although it is intended to be used in a `std` context.
//! The idea is to forbid the use of libc functionality like file io and system allocation (which
//! are not to be used in a dataplane anyway).
//! The dpdk allocator is fine, and you can use `std` in tests, but the library itself should be
//! `no_std`.
//!
//! # Safety
//!
//! This crate directly calls `dpdk-sys` and thus makes use of `unsafe` (read "not easily analyzed
//! by the rust compiler") code.
//!
//! That said, the _purpose_ of this crate is to provide a safer interface to DPDK.
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
//! encourage proper error handling.
#![cfg_attr(not(test), no_std)]
#![warn(
    missing_docs,
    clippy::all,
    clippy::missing_panics_doc,
    clippy::missing_safety_doc
)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(private_bounds)]
#![deny(missing_docs)]

pub mod dev;
pub mod eal;
pub mod socket;

extern crate alloc;

use tracing::{info, instrument};

#[cfg(test)]
mod test_inner {
    #[allow(unused_imports)]
    use alloc::{
        format,
        string::{String, ToString},
    };
    /// Feel free to use `std` as needed in tests, but try to avoid `println!` et al.
    /// `tracing::{info, debug, error, ...}` is a better option in our case anyway.
    /// `#[traced_test]` will enable a trace collection on a per-test basis.
    ///
    /// Wherever possible, restrict test logic to `core` and `alloc` to keep the test
    /// suite as close to the production environment as possible.
    #[allow(unused_extern_crates)]
    extern crate std;
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use rstest::{fixture, rstest};
    #[allow(unused_imports)]
    use tracing_test::traced_test;
}
