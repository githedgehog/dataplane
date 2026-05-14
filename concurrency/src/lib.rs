// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)]

pub mod macros;
pub mod sync;

#[cfg(all(miri, any(feature = "shuttle", feature = "loom")))]
compile_error!("miri does not meaningfully support 'loom' or 'shuttle'");

#[cfg(not(any(feature = "loom", feature = "shuttle")))]
pub use std::thread;

#[cfg(all(
    feature = "loom",
    not(feature = "shuttle"),
    not(feature = "_silence_clippy")
))]
pub use loom::thread;

#[cfg(all(
    feature = "shuttle",
    not(feature = "loom"),
    not(feature = "_silence_clippy")
))]
pub use shuttle::thread;

// `_silence_clippy` is only set under `--all-features`, where both `loom`
// and `shuttle` are pulled in. Route `thread` to `std` purely to keep clippy
// happy; the binary is never executed in that configuration.
#[cfg(all(feature = "shuttle", feature = "loom", feature = "_silence_clippy"))]
pub use std::thread;

#[cfg(all(feature = "_silence_clippy", not(feature = "shuttle")))]
compile_error!("silence_clippy manually enabled, should only be enabled by --all-features");

#[cfg(all(feature = "_silence_clippy", not(feature = "loom")))]
compile_error!("silence_clippy manually enabled, should only be enabled by --all-features");

#[allow(unused_imports)]
pub use macros::*;

pub mod quiescent;
pub mod slot;
