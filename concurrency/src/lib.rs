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

#[cfg(not(any(
    feature = "loom",
    feature = "shuttle",
    feature = "shuttle_pct",
    feature = "shuttle_dfs"
)))]
pub use std::thread;

#[cfg(all(
    feature = "loom",
    not(any(feature = "shuttle", feature = "shuttle_pct", feature = "shuttle_dfs")),
    not(feature = "silence_clippy")
))]
pub use loom::thread;

#[cfg(all(
    any(feature = "shuttle", feature = "shuttle_pct", feature = "shuttle_dfs"),
    not(feature = "loom"),
    not(feature = "silence_clippy")
))]
pub use shuttle::thread;

#[cfg(all(feature = "shuttle", feature = "loom", not(feature = "silence_clippy")))]
compile_error!("Cannot enable both 'loom' and 'shuttle' features at the same time");

//////////////////////
// This is a workaround to silence clippy warnings when both loom and shuttle
// features are enabled in the clippy checks which uses --all-features.
#[cfg(all(feature = "shuttle", feature = "loom", feature = "silence_clippy"))]
pub use std::thread;
//////////////////////

#[cfg(all(feature = "silence_clippy", not(feature = "shuttle")))]
compile_error!("silence_clippy manually enabled, should only be enabled by --all-features");

#[cfg(all(feature = "silence_clippy", not(feature = "loom")))]
compile_error!("silence_clippy manually enabled, should only be enabled by --all-features");

#[allow(unused_imports)]
pub use macros::*;

pub mod quiescent;
pub mod slot;
