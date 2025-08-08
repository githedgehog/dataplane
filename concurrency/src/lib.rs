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

#[cfg(all(feature = "loom", feature = "shuttle"))]
compile_error!("Cannot enable both 'loom' and 'shuttle' features at the same time");

#[cfg(not(any(feature = "loom", feature = "shuttle")))]
pub use std::sync;

#[cfg(feature = "loom")]
pub use loom::sync;

#[cfg(feature = "shuttle")]
pub use shuttle::sync;
