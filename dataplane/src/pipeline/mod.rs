// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Pipeline Building Blocks

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub mod sample_nfs;
mod static_nf;

#[cfg(test)]
pub(crate) mod test_utils;

#[allow(unused)]
pub use static_nf::{NetworkFunction, StaticChain};
