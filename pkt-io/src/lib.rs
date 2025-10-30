// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

#![deny(clippy::all)]

mod nf;
mod portmap;
mod tests;

pub use nf::PktIo;
pub use nf::PktQueue;
