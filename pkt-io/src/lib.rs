// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

#![deny(clippy::all)]
#![allow(clippy::collapsible_if)]

mod ctl;
mod io;

mod nf;
mod tests;

// re-exports
pub use ctl::IoManagerCtl;
pub use io::{IoManagerError, start_io};
pub use nf::PktIo;
pub use nf::PktQueue;
