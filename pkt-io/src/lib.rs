// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local packet I/O for gateway

#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::collapsible_if,
    clippy::missing_errors_doc
)]

mod nf;
mod queue;
mod tests;

pub use nf::PktIo;
pub use queue::{PktQueue, QueuedPacket};
