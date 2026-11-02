// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network functions to punt and inject packets

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

pub use nf::{PktIo, PktIoFactory, TestPktIo, TrapFunction, no_trap, queues};
pub use queue::{EndpointId, InjectError, Injector, PuntReceiver, PuntedPacket};

use tracectl::trace_target;
const PKT_IO: &str = "pkt-io";
trace_target!(PKT_IO, LevelFilter::TRACE, &["pipeline"]);
