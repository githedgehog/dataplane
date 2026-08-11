// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub(crate) mod allocation;
mod allocator_writer;
pub mod apalloc;
pub(crate) mod flows;
pub(crate) mod icmp_handling;
mod natip;
mod nf;
mod packet;
mod protocol;
mod state;
mod test;

// re exports
pub use allocator_writer::MasqueradeConfig;
pub use allocator_writer::NatAllocatorWriter;
pub use nf::Masquerade;

use tracectl::trace_target;
trace_target!("masquerade", LevelFilter::INFO, &["nat", "pipeline"]);
