// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub(crate) mod allocation;
mod allocator_writer;
pub(crate) mod apalloc;
mod flows;
pub(crate) mod icmp_handling;
mod nf;
mod packet;
mod state;
#[cfg(test)]
mod tests;

//= https://www.rfc-editor.org/rfc/rfc4787#section-6
//= type=todo
//# REQ-9:  A NAT MUST support "Hairpinning".

// re exports
pub use allocator_writer::MasqueradeConfig;
pub use allocator_writer::{NatAllocatorReader, NatAllocatorReaderFactory, NatAllocatorWriter};
pub use apalloc::MasqueradeUsage;
pub use nf::Masquerade;
pub(crate) use state::MasqueradeState;
#[cfg(test)]
pub(crate) use tests::probe;

use tracectl::trace_target;
trace_target!("masquerade", LevelFilter::INFO, &["nat", "pipeline"]);
