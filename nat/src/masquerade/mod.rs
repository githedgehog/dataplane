// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub(crate) mod allocation;
mod allocator_writer;
pub mod apalloc;
mod contract;
mod expiry;
pub(crate) mod flows;
mod fuzz;
pub(crate) mod icmp_handling;
mod natip;
mod nf;
mod packet;
mod probe;
mod protocol;
mod state;
mod state_machine;
mod test;

//= https://www.rfc-editor.org/rfc/rfc4787#section-6
//= type=todo
//# REQ-9:  A NAT MUST support "Hairpinning".
// re exports
pub use allocator_writer::MasqueradeConfig;
pub use allocator_writer::NatAllocatorWriter;
pub use nf::Masquerade;

use tracectl::trace_target;
trace_target!("masquerade", LevelFilter::INFO, &["nat", "pipeline"]);
