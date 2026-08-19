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

// A todo has to be anchored somewhere and hairpinning has no code yet, so it sits at the
// crate root. Where it will go when it is written: `nf::Masquerade`, in the source-NAT
// direction, has to recognise that the destination it is about to translate is one of its
// own public addresses and turn the packet back inward with both halves translated. The
// pieces it needs are the pool (`apalloc`, to answer "is this mine") and the reverse
// lookup the inbound path already does.
//= https://www.rfc-editor.org/rfc/rfc4787#section-6
//= type=todo
//# REQ-9:  A NAT MUST support "Hairpinning".

// re exports
pub use allocator_writer::MasqueradeConfig;
pub use allocator_writer::NatAllocatorWriter;
pub use nf::Masquerade;

use tracectl::trace_target;
trace_target!("masquerade", LevelFilter::INFO, &["nat", "pipeline"]);
