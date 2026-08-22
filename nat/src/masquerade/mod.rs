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
//
// Not implemented, and not implemented anywhere: "hairpin" does not appear in this workspace. Two
// hosts inside one VPC that address each other by a public masqueraded address are not turned
// back at the gateway.
//
// There is a real argument that the requirement does not apply as written. RFC 4787 assumes hosts
// behind the NAT have discoverable external addresses to aim at; under masquerade a public tuple
// exists only for the lifetime of an outbound flow and is not something a peer can learn and dial.
// Stable inbound addresses are port forwarding and static NAT, which are different code.
//
// That argument may well be right, which is exactly why this is `todo`. It has not been made by
// anyone who owns the decision, and REQ-9 is a MUST. If it is correct, this becomes an
// `exception` with the reasoning above; if it is not, hairpinning is missing from a NAT that
// claims to be one.
// re exports
pub use allocator_writer::MasqueradeConfig;
pub use allocator_writer::NatAllocatorWriter;
pub use nf::Masquerade;

use tracectl::trace_target;
trace_target!("masquerade", LevelFilter::INFO, &["nat", "pipeline"]);
