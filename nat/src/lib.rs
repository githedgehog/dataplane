// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]

//! Network Address Translation (NAT) for the dataplane
//!
//! This package implements a [`pipeline::NetworkFunction`] that provides Network Address
//! Translation (NAT) functionality, either source or destination.
//!
//! # Example
//!
//! ```
//! # use net::buffer::TestBuffer;
//! # use net::headers::TryIpv4;
//! # use net::packet::test_utils::build_test_ipv4_packet;
//! # use pipeline::NetworkFunction;
//! use dataplane_nat::StatelessNat;
//!
//! let (mut nat, _tablew) = StatelessNat::new();
//! let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
//! let packets_out: Vec<_> = nat.process(packets).collect();
//!
//! let hdr0_out = &packets_out[0]
//!     .try_ipv4()
//!     .expect("Failed to get IPv4 header");
//! ```
//!
//! # Limitations
//!
//! The package is subject to the following limitations:
//!
//! - Only NAT44 is supported (no NAT46, NAT64, or NAT66)
//! - Either source or destination NAT is supported, only one at a time, by a given [`StatelessNat`]
//!   or [`StatefulNat`] object.
//! - "Expose" objects mixing IPv4 and IPv6 endpoints or list of exposed IPs are not supported
//! - The total number of available (not excluded) private addresses used in an "Expose" object must
//!   be equal to the total number of publicly exposed addresses in this object.

mod stateful;
pub mod stateless;

pub use stateful::StatefulNat;
pub use stateless::StatelessNat;
