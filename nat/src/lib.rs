// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(clippy::missing_errors_doc)]

//! Network Address Translation (NAT) for the dataplane
//!
//! This package implements a [`pipeline::NetworkFunction`] that provides Network Address
//! Translation (NAT) functionality, either source or destination.
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

mod icmp_handler;
mod port;
pub mod portfw;
mod ranges;
pub mod stateful;
pub mod stateless;

pub use port::NatPort;
pub use stateful::StatefulNat;
pub use stateless::StatelessNat;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
struct NatTranslationData {
    src_addr: Option<IpAddr>,
    dst_addr: Option<IpAddr>,
    src_port: Option<NatPort>,
    dst_port: Option<NatPort>,
}
impl NatTranslationData {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub(crate) fn src_addr(mut self, address: IpAddr) -> Self {
        self.src_addr = Some(address);
        self
    }
    #[must_use]
    pub(crate) fn dst_addr(mut self, address: IpAddr) -> Self {
        self.dst_addr = Some(address);
        self
    }
    #[must_use]
    pub(crate) fn src_port(mut self, natport: NatPort) -> Self {
        self.src_port = Some(natport);
        self
    }
    #[must_use]
    pub(crate) fn dst_port(mut self, natport: NatPort) -> Self {
        self.dst_port = Some(natport);
        self
    }
}
