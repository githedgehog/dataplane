// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// Required for `self: Arc<Self>` methods under loom's Arc newtype.
#![cfg_attr(feature = "loom", feature(arbitrary_self_types))]
#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(clippy::missing_errors_doc)]

//! Network Address Translation (NAT) for the dataplane
//!
//! This package implements a [`pipeline::NetworkFunction`] that provides Network Address
//! Translation (NAT) functionality, source or destination.
//!
//! # Limitations
//!
//! The package is subject to the following limitations:
//!
//! - Only NAT44 is supported (no NAT46, NAT64, or NAT66)
//! - "Expose" objects mixing IPv4 and IPv6 endpoints or list of exposed IPs are not supported

mod common;
mod icmp_handler;
pub mod masquerade;
mod port;
pub mod portfw;
mod ranges;
pub mod static_nat;
#[cfg(test)]
mod test;

pub use icmp_handler::nf::IcmpErrorHandler;
pub use masquerade::Masquerade;
pub use port::NatPort;
pub use static_nat::StaticNat;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
struct NatEndpoint {
    addr: IpAddr,
    port: Option<NatPort>,
}

impl NatEndpoint {
    #[must_use]
    pub(crate) fn new(addr: IpAddr, port: Option<NatPort>) -> Self {
        Self { addr, port }
    }

    #[must_use]
    pub(crate) fn with_port(addr: IpAddr, port: NatPort) -> Self {
        Self::new(addr, Some(port))
    }
}

#[derive(Debug, Default)]
struct NatTranslationData {
    src: Option<NatEndpoint>,
    dst: Option<NatEndpoint>,
}

impl NatTranslationData {
    #[must_use]
    pub(crate) fn with_src(mut self, endpoint: NatEndpoint) -> Self {
        self.src = Some(endpoint);
        self
    }

    #[must_use]
    pub(crate) fn with_dst(mut self, endpoint: NatEndpoint) -> Self {
        self.dst = Some(endpoint);
        self
    }
}
