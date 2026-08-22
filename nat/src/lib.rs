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

/// One side of a translation: the address to write into the embedded packet, and the port to
/// write with it.
///
/// The port stays optional because `None` is a real instruction -- "translate the address and
/// leave the transport header alone", which is what an inner packet with no transport, or one
/// whose port is not being remapped, needs.
///
/// A port *without* an address is not expressible, because it is not something
/// `nat_translate_icmp_inner` can act on: it branches on the address, so a lone port used to be
/// accepted and then silently discarded.
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

    /// The endpoint with its port translated as well.
    #[must_use]
    pub(crate) fn with_port(addr: IpAddr, port: NatPort) -> Self {
        Self::new(addr, Some(port))
    }
}

/// Which sides of an embedded packet a translation rewrites.
///
/// Both sides optional and independent: an ICMP error's embedded packet has exactly one side that
/// the matching mapping knows about, which side depending on the direction the error travelled.
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
