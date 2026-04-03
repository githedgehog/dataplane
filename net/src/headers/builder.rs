// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Trait-driven header stacking for test packet construction.
//!
//! This module uses trait bounds to enforce valid layer ordering at
//! compile time.
//!
//! # Design
//!
//! Each header layer participates in three traits:
//!
//! - [`Within<T>`] -- declares that `Self` can follow layer `T`, and adjusts
//!   structural fields on the parent (e.g., setting `EthType::IPV4` on an
//!   `Eth` when `Ipv4` is stacked on top).
//! - [`Install<T>`] -- implemented on [`Headers`] for each header type,
//!   describing where to store the layer.
//! - [`Blank`] -- produces the cheapest valid instance of a header type.
//!   Unlike `Default`, `Blank` makes no semantic claims about field values.
//!
//! [`HeaderStack<T>`] is the state carrier that provides the chaining API.
//!
//! # Examples
//!
//! ```ignore
//! use net::headers::builder::*;
//!
//! let headers = HeaderStack::new()
//!     .eth(|e| {
//!         e.set_source(my_src_mac);
//!         e.set_destination(my_dst_mac);
//!     })
//!     .ipv4(|ip| {
//!         ip.set_source(my_src_ip);
//!         ip.set_destination(my_dst_ip);
//!     })
//!     .tcp(|tcp| {
//!         tcp.set_source(TcpPort::new_checked(12345).unwrap());
//!         tcp.set_destination(TcpPort::new_checked(80).unwrap());
//!     })
//!     .build_headers_with_payload([])
//!     .unwrap();
//! ```
//!
//! # `build_headers_with_payload` vs `build_headers`
//!
//! - [`.build_headers_with_payload(bytes)`](HeaderStack::build_headers_with_payload)
//!   -- computes length fields *and* checksums.  Use when you need a
//!   wire-correct packet.
//! - [`.build_headers()`](HeaderStack::build_headers) -- computes length
//!   fields only.  Use when checksums are irrelevant (e.g., ACL matching
//!   tests).
//!
//! # Not yet supported
//!
//! - **IPv6 extension headers** (`Ipv6Ext`, `IpAuth`).  These chain via
//!   `net_ext` on [`Headers`] and need their own `next_header` management
//!   (the extension's `next_header` field, not the base `Ipv6` header's).
//!   Requires constructors and `TypeGenerator` impls that don't exist yet.

use std::num::NonZero;

use crate::checksum::Checksum;
use crate::headers::{EmbeddedHeadersBuilder, EmbeddedTransport, Headers};
use crate::icmp4::Icmp4;
use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::Icmp6;
use crate::icmp6::TruncatedIcmp6;
use crate::ip::NextHeader;
use crate::ipv4::Ipv4;
use crate::ipv4::Ipv4LengthError;
use crate::ipv6::Ipv6;
use crate::parse::DeParse;
use crate::tcp::port::TcpPort;
use crate::tcp::{Tcp, TruncatedTcp};
use crate::udp::port::UdpPort;
use crate::udp::{Udp, UdpEncap};

use super::{Net, Transport};

/// Errors that can occur when finalizing a header stack.
///
/// Many invalid combinations (e.g. ICMP4 on IPv6, VXLAN without UDP) are
/// compile-time impossible via [`Within`] bounds.  The errors here cover
/// length-computation failures that can only be detected at finalization.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The sum of header and payload sizes overflows `u16`.
    ///
    /// Returned when the payload itself exceeds `u16`, or when adding
    /// transport + embedded + encapsulation + payload sizes together
    /// would overflow a `u16` length field (IP payload length or UDP
    /// datagram length).
    #[error("payload too large for IP/UDP length fields")]
    PayloadTooLarge,

    /// The IP payload fits in `u16`, but the IPv4 *total* length
    /// (`ihl + payload`) exceeds the field maximum.
    ///
    /// This can happen when IPv4 options increase the header length
    /// enough that the combined total no longer fits.  IPv6 is not
    /// affected because its `payload_length` field excludes the fixed
    /// header.
    #[error("IPv4 total length overflow (header + payload exceeds u16): {0}")]
    Ipv4PayloadOverflow(Ipv4LengthError),
}

/// Sub-builder for the headers embedded inside an ICMP error message.
///
/// Embedded headers start at the IP layer (no Ethernet / VLAN).  The
/// assembler automatically sets:
/// - The inner IP's `NextHeader` to match the chosen transport
/// - The inner IP's payload length to equal the transport header size
///   (representing a minimal "original" packet with no application data)
#[must_use]
pub struct EmbeddedAssembler {
    net: Option<Net>,
    transport: Option<EmbeddedTransport>,
}

impl EmbeddedAssembler {
    /// Create a new, empty embedded assembler.
    pub(crate) fn new() -> Self {
        Self {
            net: None,
            transport: None,
        }
    }

    /// Set the inner network layer to `Ipv4`.
    pub fn ipv4(mut self, f: impl FnOnce(&mut Ipv4)) -> Self {
        let mut ipv4 = Ipv4::default();
        f(&mut ipv4);
        self.net = Some(Net::Ipv4(ipv4));
        self
    }

    /// Set the inner network layer to `Ipv6`.
    pub fn ipv6(mut self, f: impl FnOnce(&mut Ipv6)) -> Self {
        let mut ipv6 = Ipv6::default();
        f(&mut ipv6);
        self.net = Some(Net::Ipv6(ipv6));
        self
    }

    /// Set the inner transport to `Tcp`.
    pub fn tcp(mut self, src: TcpPort, dst: TcpPort, f: impl FnOnce(&mut Tcp)) -> Self {
        let mut tcp = Tcp::new(src, dst);
        f(&mut tcp);
        self.transport = Some(EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(tcp)));
        self
    }

    /// Set the inner transport to `Udp`.
    pub fn udp(mut self, src: UdpPort, dst: UdpPort, f: impl FnOnce(&mut Udp)) -> Self {
        let mut udp = Udp::new(src, dst);
        f(&mut udp);
        self.transport = Some(EmbeddedTransport::Udp(
            crate::udp::TruncatedUdp::FullHeader(udp),
        ));
        self
    }

    /// Set the inner transport to `Icmp4`.
    pub fn icmp4(mut self, icmp: Icmp4) -> Self {
        self.transport = Some(EmbeddedTransport::Icmp4(TruncatedIcmp4::FullHeader(icmp)));
        self
    }

    /// Set the inner transport to `Icmp6`.
    pub fn icmp6(mut self, icmp: Icmp6) -> Self {
        self.transport = Some(EmbeddedTransport::Icmp6(TruncatedIcmp6::FullHeader(icmp)));
        self
    }

    /// Consume the assembler and produce an [`EmbeddedHeaders`] value.
    ///
    /// Sets `NextHeader` on the inner IP based on the transport (if any),
    /// and sets IP payload length to the transport header size.
    /// This is done here rather than in the transport methods so that
    /// the call order (net vs transport) does not matter.
    pub(crate) fn finish(mut self) -> super::EmbeddedHeaders {
        assert!(
            self.transport.is_none() || self.net.is_some(),
            "embedded transport requires a network layer"
        );

        // Set NextHeader based on transport type.  Done in finish() so
        // it works regardless of whether net or transport was set first.
        let nh = match &self.transport {
            Some(EmbeddedTransport::Tcp(_)) => Some(NextHeader::TCP),
            Some(EmbeddedTransport::Udp(_)) => Some(NextHeader::UDP),
            Some(EmbeddedTransport::Icmp4(_)) => Some(NextHeader::ICMP),
            Some(EmbeddedTransport::Icmp6(_)) => Some(NextHeader::ICMP6),
            None => None,
        };
        if let Some(nh) = nh {
            set_net_next_header(&mut self.net, nh);
        }

        let transport_size = self.transport.as_ref().map_or(0u16, |t| t.size().get());

        match &mut self.net {
            Some(Net::Ipv4(ip)) => {
                // transport_size is always small enough; ignore the error.
                let _ = ip.set_payload_len(transport_size);
                ip.update_checksum(&()).unwrap_or_else(|()| unreachable!());
            }
            Some(Net::Ipv6(ip)) => {
                ip.set_payload_length(transport_size);
            }
            None => {}
        }

        let mut b = EmbeddedHeadersBuilder::default();
        b.net(self.net).transport(self.transport);
        #[allow(clippy::unwrap_used)] // all fields have #[builder(default)]
        b.build().unwrap()
    }
}

/// Set `NextHeader` on whichever IP variant is present.
fn set_net_next_header(net: &mut Option<Net>, nh: NextHeader) {
    match net {
        Some(Net::Ipv4(ip)) => {
            ip.set_next_header(nh);
        }
        Some(Net::Ipv6(ip)) => {
            ip.set_next_header(nh);
        }
        None => {}
    }
}

/// Declares that `Self` is a valid child of layer `T`.
///
/// When `Self` is stacked on a parent `T`, [`conform`](Within::conform)
/// adjusts structural fields on the parent to be consistent with the child.
/// For example, `Within<Eth> for Ipv4` sets `EthType::IPV4` on the Ethernet
/// header.
///
/// Conformance is called automatically by [`HeaderStack::stack`] before the parent
/// is installed into [`Headers`].
pub trait Within<T> {
    fn conform(parent: &mut T);
}

/// Declares that [`Headers`] can absorb a value of type `T`.
///
/// Each impl stores the value in the appropriate slot on `Headers`
/// (e.g., `set_eth`, `set_transport`, `vlan.try_push`, etc.).
pub trait Install<T> {
    fn install(&mut self, value: T);
}

/// Produce an arbitrary valid instance of a header type.
///
/// Unlike `Default`, `Blank` makes no claim about the *meaning* of the
/// field values -- they are simply the cheapest legal construction.
/// Callers are expected to overwrite any fields they care about via the
/// closure passed to [`HeaderStack::stack`].
pub trait Blank {
    fn blank() -> Self;
}

/// The concrete state carrier for the header-stacking builder.
///
/// `T` is the type of the layer currently being held (not yet installed
/// into [`Headers`]).  It will be installed when the next layer is stacked
/// or when one of the build methods is called.
///
/// Start with [`HeaderStack::new()`], chain layer methods (`.eth(...)`,
/// `.ipv4(...)`, `.tcp(...)`, etc.), then finalize with
/// `.build_headers_with_payload([])` or `.build_headers()`.
pub struct HeaderStack<T> {
    headers: Headers,
    working: T,
}

impl HeaderStack<()> {
    /// Create a new header stack builder.
    #[must_use]
    pub fn new() -> Self {
        HeaderStack {
            headers: Headers::default(),
            working: (),
        }
    }
}

impl Default for HeaderStack<()> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> HeaderStack<T>
where
    Headers: Install<T>,
{
    /// Push a new layer onto the stack.
    ///
    /// The new layer is created via [`Blank::blank`], then the closure `f`
    /// runs to customize it.  The *previous* top-of-stack is conformed
    /// (via [`Within`]) and installed into [`Headers`] before the new layer
    /// is created.
    pub fn stack<U>(mut self, f: impl FnOnce(&mut U)) -> HeaderStack<U>
    where
        U: Blank + Within<T>,
        Headers: Install<U>,
    {
        U::conform(&mut self.working);
        self.headers.install(self.working);

        let mut e = U::blank();
        f(&mut e);
        HeaderStack {
            headers: self.headers,
            working: e,
        }
    }

    /// Install the final layer, compute length fields, and update checksums.
    ///
    /// `payload` is the byte content following all headers on the wire.
    /// Pass `&[]` when there is no trailing payload.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::PayloadTooLarge`] if the total size overflows
    /// `u16`, or [`BuildError::Ipv4PayloadOverflow`] if the IPv4 total
    /// length exceeds the maximum.
    pub fn build_headers_with_payload(
        mut self,
        payload: impl AsRef<[u8]>,
    ) -> Result<Headers, BuildError> {
        self.headers.install(self.working);
        fixup_lengths(&mut self.headers, payload.as_ref())?;
        self.headers.update_checksums(payload);
        Ok(self.headers)
    }

    /// Install the final layer and compute length fields only.
    ///
    /// Checksums are left as-is.  Useful when the caller does not have a
    /// real payload or does not care about checksum correctness (e.g.,
    /// testing header layout or ACL matching where only field values
    /// matter).
    ///
    /// # Errors
    ///
    /// Returns [`BuildError::PayloadTooLarge`] if the total size overflows
    /// `u16`, or [`BuildError::Ipv4PayloadOverflow`] if the IPv4 total
    /// length exceeds the maximum.
    pub fn build_headers(mut self) -> Result<Headers, BuildError> {
        self.headers.install(self.working);
        fixup_lengths(&mut self.headers, &[])?;
        Ok(self.headers)
    }

}


// Seed impls -- the () layer that starts every stack
impl Install<()> for Headers {
    fn install(&mut self, (): ()) {}
}

impl Blank for () {
    fn blank() -> Self {}
}

// Embedded ICMP headers -- modifier on HeaderStack<Icmp4> / HeaderStack<Icmp6>
macro_rules! impl_embedded {
    ($icmp_ty:ty) => {
        impl HeaderStack<$icmp_ty> {
            /// Attach ICMP-error embedded headers.
            ///
            /// The closure receives a fresh [`EmbeddedAssembler`] and should
            /// configure the inner network and (optionally) transport headers
            /// that represent the *offending original packet*.
            #[must_use]
            pub fn embedded(
                mut self,
                f: impl FnOnce(EmbeddedAssembler) -> EmbeddedAssembler,
            ) -> Self {
                let assembler = f(EmbeddedAssembler::new());
                self.headers.embedded_ip = Some(assembler.finish());
                self
            }
        }
    };
}

impl_embedded!(Icmp4);
impl_embedded!(Icmp6);

/// Compute length fields over the fully-assembled headers.
///
/// Sets:
/// 1. UDP datagram length (header + encap + payload)
/// 2. IP payload length (transport + embedded + encap + payload)
///
/// Checksums are NOT touched -- the caller decides whether to run
/// [`Headers::update_checksums`] separately.
fn fixup_lengths(headers: &mut Headers, payload: &[u8]) -> Result<(), BuildError> {
    let transport_size: u16 = headers.transport.as_ref().map_or(0, |t| t.size().get());
    let embedded_size: u16 = headers.embedded_ip.as_ref().map_or(0, |e| e.size().get());
    let encap_size: u16 = match &headers.udp_encap {
        Some(UdpEncap::Vxlan(v)) => v.size().get(),
        None => 0,
    };

    let payload_u16 = u16::try_from(payload.len()).map_err(|_| BuildError::PayloadTooLarge)?;

    // UDP datagram length
    if let Some(Transport::Udp(udp)) = &mut headers.transport {
        let udp_total = Udp::MIN_LENGTH
            .get()
            .checked_add(encap_size)
            .and_then(|v| v.checked_add(payload_u16))
            .and_then(NonZero::new)
            .ok_or(BuildError::PayloadTooLarge)?;

        #[allow(unsafe_code)]
        // SAFETY: `udp_total >= Udp::MIN_LENGTH` by construction.
        unsafe {
            udp.set_length(udp_total);
        }
    }

    // IP payload length
    // TODO: include net_ext size once IPv6 extension headers are supported.
    let ip_payload = transport_size
        .checked_add(embedded_size)
        .and_then(|v| v.checked_add(encap_size))
        .and_then(|v| v.checked_add(payload_u16))
        .ok_or(BuildError::PayloadTooLarge)?;

    match &mut headers.net {
        Some(Net::Ipv4(ip)) => {
            ip.set_payload_len(ip_payload)
                .map_err(BuildError::Ipv4PayloadOverflow)?;
        }
        Some(Net::Ipv6(ip)) => {
            ip.set_payload_length(ip_payload);
        }
        None => {}
    }

    Ok(())
}

