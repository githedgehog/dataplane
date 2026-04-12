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
//! # IPv6 Extension Headers
//!
//! Extension headers are supported as individual typed layers:
//! [`HopByHop`], [`DestOpts`], [`Routing`], [`Fragment`], [`Ipv6Auth`].
//! [`Within`] bounds enforce key [RFC 8200 section 4.1] ordering constraints
//! at compile time (e.g. `HopByHop` may only follow `Ipv6`).  The bounds
//! prevent clearly invalid chains but do not enforce the full recommended
//! ordering -- for example, two `DestOpts` layers are both permitted.
//!
//! IPv4 authentication headers use [`Ipv4Auth`], which can only follow `Ipv4`.
//!
//! [RFC 8200 section 4.1]: https://datatracker.ietf.org/doc/html/rfc8200#section-4.1

use std::num::NonZero;

use etherparse::IpNumber;

use crate::checksum::Checksum;
use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::eth::mac::{DestinationMac, Mac, SourceMac};
use crate::headers::{EmbeddedHeadersBuilder, EmbeddedTransport, Headers};
use crate::icmp4::Icmp4;
use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::Icmp6;
use crate::icmp6::TruncatedIcmp6;
use crate::ip::NextHeader;
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv4::Ipv4LengthError;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::parse::DeParse;
use crate::tcp::port::TcpPort;
use crate::tcp::{Tcp, TruncatedTcp};
use crate::udp::port::UdpPort;
use crate::udp::{Udp, UdpChecksum, UdpEncap};
use crate::vlan::{Pcp, Vid, Vlan};
use crate::vxlan::{Vni, Vxlan};

use super::{Net, NetExt, Transport};

/// Errors that can occur when finalizing a header stack.
///
/// Many invalid combinations (e.g. ICMP4 on IPv6, VXLAN without UDP) are
/// compile-time impossible via [`Within`] bounds (which also prevent
/// headers from "dangling" without a valid parent).  The errors here cover
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
    pub(crate) fn finish(self) -> super::EmbeddedHeaders {
        assert!(
            self.transport.is_none() || self.net.is_some(),
            "embedded transport requires a network layer"
        );
        fixup_embedded(self.net, self.transport)
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

/// Build [`EmbeddedHeaders`](super::EmbeddedHeaders) from raw net/transport
/// layers, applying protocol fixups.
///
/// Sets:
/// 1. `NextHeader` on the IP layer to match the transport variant
/// 2. IP payload length to the transport header size
/// 3. IPv4 header checksum (if applicable)
///
/// Used by [`EmbeddedAssembler::finish`].
fn fixup_embedded(
    mut net: Option<Net>,
    transport: Option<EmbeddedTransport>,
) -> super::EmbeddedHeaders {
    // Set NextHeader based on transport type.
    let nh = match &transport {
        Some(EmbeddedTransport::Tcp(_)) => Some(NextHeader::TCP),
        Some(EmbeddedTransport::Udp(_)) => Some(NextHeader::UDP),
        Some(EmbeddedTransport::Icmp4(_)) => Some(NextHeader::ICMP),
        Some(EmbeddedTransport::Icmp6(_)) => Some(NextHeader::ICMP6),
        None => None,
    };
    if let Some(nh) = nh {
        set_net_next_header(&mut net, nh);
    }

    let transport_size = transport.as_ref().map_or(0u16, |t| t.size().get());

    match &mut net {
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
    b.net(net).transport(transport);

    b.build().unwrap_or_else(|_| unreachable!())
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

/// Helper macro to generate named layer methods on `HeaderStack<T>`.
macro_rules! layer_method {
    ($(#[$meta:meta])* $method:ident, $header:ty) => {
        $(#[$meta])*
        pub fn $method(self, f: impl FnOnce(&mut $header)) -> HeaderStack<$header>
        where
            $header: Blank + Within<T>,
            Headers: Install<$header>,
        {
            self.stack(f)
        }
    };
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
    pub fn stack<U>(mut self, mutate: impl FnOnce(&mut U)) -> HeaderStack<U>
    where
        U: Blank + Within<T>,
        Headers: Install<U>,
    {
        U::conform(&mut self.working);
        self.headers.install(self.working);

        let mut e = U::blank();
        mutate(&mut e);
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

    layer_method!(
        /// Push an `Eth` layer.
        eth, Eth
    );
    layer_method!(
        /// Push a `Vlan` layer.
        vlan, Vlan
    );
    layer_method!(
        /// Push an `Ipv4` layer.
        ipv4, Ipv4
    );
    layer_method!(
        /// Push an `Ipv6` layer.
        ipv6, Ipv6
    );
    layer_method!(
        /// Push a `Tcp` layer.
        tcp, Tcp
    );
    layer_method!(
        /// Push a `Udp` layer.
        udp, Udp
    );
    layer_method!(
        /// Push an `Icmp4` layer.
        icmp4, Icmp4
    );
    layer_method!(
        /// Push an `Icmp6` layer.
        icmp6, Icmp6
    );
    layer_method!(
        /// Push a `Vxlan` layer.
        vxlan, Vxlan
    );

    // IPv6 extension header layers

    layer_method!(
        /// Push a `HopByHop` extension header (RFC 8200 section 4.3).
        hop_by_hop, HopByHop
    );
    layer_method!(
        /// Push a `DestOpts` extension header (RFC 8200 section 4.6).
        dest_opts, DestOpts
    );
    layer_method!(
        /// Push a `Routing` extension header (RFC 8200 section 4.4).
        routing, Routing
    );
    layer_method!(
        /// Push a `Fragment` extension header (RFC 8200 section 4.5).
        fragment, Fragment
    );
    layer_method!(
        /// Push an `Ipv4Auth` extension header (RFC 4302, IPv4 context).
        ipv4_auth, Ipv4Auth
    );
    layer_method!(
        /// Push an `Ipv6Auth` extension header (RFC 4302, IPv6 context).
        ipv6_auth, Ipv6Auth
    );

    // ICMPv4 subtype layers -- available after `.icmp4()`

    layer_method!(
        /// Specialize as `Icmp4` Destination Unreachable (type 3).
        dest_unreachable, Icmp4DestUnreachable
    );
    layer_method!(
        /// Specialize as `ICMPv4` Redirect (type 5).
        redirect, Icmp4Redirect
    );
    layer_method!(
        /// Specialize as `ICMPv4` Time Exceeded (type 11).
        time_exceeded, Icmp4TimeExceeded
    );
    layer_method!(
        /// Specialize as `ICMPv4` Parameter Problem (type 12).
        param_problem, Icmp4ParamProblem
    );
    layer_method!(
        /// Specialize as `ICMPv4` Echo Request (type 8).
        echo_request, Icmp4EchoRequest
    );
    layer_method!(
        /// Specialize as `ICMPv4` Echo Reply (type 0).
        echo_reply, Icmp4EchoReply
    );

    // ICMPv6 subtype layers -- available after `.icmp6()`
    //
    // ICMPv6 subtypes use a `6` suffix to avoid ambiguity with
    // the ICMPv4 methods above. Both sets live in the same generic impl
    // block, and Rust resolves the correct one via the `Within<T>` bound
    // on `T` (the current top-of-stack).

    layer_method!(
        /// Specialize as `ICMPv6` Destination Unreachable (type 1).
        dest_unreachable6, Icmp6DestUnreachable
    );
    layer_method!(
        /// Specialize as `ICMPv6` Packet Too Big (type 2).
        packet_too_big6, Icmp6PacketTooBig
    );
    layer_method!(
        /// Specialize as `ICMPv6` Time Exceeded (type 3).
        time_exceeded6, Icmp6TimeExceeded
    );
    layer_method!(
        /// Specialize as `ICMPv6` Parameter Problem (type 4).
        param_problem6, Icmp6ParamProblem
    );
    layer_method!(
        /// Specialize as `ICMPv6` Echo Request (type 128).
        echo_request6, Icmp6EchoRequest
    );
    layer_method!(
        /// Specialize as `ICMPv6` Echo Reply (type 129).
        echo_reply6, Icmp6EchoReply
    );
}

// Within impls -- valid layer relationships
impl Within<()> for Eth {
    fn conform(_parent: &mut ()) {}
}

impl Within<Eth> for Vlan {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::VLAN);
    }
}

impl Within<Vlan> for Vlan {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::VLAN);
    }
}

impl Within<Eth> for Ipv4 {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::IPV4);
    }
}

impl Within<Vlan> for Ipv4 {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::IPV4);
    }
}

impl Within<Eth> for Ipv6 {
    fn conform(parent: &mut Eth) {
        parent.set_ether_type(EthType::IPV6);
    }
}

impl Within<Vlan> for Ipv6 {
    fn conform(parent: &mut Vlan) {
        parent.set_inner_ethtype(EthType::IPV6);
    }
}

impl Within<Ipv4> for Tcp {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv6> for Tcp {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv4> for Udp {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv6> for Udp {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv4> for Icmp4 {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::ICMP);
    }
}

impl Within<Ipv6> for Icmp6 {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<Udp> for Vxlan {
    fn conform(parent: &mut Udp) {
        let _ = parent.set_checksum(UdpChecksum::ZERO);
        parent.set_destination(Vxlan::PORT);
    }
}

// ---------------------------------------------------------------------------
// Within impls for IPv6 extension headers (RFC 8200 section 4.1 ordering)
// ---------------------------------------------------------------------------
//
// Recommended order:
//   IPv6 -> HopByHop -> DestOpts -> Routing -> Fragment -> AH -> DestOpts -> upper
//
// HopByHop MUST immediately follow IPv6 when present.
// DestOpts may appear in two positions (before Routing, and after AH).
// The `Within` bounds encode valid parent->child transitions; absence of
// an impl = compile error = invalid ordering.

// -- HopByHop: only after Ipv6 --
impl Within<Ipv6> for HopByHop {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::HOP_BY_HOP);
    }
}

// -- DestOpts: after Ipv6, HopByHop, Routing, Fragment, or Ipv6Auth --
// RFC 8200 section 4.1 allows DestOpts in two positions: before Routing
// (first occurrence) and as the final extension before the upper layer.
impl Within<Ipv6> for DestOpts {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

impl Within<HopByHop> for DestOpts {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

impl Within<Routing> for DestOpts {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

impl Within<Fragment> for DestOpts {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

impl Within<Ipv6Auth> for DestOpts {
    fn conform(parent: &mut Ipv6Auth) {
        parent.set_next_header(NextHeader::DEST_OPTS);
    }
}

// -- Routing: after Ipv6, HopByHop, or DestOpts --
impl Within<Ipv6> for Routing {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::ROUTING);
    }
}

impl Within<HopByHop> for Routing {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::ROUTING);
    }
}

impl Within<DestOpts> for Routing {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::ROUTING);
    }
}

// -- Fragment: after Ipv6, HopByHop, DestOpts, or Routing --
impl Within<Ipv6> for Fragment {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::FRAGMENT);
    }
}

impl Within<HopByHop> for Fragment {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::FRAGMENT);
    }
}

impl Within<DestOpts> for Fragment {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::FRAGMENT);
    }
}

impl Within<Routing> for Fragment {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::FRAGMENT);
    }
}

// -- Ipv4Auth: after Ipv4 only --
impl Within<Ipv4> for Ipv4Auth {
    fn conform(parent: &mut Ipv4) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

// -- Ipv6Auth: after Ipv6, HopByHop, DestOpts, Routing, or Fragment --
impl Within<Ipv6> for Ipv6Auth {
    fn conform(parent: &mut Ipv6) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

impl Within<HopByHop> for Ipv6Auth {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

impl Within<DestOpts> for Ipv6Auth {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

impl Within<Routing> for Ipv6Auth {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

impl Within<Fragment> for Ipv6Auth {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::AUTH);
    }
}

// -- Transport after extension headers --
// Tcp, Udp, Icmp6 can follow any IPv6 extension header.
// Icmp4 can follow Ipv4Auth (IPv4 context).

impl Within<HopByHop> for Tcp {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<DestOpts> for Tcp {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Routing> for Tcp {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Fragment> for Tcp {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv4Auth> for Tcp {
    fn conform(parent: &mut Ipv4Auth) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<Ipv6Auth> for Tcp {
    fn conform(parent: &mut Ipv6Auth) {
        parent.set_next_header(NextHeader::TCP);
    }
}

impl Within<HopByHop> for Udp {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<DestOpts> for Udp {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Routing> for Udp {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Fragment> for Udp {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv4Auth> for Udp {
    fn conform(parent: &mut Ipv4Auth) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv6Auth> for Udp {
    fn conform(parent: &mut Ipv6Auth) {
        parent.set_next_header(NextHeader::UDP);
    }
}

impl Within<Ipv4Auth> for Icmp4 {
    fn conform(parent: &mut Ipv4Auth) {
        parent.set_next_header(NextHeader::ICMP);
    }
}

impl Within<HopByHop> for Icmp6 {
    fn conform(parent: &mut HopByHop) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<DestOpts> for Icmp6 {
    fn conform(parent: &mut DestOpts) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<Routing> for Icmp6 {
    fn conform(parent: &mut Routing) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<Fragment> for Icmp6 {
    fn conform(parent: &mut Fragment) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

impl Within<Ipv6Auth> for Icmp6 {
    fn conform(parent: &mut Ipv6Auth) {
        parent.set_next_header(NextHeader::ICMP6);
    }
}

// Install impls -- how Headers absorbs each layer

impl Install<()> for Headers {
    fn install(&mut self, (): ()) {}
}

impl Install<Eth> for Headers {
    fn install(&mut self, eth: Eth) {
        self.set_eth(eth);
    }
}

impl Install<Vlan> for Headers {
    /// # Panics
    ///
    /// Panics if the VLAN stack is full (more than `MAX_VLANS` pushed).
    /// This is test-facing code; exceeding the limit is a programming error.
    fn install(&mut self, vlan: Vlan) {
        #[allow(clippy::expect_used)] // test code
        self.vlan
            .try_push(vlan)
            .expect("too many VLANs (exceeded MAX_VLANS)");
    }
}

impl Install<Ipv4> for Headers {
    fn install(&mut self, ip: Ipv4) {
        self.net = Some(Net::Ipv4(ip));
    }
}

impl Install<Ipv6> for Headers {
    fn install(&mut self, ip: Ipv6) {
        self.net = Some(Net::Ipv6(ip));
    }
}

impl Install<Tcp> for Headers {
    fn install(&mut self, tcp: Tcp) {
        self.set_transport(Some(Transport::Tcp(tcp)));
    }
}

impl Install<Udp> for Headers {
    fn install(&mut self, udp: Udp) {
        self.set_transport(Some(Transport::Udp(udp)));
    }
}

impl Install<Icmp4> for Headers {
    fn install(&mut self, icmp: Icmp4) {
        self.set_transport(Some(Transport::Icmp4(icmp)));
    }
}

impl Install<Icmp6> for Headers {
    fn install(&mut self, icmp: Icmp6) {
        self.set_transport(Some(Transport::Icmp6(icmp)));
    }
}

impl Install<Vxlan> for Headers {
    fn install(&mut self, vxlan: Vxlan) {
        self.udp_encap = Some(UdpEncap::Vxlan(vxlan));
    }
}

impl Install<HopByHop> for Headers {
    /// # Panics
    ///
    /// Panics if the extension header stack is full.
    fn install(&mut self, hbh: HopByHop) {
        #[allow(clippy::expect_used)]
        self.net_ext
            .try_push(NetExt::HopByHop(hbh))
            .expect("too many extension headers (exceeded MAX_NET_EXTENSIONS)");
    }
}

impl Install<DestOpts> for Headers {
    /// # Panics
    ///
    /// Panics if the extension header stack is full.
    fn install(&mut self, d: DestOpts) {
        #[allow(clippy::expect_used)]
        self.net_ext
            .try_push(NetExt::DestOpts(d))
            .expect("too many extension headers (exceeded MAX_NET_EXTENSIONS)");
    }
}

impl Install<Routing> for Headers {
    /// # Panics
    ///
    /// Panics if the extension header stack is full.
    fn install(&mut self, r: Routing) {
        #[allow(clippy::expect_used)]
        self.net_ext
            .try_push(NetExt::Routing(r))
            .expect("too many extension headers (exceeded MAX_NET_EXTENSIONS)");
    }
}

impl Install<Fragment> for Headers {
    /// # Panics
    ///
    /// Panics if the extension header stack is full.
    fn install(&mut self, f: Fragment) {
        #[allow(clippy::expect_used)]
        self.net_ext
            .try_push(NetExt::Fragment(f))
            .expect("too many extension headers (exceeded MAX_NET_EXTENSIONS)");
    }
}

impl Install<Ipv4Auth> for Headers {
    /// # Panics
    ///
    /// Panics if the extension header stack is full.
    fn install(&mut self, a: Ipv4Auth) {
        #[allow(clippy::expect_used)]
        self.net_ext
            .try_push(NetExt::Ipv4Auth(a))
            .expect("too many extension headers (exceeded MAX_NET_EXTENSIONS)");
    }
}

impl Install<Ipv6Auth> for Headers {
    /// # Panics
    ///
    /// Panics if the extension header stack is full.
    fn install(&mut self, a: Ipv6Auth) {
        #[allow(clippy::expect_used)]
        self.net_ext
            .try_push(NetExt::Ipv6Auth(a))
            .expect("too many extension headers (exceeded MAX_NET_EXTENSIONS)");
    }
}

impl Blank for () {
    fn blank() -> Self {}
}

impl Blank for Eth {
    fn blank() -> Self {
        // Locally-administered unicast MACs -- won't collide with real hardware.
        #[allow(clippy::unwrap_used)]
        let src = SourceMac::new(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])).unwrap();
        #[allow(clippy::unwrap_used)]
        let dst = DestinationMac::new(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])).unwrap();
        Eth::new(src, dst, EthType::IPV4)
    }
}

impl Blank for Vlan {
    fn blank() -> Self {
        Vlan::new(Vid::MIN, EthType::IPV4, Pcp::MIN, false)
    }
}

impl Blank for Ipv4 {
    fn blank() -> Self {
        Ipv4::default()
    }
}

impl Blank for Ipv6 {
    fn blank() -> Self {
        Ipv6::default()
    }
}

impl Blank for Tcp {
    fn blank() -> Self {
        #[allow(clippy::unwrap_used)] // port 1 is always valid
        Tcp::new(
            TcpPort::new_checked(1).unwrap(),
            TcpPort::new_checked(1).unwrap(),
        )
    }
}

impl Blank for Udp {
    fn blank() -> Self {
        #[allow(clippy::unwrap_used)] // port 1 is always valid
        Udp::new(
            UdpPort::new_checked(1).unwrap(),
            UdpPort::new_checked(1).unwrap(),
        )
    }
}

impl Blank for Icmp4 {
    fn blank() -> Self {
        Icmp4::with_type(crate::icmp4::Icmp4Type::EchoRequest(
            Icmp4EchoRequest::blank(),
        ))
    }
}

impl Blank for Icmp6 {
    fn blank() -> Self {
        Icmp6::with_type(crate::icmp6::Icmp6Type::EchoRequest(
            Icmp6EchoRequest::blank(),
        ))
    }
}

impl Blank for Vxlan {
    fn blank() -> Self {
        #[allow(clippy::unwrap_used)] // VNI 1 is always valid
        Vxlan::new(Vni::new_checked(1).unwrap())
    }
}

impl Blank for HopByHop {
    fn blank() -> Self {
        use etherparse::Ipv6RawExtHeader;
        // Minimum valid payload: 6 zero bytes (8-byte aligned with the 2-byte header prefix).
        #[allow(clippy::unwrap_used, unsafe_code)]
        // SAFETY: we are constructing this as a HopByHop by definition.
        unsafe {
            HopByHop::from_raw_unchecked(Box::new(
                Ipv6RawExtHeader::new_raw(IpNumber::TCP, &[0; 6]).unwrap(),
            ))
        }
    }
}

impl Blank for DestOpts {
    fn blank() -> Self {
        use etherparse::Ipv6RawExtHeader;
        #[allow(clippy::unwrap_used, unsafe_code)]
        // SAFETY: we are constructing this as a DestOpts by definition.
        unsafe {
            DestOpts::from_raw_unchecked(Box::new(
                Ipv6RawExtHeader::new_raw(IpNumber::TCP, &[0; 6]).unwrap(),
            ))
        }
    }
}

impl Blank for Routing {
    fn blank() -> Self {
        use etherparse::Ipv6RawExtHeader;
        #[allow(clippy::unwrap_used, unsafe_code)]
        // SAFETY: we are constructing this as a Routing by definition.
        unsafe {
            Routing::from_raw_unchecked(Box::new(
                Ipv6RawExtHeader::new_raw(IpNumber::TCP, &[0; 6]).unwrap(),
            ))
        }
    }
}

impl Blank for Fragment {
    fn blank() -> Self {
        use etherparse::{IpFragOffset, Ipv6FragmentHeader};
        #[allow(unsafe_code)]
        // SAFETY: we are constructing this as a Fragment by definition.
        unsafe {
            Fragment::from_raw_unchecked(Ipv6FragmentHeader::new(
                IpNumber::TCP,
                IpFragOffset::ZERO,
                false,
                0,
            ))
        }
    }
}

impl Blank for Ipv4Auth {
    fn blank() -> Self {
        use crate::ip_auth::IpAuth;
        // Default IpAuthHeader has zero-length ICV -- the minimum valid AH.
        Ipv4Auth::new(IpAuth::from_inner(Box::default()))
    }
}

impl Blank for Ipv6Auth {
    fn blank() -> Self {
        use crate::ip_auth::IpAuth;
        Ipv6Auth::new(IpAuth::from_inner(Box::default()))
    }
}

// ---------------------------------------------------------------------------
// ICMP subtype newtypes
// ---------------------------------------------------------------------------
//
// Each newtype wraps the etherparse inner header/code for one ICMP message
// type.  They participate in the builder chain via `Within<Icmp4>` (or
// `Icmp6`) and `Install` -- conform sets the variant on the parent ICMP
// header, then install patches the inner value into the already-stored
// transport slot.
//
// Error subtypes enable `.embedded()` / `.embed_*()` for attaching the
// offending original packet.  Query subtypes (echo) are terminal.

use crate::icmp4::{
    Icmp4DestUnreachable, Icmp4EchoReply, Icmp4EchoRequest, Icmp4ParamProblem, Icmp4Redirect,
    Icmp4RedirectCode, Icmp4TimeExceeded,
};
use crate::icmp6::{
    Icmp6DestUnreachable, Icmp6EchoReply, Icmp6EchoRequest, Icmp6PacketTooBig, Icmp6ParamProblem,
    Icmp6ParamProblemCode, Icmp6TimeExceeded,
};

// -- Within impls: ICMP subtypes after Icmp4 / Icmp6 ------------------------

macro_rules! within_icmp4_subtype {
    ($subtype:ty, $to_icmp4_type:expr) => {
        impl Within<Icmp4> for $subtype {
            fn conform(parent: &mut Icmp4) {
                parent.set_type($to_icmp4_type(<$subtype>::blank()));
            }
        }
    };
}

within_icmp4_subtype!(
    Icmp4DestUnreachable,
    crate::icmp4::Icmp4Type::DestUnreachable
);
within_icmp4_subtype!(Icmp4Redirect, crate::icmp4::Icmp4Type::Redirect);
within_icmp4_subtype!(Icmp4TimeExceeded, crate::icmp4::Icmp4Type::TimeExceeded);
within_icmp4_subtype!(Icmp4ParamProblem, crate::icmp4::Icmp4Type::ParamProblem);
within_icmp4_subtype!(Icmp4EchoRequest, crate::icmp4::Icmp4Type::EchoRequest);
within_icmp4_subtype!(Icmp4EchoReply, crate::icmp4::Icmp4Type::EchoReply);

macro_rules! within_icmp6_subtype {
    ($subtype:ty, $to_icmp6_type:expr) => {
        impl Within<Icmp6> for $subtype {
            fn conform(parent: &mut Icmp6) {
                parent.set_type($to_icmp6_type(<$subtype>::blank()));
            }
        }
    };
}

within_icmp6_subtype!(
    Icmp6DestUnreachable,
    crate::icmp6::Icmp6Type::DestUnreachable
);
within_icmp6_subtype!(Icmp6PacketTooBig, crate::icmp6::Icmp6Type::PacketTooBig);
within_icmp6_subtype!(Icmp6TimeExceeded, crate::icmp6::Icmp6Type::TimeExceeded);
within_icmp6_subtype!(Icmp6ParamProblem, crate::icmp6::Icmp6Type::ParamProblem);
within_icmp6_subtype!(Icmp6EchoRequest, crate::icmp6::Icmp6Type::EchoRequest);
within_icmp6_subtype!(Icmp6EchoReply, crate::icmp6::Icmp6Type::EchoReply);

// -- Install impls: set the ICMP type on the already-stored transport --------

macro_rules! install_icmp4_subtype {
    ($subtype:ty, $to_icmp4_type:expr) => {
        impl Install<$subtype> for Headers {
            fn install(&mut self, value: $subtype) {
                match &mut self.transport {
                    Some(Transport::Icmp4(icmp)) => {
                        icmp.set_type($to_icmp4_type(value));
                    }
                    _ => unreachable!("conform should have installed Icmp4 transport"),
                }
            }
        }
    };
}

install_icmp4_subtype!(
    Icmp4DestUnreachable,
    crate::icmp4::Icmp4Type::DestUnreachable
);
install_icmp4_subtype!(Icmp4Redirect, crate::icmp4::Icmp4Type::Redirect);
install_icmp4_subtype!(Icmp4TimeExceeded, crate::icmp4::Icmp4Type::TimeExceeded);
install_icmp4_subtype!(Icmp4ParamProblem, crate::icmp4::Icmp4Type::ParamProblem);
install_icmp4_subtype!(Icmp4EchoRequest, crate::icmp4::Icmp4Type::EchoRequest);
install_icmp4_subtype!(Icmp4EchoReply, crate::icmp4::Icmp4Type::EchoReply);

macro_rules! install_icmp6_subtype {
    ($subtype:ty, $to_icmp6_type:expr) => {
        impl Install<$subtype> for Headers {
            fn install(&mut self, value: $subtype) {
                match &mut self.transport {
                    Some(Transport::Icmp6(icmp)) => {
                        icmp.set_type($to_icmp6_type(value));
                    }
                    _ => unreachable!("conform should have installed Icmp6 transport"),
                }
            }
        }
    };
}

install_icmp6_subtype!(
    Icmp6DestUnreachable,
    crate::icmp6::Icmp6Type::DestUnreachable
);
install_icmp6_subtype!(Icmp6PacketTooBig, crate::icmp6::Icmp6Type::PacketTooBig);
install_icmp6_subtype!(Icmp6TimeExceeded, crate::icmp6::Icmp6Type::TimeExceeded);
install_icmp6_subtype!(Icmp6ParamProblem, crate::icmp6::Icmp6Type::ParamProblem);
install_icmp6_subtype!(Icmp6EchoRequest, crate::icmp6::Icmp6Type::EchoRequest);
install_icmp6_subtype!(Icmp6EchoReply, crate::icmp6::Icmp6Type::EchoReply);

// -- Blank impls -------------------------------------------------------------

impl Blank for Icmp4DestUnreachable {
    fn blank() -> Self {
        Self::Network
    }
}

impl Blank for Icmp4Redirect {
    fn blank() -> Self {
        #[allow(clippy::unwrap_used)] // 10.0.0.1 is always unicast
        Self::new(
            Icmp4RedirectCode::Network,
            crate::ipv4::UnicastIpv4Addr::new(std::net::Ipv4Addr::new(10, 0, 0, 1)).unwrap(),
        )
    }
}

impl Blank for Icmp4TimeExceeded {
    fn blank() -> Self {
        Self::TtlExceeded
    }
}

impl Blank for Icmp4ParamProblem {
    fn blank() -> Self {
        Self::PointerIndicatesError(0)
    }
}

impl Blank for Icmp4EchoRequest {
    fn blank() -> Self {
        Self { id: 0, seq: 0 }
    }
}

impl Blank for Icmp4EchoReply {
    fn blank() -> Self {
        Self { id: 0, seq: 0 }
    }
}

impl Blank for Icmp6DestUnreachable {
    fn blank() -> Self {
        Self::NoRoute
    }
}

impl Blank for Icmp6PacketTooBig {
    fn blank() -> Self {
        Self::new(1280).unwrap_or_else(|_| unreachable!())
    }
}

impl Blank for Icmp6TimeExceeded {
    fn blank() -> Self {
        Self::HopLimitExceeded
    }
}

impl Blank for Icmp6ParamProblem {
    fn blank() -> Self {
        Self {
            code: Icmp6ParamProblemCode::ErroneousHeaderField,
            pointer: 0,
        }
    }
}

impl Blank for Icmp6EchoRequest {
    fn blank() -> Self {
        Self { id: 0, seq: 0 }
    }
}

impl Blank for Icmp6EchoReply {
    fn blank() -> Self {
        Self { id: 0, seq: 0 }
    }
}

// -- Embedded ICMP headers (HeaderStack) -------------------------------------
//
// `.embedded()` is only available on error subtype layers, not on bare
// `Icmp4` / `Icmp6`.

macro_rules! impl_embedded {
    ($subtype:ty) => {
        impl HeaderStack<$subtype> {
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

// ICMPv4 error subtypes
impl_embedded!(Icmp4DestUnreachable);
impl_embedded!(Icmp4Redirect);
impl_embedded!(Icmp4TimeExceeded);
impl_embedded!(Icmp4ParamProblem);

// ICMPv6 error subtypes
impl_embedded!(Icmp6DestUnreachable);
impl_embedded!(Icmp6PacketTooBig);
impl_embedded!(Icmp6TimeExceeded);
impl_embedded!(Icmp6ParamProblem);

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

    let net_ext_size: u16 = headers.net_ext.iter().map(|e| e.size().get()).sum();

    // Transport payload (used for UDP length -- excludes extension headers
    // since they sit between IP and transport, not inside UDP).
    let base_payload = transport_size
        .checked_add(payload_u16)
        .and_then(|v| v.checked_add(encap_size))
        .and_then(|v| v.checked_add(embedded_size))
        .ok_or(BuildError::PayloadTooLarge)?;

    // IP payload includes extension headers + transport payload.
    let ip_payload = base_payload
        .checked_add(net_ext_size)
        .ok_or(BuildError::PayloadTooLarge)?;

    match headers.transport {
        Some(Transport::Udp(ref mut udp)) => {
            // SAFETY: `transport_size >= Udp::MIN_LENGTH` when transport is UDP, so
            // `base_payload` is guaranteed non-zero.
            let udp_len = NonZero::new(base_payload).unwrap_or_else(|| unreachable!());
            #[allow(unsafe_code)]
            // SAFETY: `udp_len >= Udp::MIN_LENGTH` by construction.
            unsafe {
                udp.set_length(udp_len);
            }
        }
        // No length field in these headers to adjust.
        Some(Transport::Tcp(_) | Transport::Icmp4(_) | Transport::Icmp6(_)) | None => {}
    }

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

// ---------------------------------------------------------------------------
// Fuzz header-stack generator (bolero integration)
// ---------------------------------------------------------------------------

/// Fuzz-driven header stacking for property-based tests.
///
/// [`FuzzLayer`] chains implement [`ValueGenerator`](bolero::ValueGenerator),
/// producing [`Headers`] by using [`TypeGenerator`](bolero::TypeGenerator) to
/// create each layer, then applying caller-supplied mutation closures to pin
/// specific field values.
///
/// # Design
///
/// Where [`HeaderStack`] eagerly builds headers using [`Blank`] values,
/// a fuzz chain stores a *recipe* -- a chain of
/// `(TypeGenerator::generate, mutation)` pairs -- and replays it each time
/// the fuzzer calls [`ValueGenerator::generate`](bolero::ValueGenerator::generate).
///
/// The chain is encoded in nested generics ([`ChainBase`] -> [`FuzzLayer`] -> ...),
/// so all closure types are monomorphised and the hot path is zero-overhead.
///
/// # Examples
///
/// ```ignore
/// use net::headers::builder::*;
///
/// // All TCP packets with dst port 80, everything else fuzzed.
/// bolero::check!()
///     .with_generator(
///         ChainBase::new()
///             .eth(|_| {})
///             .ipv4(|_| {})
///             .tcp(|tcp| {
///                 tcp.set_destination(TcpPort::new_checked(80).unwrap());
///             }),
///     )
///     .for_each(|headers: &Headers| {
///         // `headers` has fuzzed values everywhere except dst port.
///     });
/// ```
#[cfg(any(test, feature = "bolero"))]
mod fuzz {
    use std::marker::PhantomData;

    use bolero::{Driver, TypeGenerator, ValueGenerator};

    use super::{BuildError, Headers, Install, Within, fixup_lengths};

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::ChainBase {}
        impl<Inner, Layer, Mutation> Sealed for super::FuzzLayer<Inner, Layer, Mutation> {}
    }

    /// Recursive generation of the fuzz header chain.
    ///
    /// Each link generates all preceding layers, installs them into
    /// [`Headers`], and returns the not-yet-installed top layer so the
    /// next link can [`conform`](Within::conform) and install it.
    ///
    /// This trait is sealed --
    /// only [`ChainBase`], [`FuzzLayer`],
    /// [`FuzzEmbeddedNet`], and [`FuzzEmbeddedFull`] implement it.
    pub trait GenerateChain: sealed::Sealed {
        /// The header type sitting at the top of the stack (not yet installed).
        type Top;

        /// Generate all layers up to and including the top.
        fn generate_chain<D: Driver>(&self, driver: &mut D) -> Option<(Headers, Self::Top)>;
    }

    /// Convenience entry point for fuzz header generation.
    ///
    /// Equivalent to [`ChainBase::new()`] -- returns a fresh chain ready
    /// for `.eth(...)`, `.ipv4(...)`, etc.
    #[must_use]
    pub fn header_chain() -> ChainBase {
        ChainBase::new()
    }

    /// Base of a fuzz header stack - no layers yet.
    ///
    /// Start here, then chain layer methods (`.eth(...)`, `.ipv4(...)`, ...).
    /// The resulting chain implements [`ValueGenerator`] directly.
    #[derive(Default)]
    #[non_exhaustive]
    pub struct ChainBase;

    impl ChainBase {
        /// Create a new, empty fuzz header stack.
        #[must_use]
        pub const fn new() -> Self {
            Self
        }

        /// Push a layer onto the stack.
        ///
        /// The layer type `U` is created via [`TypeGenerator::generate`] at
        /// generation time, then `mutate` is applied to pin specific fields.
        pub fn stack<U, N>(self, mutate: N) -> FuzzLayer<Self, U, N>
        where
            U: TypeGenerator + Within<()>,
            N: Fn(&mut U),
        {
            FuzzLayer {
                inner: self,
                mutate,
                _layer: PhantomData,
            }
        }

        /// Push an `Eth` layer.
        pub fn eth(
            self,
            f: impl Fn(&mut crate::eth::Eth),
        ) -> FuzzLayer<Self, crate::eth::Eth, impl Fn(&mut crate::eth::Eth)> {
            self.stack(f)
        }
    }

    impl GenerateChain for ChainBase {
        type Top = ();

        fn generate_chain<D: Driver>(&self, _driver: &mut D) -> Option<(Headers, ())> {
            Some((Headers::default(), ()))
        }
    }

    /// One layer in a fuzz header stack recipe.
    ///
    /// - `Inner` -- the preceding chain ([`ChainBase`] or another `FuzzLayer`).
    /// - `Layer` -- the header type at this position.
    /// - `Mutation` -- the mutation closure that pins field values after
    ///   [`TypeGenerator`] produces a fuzzed instance.
    pub struct FuzzLayer<Inner, Layer, Mutation> {
        inner: Inner,
        mutate: Mutation,
        _layer: PhantomData<Layer>,
    }

    impl<Inner, Layer, Mutation> GenerateChain for FuzzLayer<Inner, Layer, Mutation>
    where
        Inner: GenerateChain,
        Layer: TypeGenerator + Within<Inner::Top>,
        Mutation: Fn(&mut Layer),
        Headers: Install<Inner::Top>,
    {
        type Top = Layer;

        fn generate_chain<D: Driver>(&self, driver: &mut D) -> Option<(Headers, Layer)> {
            let (mut headers, mut prev) = self.inner.generate_chain(driver)?;
            Layer::conform(&mut prev);
            headers.install(prev);
            let mut layer = Layer::generate(driver)?;
            (self.mutate)(&mut layer);
            Some((headers, layer))
        }
    }

    /// Helper macro to generate named layer methods on [`FuzzLayer`].
    ///
    /// Each method delegates to [`FuzzLayer::stack`] with the concrete
    /// header type, mirroring the named methods on [`super::HeaderStack`].
    macro_rules! fuzz_layer_method {
        ($(#[$meta:meta])* $method:ident, $header:ty) => {
            $(#[$meta])*
            pub fn $method(
                self,
                f: impl Fn(&mut $header),
            ) -> FuzzLayer<Self, $header, impl Fn(&mut $header)>
            where
                $header: TypeGenerator + Within<Layer>,
            {
                self.stack(f)
            }
        };
    }

    impl<Inner, Layer, Mutation> FuzzLayer<Inner, Layer, Mutation>
    where
        Inner: GenerateChain,
        Layer: TypeGenerator + Within<Inner::Top>,
        Mutation: Fn(&mut Layer),
        Headers: Install<Inner::Top> + Install<Layer>,
    {
        /// Push a new layer onto the stack.
        ///
        /// At generation time, the layer is created via
        /// [`TypeGenerator::generate`], then `mutate` is applied.
        pub fn stack<U, N>(self, mutate: N) -> FuzzLayer<Self, U, N>
        where
            U: TypeGenerator + Within<Layer>,
            N: Fn(&mut U),
        {
            FuzzLayer {
                inner: self,
                mutate,
                _layer: PhantomData,
            }
        }

        fuzz_layer_method!(
            /// Push an `Eth` layer.
            eth,
            crate::eth::Eth
        );
        fuzz_layer_method!(
            /// Push a `Vlan` layer.
            vlan,
            crate::vlan::Vlan
        );
        fuzz_layer_method!(
            /// Push an `Ipv4` layer.
            ipv4,
            crate::ipv4::Ipv4
        );
        fuzz_layer_method!(
            /// Push an `Ipv6` layer.
            ipv6,
            crate::ipv6::Ipv6
        );
        fuzz_layer_method!(
            /// Push a `Tcp` layer.
            tcp,
            crate::tcp::Tcp
        );
        fuzz_layer_method!(
            /// Push a `Udp` layer.
            udp,
            crate::udp::Udp
        );
        fuzz_layer_method!(
            /// Push an `Icmp4` layer.
            icmp4,
            crate::icmp4::Icmp4
        );
        fuzz_layer_method!(
            /// Push an `Icmp6` layer.
            icmp6,
            crate::icmp6::Icmp6
        );
        fuzz_layer_method!(
            /// Push a `Vxlan` layer.
            vxlan,
            crate::vxlan::Vxlan
        );

        // IPv6 extension header layers
        fuzz_layer_method!(
            /// Push a `HopByHop` extension header.
            hop_by_hop,
            crate::ipv6::HopByHop
        );
        fuzz_layer_method!(
            /// Push a `DestOpts` extension header.
            dest_opts,
            crate::ipv6::DestOpts
        );
        fuzz_layer_method!(
            /// Push a `Routing` extension header.
            routing,
            crate::ipv6::Routing
        );
        fuzz_layer_method!(
            /// Push a `Fragment` extension header.
            fragment,
            crate::ipv6::Fragment
        );
        fuzz_layer_method!(
            /// Push an `Ipv4Auth` extension header.
            ipv4_auth,
            crate::ip_auth::Ipv4Auth
        );
        fuzz_layer_method!(
            /// Push an `Ipv6Auth` extension header.
            ipv6_auth,
            crate::ip_auth::Ipv6Auth
        );

        // ICMPv4 subtype layers
        fuzz_layer_method!(
            /// Specialize as `ICMPv4` Destination Unreachable.
            dest_unreachable, super::Icmp4DestUnreachable
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv4` Redirect.
            redirect, super::Icmp4Redirect
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv4` Time Exceeded.
            time_exceeded, super::Icmp4TimeExceeded
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv4` Parameter Problem.
            param_problem, super::Icmp4ParamProblem
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv4` Echo Request.
            echo_request, super::Icmp4EchoRequest
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv4` Echo Reply.
            echo_reply, super::Icmp4EchoReply
        );

        // ICMPv6 subtype layers
        fuzz_layer_method!(
            /// Specialize as `ICMPv6` Destination Unreachable.
            dest_unreachable6, super::Icmp6DestUnreachable
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv6` Packet Too Big.
            packet_too_big6, super::Icmp6PacketTooBig
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv6` Time Exceeded.
            time_exceeded6, super::Icmp6TimeExceeded
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv6` Parameter Problem.
            param_problem6, super::Icmp6ParamProblem
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv6` Echo Request.
            echo_request6, super::Icmp6EchoRequest
        );
        fuzz_layer_method!(
            /// Specialize as `ICMPv6` Echo Reply.
            echo_reply6, super::Icmp6EchoReply
        );
    }

    // -- ValueGenerator impls ------------------------------------------------
    //
    // Any fuzz chain can be passed directly to `bolero::check!().with_generator(...)`
    // without an intermediate wrapper -- no `.finish()` needed.

    impl<Inner, Layer, Mutation> ValueGenerator for FuzzLayer<Inner, Layer, Mutation>
    where
        Inner: GenerateChain,
        Layer: TypeGenerator + Within<Inner::Top>,
        Mutation: Fn(&mut Layer),
        Headers: Install<Inner::Top> + Install<Layer>,
    {
        type Output = Headers;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let (mut headers, top) = self.generate_chain(driver)?;
            headers.install(top);
            // Discard packets whose lengths overflow u16 -- the fuzzer will
            // try again with different inputs.
            fixup_lengths(&mut headers, &[]).ok()?;
            Some(headers)
        }
    }

    impl<Inner, Layer, Mutation> FuzzLayer<Inner, Layer, Mutation>
    where
        Inner: GenerateChain,
        Layer: TypeGenerator + Within<Inner::Top>,
        Mutation: Fn(&mut Layer),
        Headers: Install<Inner::Top> + Install<Layer>,
    {
        /// Generate headers with an explicit payload for length computation.
        ///
        /// Unlike the [`ValueGenerator`] impl (which silently discards
        /// packets whose lengths overflow `u16`), this method propagates
        /// length errors as `Some(Err(...))`, returning `None` only when
        /// the driver cannot produce enough bytes.
        #[must_use]
        pub fn generate_with_payload<D: Driver>(
            &self,
            driver: &mut D,
            payload: &[u8],
        ) -> Option<Result<Headers, BuildError>> {
            let (mut headers, top) = self.generate_chain(driver)?;
            headers.install(top);
            Some(fixup_lengths(&mut headers, payload).map(|()| headers))
        }
    }

    // -----------------------------------------------------------------------
    // Fuzz: ICMP subtypes and embedded header generation
    // -----------------------------------------------------------------------

    use super::{
        EmbeddedTransport, Icmp4DestUnreachable, Icmp4EchoReply, Icmp4EchoRequest,
        Icmp4ParamProblem, Icmp4Redirect, Icmp4RedirectCode, Icmp4TimeExceeded,
        Icmp6DestUnreachable, Icmp6EchoReply, Icmp6EchoRequest, Icmp6PacketTooBig,
        Icmp6ParamProblem, Icmp6ParamProblemCode, Icmp6TimeExceeded, fixup_embedded,
    };
    use crate::headers::Net;
    use crate::icmp4::{Icmp4, TruncatedIcmp4};
    use crate::icmp6::{Icmp6, TruncatedIcmp6};
    use crate::ipv4::Ipv4;
    use crate::ipv6::Ipv6;
    use crate::tcp::{Tcp, TruncatedTcp};
    use crate::udp::{TruncatedUdp, Udp};

    // -- TypeGenerator impls for ICMP subtypes --------------------------------

    fn pick<D: Driver, const N: usize, T: Copy>(driver: &mut D, items: [T; N]) -> Option<T> {
        let idx = driver.gen_usize(std::ops::Bound::Included(&0), std::ops::Bound::Excluded(&N))?;
        Some(items[idx])
    }

    impl TypeGenerator for Icmp4DestUnreachable {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let variant: u8 =
                driver.gen_u8(std::ops::Bound::Included(&0), std::ops::Bound::Included(&5))?;
            Some(match variant {
                0 => Self::Network,
                1 => Self::Host,
                2 => Self::Protocol,
                3 => Self::Port,
                4 => Self::FragmentationNeeded {
                    next_hop_mtu: std::num::NonZero::new(
                        driver
                            .gen_u16(std::ops::Bound::Included(&68), std::ops::Bound::Unbounded)?,
                    ),
                },
                _ => Self::SourceRouteFailed,
            })
        }
    }

    impl TypeGenerator for Icmp4Redirect {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let code = pick(
                driver,
                [
                    Icmp4RedirectCode::Network,
                    Icmp4RedirectCode::Host,
                    Icmp4RedirectCode::TosNetwork,
                    Icmp4RedirectCode::TosHost,
                ],
            )?;
            let gateway: crate::ipv4::UnicastIpv4Addr = driver.produce()?;
            Some(Self::new(code, gateway))
        }
    }

    impl TypeGenerator for Icmp4TimeExceeded {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            pick(driver, [Self::TtlExceeded, Self::FragmentReassembly])
        }
    }

    impl TypeGenerator for Icmp4ParamProblem {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let variant: u8 =
                driver.gen_u8(std::ops::Bound::Included(&0), std::ops::Bound::Included(&2))?;
            Some(match variant {
                0 => Self::PointerIndicatesError(driver.produce()?),
                1 => Self::MissingRequiredOption,
                _ => Self::BadLength,
            })
        }
    }

    impl TypeGenerator for Icmp4EchoRequest {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                id: driver.produce()?,
                seq: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Icmp4EchoReply {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                id: driver.produce()?,
                seq: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Icmp6DestUnreachable {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            pick(
                driver,
                [
                    Self::NoRoute,
                    Self::Prohibited,
                    Self::BeyondScope,
                    Self::Address,
                    Self::Port,
                    Self::SourceAddressFailedPolicy,
                    Self::RejectRoute,
                ],
            )
        }
    }

    impl TypeGenerator for Icmp6PacketTooBig {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let mtu =
                driver.gen_u32(std::ops::Bound::Included(&1280), std::ops::Bound::Unbounded)?;
            Some(Self::new(mtu).unwrap_or_else(|_| unreachable!()))
        }
    }

    impl TypeGenerator for Icmp6TimeExceeded {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            pick(driver, [Self::HopLimitExceeded, Self::FragmentReassembly])
        }
    }

    impl TypeGenerator for Icmp6ParamProblem {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let code = pick(
                driver,
                [
                    Icmp6ParamProblemCode::ErroneousHeaderField,
                    Icmp6ParamProblemCode::UnrecognizedNextHeader,
                    Icmp6ParamProblemCode::UnrecognizedIpv6Option,
                ],
            )?;
            Some(Self {
                code,
                pointer: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Icmp6EchoRequest {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                id: driver.produce()?,
                seq: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Icmp6EchoReply {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                id: driver.produce()?,
                seq: driver.produce()?,
            })
        }
    }

    // -----------------------------------------------------------------------
    // Embedded ICMP header generation (flattened into the main chain)
    // -----------------------------------------------------------------------

    /// Helper to generate a net layer via [`TypeGenerator`], apply the
    /// mutation, and wrap in [`Net`].
    trait GenerateNet: TypeGenerator {
        fn generate_and_wrap<D: Driver>(driver: &mut D, mutate: &impl Fn(&mut Self))
        -> Option<Net>;
    }

    impl GenerateNet for Ipv4 {
        fn generate_and_wrap<D: Driver>(
            driver: &mut D,
            mutate: &impl Fn(&mut Self),
        ) -> Option<Net> {
            let mut ip = Ipv4::generate(driver)?;
            mutate(&mut ip);
            Some(Net::Ipv4(ip))
        }
    }

    impl GenerateNet for Ipv6 {
        fn generate_and_wrap<D: Driver>(
            driver: &mut D,
            mutate: &impl Fn(&mut Self),
        ) -> Option<Net> {
            let mut ip = Ipv6::generate(driver)?;
            mutate(&mut ip);
            Some(Net::Ipv6(ip))
        }
    }

    /// Helper to generate a transport layer via [`TypeGenerator`], apply the
    /// mutation, and wrap in [`EmbeddedTransport`].
    trait GenerateEmbeddedTransport: TypeGenerator {
        fn generate_and_wrap<D: Driver>(
            driver: &mut D,
            mutate: &impl Fn(&mut Self),
        ) -> Option<EmbeddedTransport>;
    }

    impl GenerateEmbeddedTransport for Tcp {
        fn generate_and_wrap<D: Driver>(
            driver: &mut D,
            mutate: &impl Fn(&mut Self),
        ) -> Option<EmbeddedTransport> {
            let mut tcp = Tcp::generate(driver)?;
            mutate(&mut tcp);
            Some(EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(tcp)))
        }
    }

    impl GenerateEmbeddedTransport for Udp {
        fn generate_and_wrap<D: Driver>(
            driver: &mut D,
            mutate: &impl Fn(&mut Self),
        ) -> Option<EmbeddedTransport> {
            let mut udp = Udp::generate(driver)?;
            mutate(&mut udp);
            Some(EmbeddedTransport::Udp(TruncatedUdp::FullHeader(udp)))
        }
    }

    impl GenerateEmbeddedTransport for Icmp4 {
        fn generate_and_wrap<D: Driver>(
            driver: &mut D,
            mutate: &impl Fn(&mut Self),
        ) -> Option<EmbeddedTransport> {
            let mut icmp = Icmp4::generate(driver)?;
            mutate(&mut icmp);
            Some(EmbeddedTransport::Icmp4(TruncatedIcmp4::FullHeader(icmp)))
        }
    }

    impl GenerateEmbeddedTransport for Icmp6 {
        fn generate_and_wrap<D: Driver>(
            driver: &mut D,
            mutate: &impl Fn(&mut Self),
        ) -> Option<EmbeddedTransport> {
            let mut icmp = Icmp6::generate(driver)?;
            mutate(&mut icmp);
            Some(EmbeddedTransport::Icmp6(TruncatedIcmp6::FullHeader(icmp)))
        }
    }

    // -- FuzzEmbeddedNet: ICMP layer + embedded net, no transport ------------

    /// An ICMP fuzz layer with an embedded network header but no transport.
    ///
    /// Obtained by calling `.embed_ipv4(...)` or `.embed_ipv6(...)` on a
    /// an ICMP error subtype layer (e.g. `Icmp4DestUnreachable`).
    ///
    /// Chain `.embed_tcp(...)`, `.embed_udp(...)`, etc. to add an embedded
    /// transport, or use directly as a [`ValueGenerator`] (net-only
    /// embedded headers).
    pub struct FuzzEmbeddedNet<S, N, NM> {
        layer: S,
        net_mutate: NM,
        _net: PhantomData<N>,
    }

    impl<S, N, NM> sealed::Sealed for FuzzEmbeddedNet<S, N, NM> {}

    impl<S, N, NM> GenerateChain for FuzzEmbeddedNet<S, N, NM>
    where
        S: GenerateChain,
        N: GenerateNet,
        NM: Fn(&mut N),
    {
        type Top = S::Top;

        fn generate_chain<D: Driver>(&self, driver: &mut D) -> Option<(Headers, Self::Top)> {
            let (mut headers, top) = self.layer.generate_chain(driver)?;
            let net = N::generate_and_wrap(driver, &self.net_mutate)?;
            headers.embedded_ip = Some(fixup_embedded(Some(net), None));
            Some((headers, top))
        }
    }

    impl<S, N, NM> ValueGenerator for FuzzEmbeddedNet<S, N, NM>
    where
        S: GenerateChain,
        N: GenerateNet,
        NM: Fn(&mut N),
        Headers: Install<S::Top>,
    {
        type Output = Headers;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let (mut headers, top) = self.generate_chain(driver)?;
            headers.install(top);
            fixup_lengths(&mut headers, &[]).ok()?;
            Some(headers)
        }
    }

    macro_rules! fuzz_embedded_transport_method {
        ($(#[$meta:meta])* $method:ident, $transport:ty) => {
            $(#[$meta])*
            pub fn $method(
                self,
                f: impl Fn(&mut $transport),
            ) -> FuzzEmbeddedFull<S, N, NM, $transport, impl Fn(&mut $transport)> {
                FuzzEmbeddedFull {
                    layer: self.layer,
                    net_mutate: self.net_mutate,
                    transport_mutate: f,
                    _net: PhantomData,
                    _transport: PhantomData,
                }
            }
        };
    }

    impl<S, N, NM> FuzzEmbeddedNet<S, N, NM> {
        fuzz_embedded_transport_method!(
            /// Add a fuzzed `Tcp` embedded transport layer.
            embed_tcp,
            Tcp
        );
        fuzz_embedded_transport_method!(
            /// Add a fuzzed `Udp` embedded transport layer.
            embed_udp,
            Udp
        );
        fuzz_embedded_transport_method!(
            /// Add a fuzzed `Icmp4` embedded transport layer.
            embed_icmp4,
            Icmp4
        );
        fuzz_embedded_transport_method!(
            /// Add a fuzzed `Icmp6` embedded transport layer.
            embed_icmp6,
            Icmp6
        );
    }

    // -- FuzzEmbeddedFull: ICMP layer + embedded net + embedded transport ----

    /// An ICMP fuzz layer with both embedded network and transport headers.
    ///
    /// Obtained by calling `.embed_tcp(...)`, `.embed_udp(...)`, etc. on a
    /// [`FuzzEmbeddedNet`].  This is a terminal chain element -- it
    /// implements [`ValueGenerator`] and can be passed directly to
    /// `bolero::check!().with_generator(...)`.
    pub struct FuzzEmbeddedFull<S, N, NM, T, TM> {
        layer: S,
        net_mutate: NM,
        transport_mutate: TM,
        _net: PhantomData<N>,
        _transport: PhantomData<T>,
    }

    impl<S, N, NM, T, TM> sealed::Sealed for FuzzEmbeddedFull<S, N, NM, T, TM> {}

    impl<S, N, NM, T, TM> GenerateChain for FuzzEmbeddedFull<S, N, NM, T, TM>
    where
        S: GenerateChain,
        N: GenerateNet,
        NM: Fn(&mut N),
        T: GenerateEmbeddedTransport,
        TM: Fn(&mut T),
    {
        type Top = S::Top;

        fn generate_chain<D: Driver>(&self, driver: &mut D) -> Option<(Headers, Self::Top)> {
            let (mut headers, top) = self.layer.generate_chain(driver)?;
            let net = N::generate_and_wrap(driver, &self.net_mutate)?;
            let transport = T::generate_and_wrap(driver, &self.transport_mutate)?;
            headers.embedded_ip = Some(fixup_embedded(Some(net), Some(transport)));
            Some((headers, top))
        }
    }

    impl<S, N, NM, T, TM> ValueGenerator for FuzzEmbeddedFull<S, N, NM, T, TM>
    where
        S: GenerateChain,
        N: GenerateNet,
        NM: Fn(&mut N),
        T: GenerateEmbeddedTransport,
        TM: Fn(&mut T),
        Headers: Install<S::Top>,
    {
        type Output = Headers;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            let (mut headers, top) = self.generate_chain(driver)?;
            headers.install(top);
            fixup_lengths(&mut headers, &[]).ok()?;
            Some(headers)
        }
    }

    // -- .embed_ipv4() / .embed_ipv6() on ICMP FuzzLayers ---------------------

    macro_rules! impl_fuzz_embedded {
        ($icmp_ty:ty) => {
            impl<Inner, Mutation> FuzzLayer<Inner, $icmp_ty, Mutation>
            where
                Inner: GenerateChain,
                $icmp_ty: TypeGenerator + Within<Inner::Top>,
                Mutation: Fn(&mut $icmp_ty),
                Headers: Install<Inner::Top> + Install<$icmp_ty>,
            {
                /// Add a fuzzed `Ipv4` embedded network layer.
                pub fn embed_ipv4(
                    self,
                    f: impl Fn(&mut Ipv4),
                ) -> FuzzEmbeddedNet<Self, Ipv4, impl Fn(&mut Ipv4)> {
                    FuzzEmbeddedNet {
                        layer: self,
                        net_mutate: f,
                        _net: PhantomData,
                    }
                }

                /// Add a fuzzed `Ipv6` embedded network layer.
                pub fn embed_ipv6(
                    self,
                    f: impl Fn(&mut Ipv6),
                ) -> FuzzEmbeddedNet<Self, Ipv6, impl Fn(&mut Ipv6)> {
                    FuzzEmbeddedNet {
                        layer: self,
                        net_mutate: f,
                        _net: PhantomData,
                    }
                }
            }
        };
    }

    // ICMPv4 error subtypes
    impl_fuzz_embedded!(super::Icmp4DestUnreachable);
    impl_fuzz_embedded!(super::Icmp4Redirect);
    impl_fuzz_embedded!(super::Icmp4TimeExceeded);
    impl_fuzz_embedded!(super::Icmp4ParamProblem);

    // ICMPv6 error subtypes
    impl_fuzz_embedded!(super::Icmp6DestUnreachable);
    impl_fuzz_embedded!(super::Icmp6PacketTooBig);
    impl_fuzz_embedded!(super::Icmp6TimeExceeded);
    impl_fuzz_embedded!(super::Icmp6ParamProblem);
}

#[cfg(any(test, feature = "bolero"))]
pub use fuzz::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::TryInnerIpv4;
    use crate::ipv4::UnicastIpv4Addr;
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_tcp_fixup_headers() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap());
                ip.set_destination(Ipv4Addr::new(10, 0, 0, 2));
            })
            .tcp(|tcp| {
                tcp.set_source(TcpPort::new_checked(12345).unwrap());
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            })
            .build_headers()
            .unwrap();

        // Eth should have IPV4 ethtype (set by conform)
        assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV4);

        // IPv4 next_header should be TCP (set by conform)
        let Net::Ipv4(ipv4) = headers.net().unwrap() else {
            panic!("expected Ipv4");
        };
        assert_eq!(ipv4.next_header(), NextHeader::TCP);

        // Transport should be TCP
        assert!(matches!(headers.transport(), Some(Transport::Tcp(_))));
    }

    #[test]
    fn ipv6_udp_fixup_headers() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .udp(|udp| {
                udp.set_source(UdpPort::new_checked(5000).unwrap());
                udp.set_destination(UdpPort::new_checked(6000).unwrap());
            })
            .build_headers()
            .unwrap();

        assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);

        let Net::Ipv6(ipv6) = headers.net().unwrap() else {
            panic!("expected Ipv6");
        };
        assert_eq!(ipv6.next_header(), NextHeader::UDP);
    }

    #[test]
    fn double_vlan_ordering() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .vlan(|v| {
                v.set_vid(Vid::new(100).unwrap());
            })
            .vlan(|v| {
                v.set_vid(Vid::new(200).unwrap());
            })
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();

        let vlans = headers.vlan();
        assert_eq!(vlans.len(), 2);
        assert_eq!(vlans[0].vid(), Vid::new(100).unwrap());
        assert_eq!(vlans[1].vid(), Vid::new(200).unwrap());
    }

    #[test]
    fn vxlan_conforms_udp() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|udp| {
                // User sets a wrong port -- conform should overwrite it.
                udp.set_destination(UdpPort::new_checked(9999).unwrap());
            })
            .vxlan(|_| {})
            .build_headers()
            .unwrap();

        let Transport::Udp(udp) = headers.transport().unwrap() else {
            panic!("expected Udp");
        };
        assert_eq!(udp.destination(), Vxlan::PORT);
    }

    #[test]
    fn icmp4_with_embedded() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.set_destination(Ipv4Addr::new(10, 0, 0, 1));
            })
            .icmp4(|_| {})
            .dest_unreachable(|_| {})
            .embedded(|inner| {
                inner
                    .ipv4(|ip| {
                        ip.set_source(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap());
                        ip.set_destination(Ipv4Addr::new(10, 0, 0, 1));
                    })
                    .tcp(
                        TcpPort::new_checked(12345).unwrap(),
                        TcpPort::new_checked(80).unwrap(),
                        |_| {},
                    )
            })
            .build_headers_with_payload([])
            .unwrap();

        assert!(headers.embedded_ip().is_some());
        assert!(matches!(headers.transport(), Some(Transport::Icmp4(_))));
    }

    #[test]
    fn fixup_computes_ip_payload_length() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers_with_payload([])
            .unwrap();

        let Net::Ipv4(ipv4) = headers.net().unwrap() else {
            panic!("expected Ipv4");
        };
        let Transport::Tcp(tcp) = headers.transport().unwrap() else {
            panic!("expected Tcp");
        };

        // IP payload length should equal the TCP header size (no trailing payload).
        assert_eq!(
            ipv4.total_len()
                .checked_sub(u16::try_from(ipv4.header_len()).unwrap())
                .unwrap(),
            tcp.size().get()
        );
    }

    #[test]
    fn blank_eth_uses_locally_administered_macs() {
        let eth = Eth::blank();
        let src = eth.source();
        let dst = eth.destination();
        // Locally-administered bit (second-least-significant bit of first octet)
        assert_ne!(src.inner().0, [0; 6]);
        assert_ne!(dst.inner().0, [0; 6]);
    }

    #[test]
    fn vxlan_udp_length_includes_encap() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|_| {})
            .vxlan(|_| {})
            .build_headers_with_payload([])
            .unwrap();

        let Transport::Udp(udp) = headers.transport().unwrap() else {
            panic!("expected Udp");
        };
        // UDP length = UDP header + VXLAN header + 0 payload
        assert_eq!(
            udp.length().get(),
            Udp::MIN_LENGTH.get() + Vxlan::MIN_LENGTH.get()
        );
    }

    #[test]
    fn icmp4_embedded_inner_next_header_is_correct() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .icmp4(|_| {})
            .time_exceeded(|_| {})
            .embedded(|inner| {
                inner.ipv4(|_| {}).tcp(
                    TcpPort::new_checked(1).unwrap(),
                    TcpPort::new_checked(1).unwrap(),
                    |_| {},
                )
            })
            .build_headers_with_payload([])
            .unwrap();

        let eh = headers
            .embedded_ip()
            .expect("embedded headers should exist");
        assert!(eh.net_headers_len() > 0, "inner IP should be present");
        assert!(
            eh.transport_headers_len() > 0,
            "inner transport should be present"
        );
    }

    #[test]
    fn icmp6_with_embedded_ipv6_udp() {
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .icmp6(|_| {})
            .dest_unreachable6(|_| {})
            .embedded(|inner| {
                inner.ipv6(|_| {}).udp(
                    UdpPort::new_checked(1).unwrap(),
                    UdpPort::new_checked(1).unwrap(),
                    |_| {},
                )
            })
            .build_headers_with_payload([])
            .unwrap();

        assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);
        assert!(matches!(headers.transport(), Some(Transport::Icmp6(_))));
        assert!(headers.embedded_ip().is_some());
    }

    #[test]
    fn fixup_with_nonempty_payload() {
        let payload = [0xAA; 100];
        let headers = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers_with_payload(payload)
            .unwrap();

        let Net::Ipv4(ipv4) = headers.net().unwrap() else {
            panic!("expected Ipv4");
        };
        let Transport::Tcp(tcp) = headers.transport().unwrap() else {
            panic!("expected Tcp");
        };

        let expected_ip_payload = tcp.size().get() + u16::try_from(payload.len()).unwrap();
        assert_eq!(
            ipv4.total_len()
                .checked_sub(u16::try_from(ipv4.header_len()).unwrap())
                .unwrap(),
            expected_ip_payload
        );
    }

    #[test]
    #[should_panic(expected = "too many VLANs")]
    fn too_many_vlans_panics() {
        let _ = HeaderStack::new()
            .eth(|_| {})
            .vlan(|_| {})
            .vlan(|_| {})
            .vlan(|_| {})
            .vlan(|_| {})
            .vlan(|_| {}) // 5th VLAN -- should panic
            .build_headers();
    }

    // -- Property-based tests (bolero) ----------------------------------------

    use crate::buffer::TestBuffer;
    use crate::parse::Parse;

    /// Replace a `Blank` value with a bolero-generated one.
    fn inject<T>(input: T) -> impl FnOnce(&mut T) {
        |reference| {
            let _ = std::mem::replace(reference, input);
        }
    }

    const MAX_PAYLOAD_LEN: usize = 60_000;

    #[test]
    fn ipv4_tcp_consistent() {
        bolero::check!().with_type().cloned().for_each(
            |(eth, ipv4, tcp, payload): (Eth, Ipv4, Tcp, Vec<u8>)| {
                if payload.len() > MAX_PAYLOAD_LEN {
                    return;
                }

                let expected_payload_len = tcp
                    .size()
                    .get()
                    .checked_add(u16::try_from(payload.len()).unwrap())
                    .unwrap();

                let headers = HeaderStack::new()
                    .eth(inject(eth))
                    .ipv4(inject(ipv4))
                    .tcp(inject(tcp))
                    .build_headers_with_payload(&payload)
                    .unwrap();

                assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV4);
                let Some(Net::Ipv4(ipv4)) = headers.net() else {
                    panic!("expected Ipv4");
                };
                assert_eq!(ipv4.next_header(), NextHeader::TCP);
                assert_eq!(
                    ipv4.total_len()
                        .checked_sub(u16::try_from(ipv4.header_len()).unwrap())
                        .unwrap(),
                    expected_payload_len
                );

                let mut test_buffer = TestBuffer::new();
                headers.deparse(test_buffer.as_mut()).unwrap();
                let (headers2, consumed) = Headers::parse(test_buffer.as_ref()).unwrap();
                assert_eq!(consumed.get() as usize, headers.size().get() as usize);
                assert_eq!(headers, headers2, "round trip failed after using builder");
            },
        );
    }

    #[test]
    fn ipv6_udp_vxlan_consistent() {
        bolero::check!().with_type().cloned().for_each(
            |(eth, ipv6, udp, vxlan, payload): (Eth, Ipv6, Udp, Vxlan, Vec<u8>)| {
                if payload.len() > MAX_PAYLOAD_LEN {
                    return;
                }

                let headers = HeaderStack::new()
                    .eth(inject(eth))
                    .ipv6(inject(ipv6))
                    .udp(inject(udp))
                    .vxlan(inject(vxlan))
                    .build_headers_with_payload(&payload)
                    .unwrap();

                assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);
                let Some(Net::Ipv6(ipv6)) = headers.net() else {
                    panic!("expected Ipv6");
                };
                let Some(Transport::Udp(udp)) = headers.transport() else {
                    panic!("expected Udp");
                };
                let Some(UdpEncap::Vxlan(_)) = headers.udp_encap() else {
                    panic!("expected Vxlan");
                };
                assert_eq!(ipv6.next_header(), NextHeader::UDP);
                assert_eq!(udp.destination(), Vxlan::PORT);

                // UDP length = UDP header + VXLAN header + payload
                let expected_udp_len = Udp::MIN_LENGTH.get()
                    + vxlan.size().get()
                    + u16::try_from(payload.len()).unwrap();
                assert_eq!(udp.length().get(), expected_udp_len);

                // VXLAN conform must zero the UDP checksum (RFC 7348)
                assert_eq!(
                    udp.checksum(),
                    Some(UdpChecksum::ZERO),
                    "VXLAN UDP checksum should be zero per RFC 7348"
                );

                let mut test_buffer = TestBuffer::new();
                headers.deparse(test_buffer.as_mut()).unwrap();
                let (headers2, consumed) = Headers::parse(test_buffer.as_ref()).unwrap();
                assert_eq!(consumed.get() as usize, headers.size().get() as usize);
                assert_eq!(headers, headers2, "round trip failed after using builder");
            },
        );
    }

    #[test]
    fn vxlan_always_overrides_udp_dst() {
        bolero::check!().with_type().cloned().for_each(
            |(eth, ipv4, udp, vxlan): (Eth, Ipv4, Udp, Vxlan)| {
                let headers = HeaderStack::new()
                    .eth(inject(eth))
                    .ipv4(inject(ipv4))
                    .udp(inject(udp))
                    .vxlan(inject(vxlan))
                    .build_headers()
                    .unwrap();

                let Transport::Udp(udp) = headers.transport().unwrap() else {
                    panic!("expected Udp");
                };
                assert_eq!(
                    udp.destination(),
                    Vxlan::PORT,
                    "VXLAN conform must override UDP dst port to 4789",
                );
            },
        );
    }

    // -- Fuzz ValueGenerator tests -------------------------------------------

    #[test]
    fn fuzz_ipv4_tcp_dst_port_pinned() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|ip| {
                        ip.set_source(Ipv4Addr::new(169, 254, 32, 53).try_into().unwrap());
                    })
                    .tcp(|tcp| {
                        tcp.set_destination(TcpPort::new_checked(80).unwrap());
                    }),
            )
            .for_each(|headers| {
                // Layer ordering invariants (same as HeaderStack).
                assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV4);
                let Some(Net::Ipv4(ipv4)) = headers.net() else {
                    panic!("expected Ipv4");
                };
                // source ip is pinned
                assert_eq!(ipv4.source().inner().octets(), [169, 254, 32, 53]);
                // next_header is pinned
                assert_eq!(ipv4.next_header(), NextHeader::TCP);

                let Some(Transport::Tcp(tcp)) = headers.transport() else {
                    panic!("expected Tcp");
                };
                // dst port is pinned
                assert_eq!(
                    tcp.destination(),
                    TcpPort::new_checked(80).unwrap(),
                    "mutation closure should pin TCP dst port to 80",
                );
            });
    }

    #[test]
    fn fuzz_ipv6_udp_vxlan_conforms() {
        let generator = ChainBase::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .udp(|_| {})
            .vxlan(|_| {});

        bolero::check!()
            .with_generator(generator)
            .for_each(|headers| {
                assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);
                let Some(Net::Ipv6(ipv6)) = headers.net() else {
                    panic!("expected Ipv6");
                };
                assert_eq!(ipv6.next_header(), NextHeader::UDP);

                let Some(Transport::Udp(udp)) = headers.transport() else {
                    panic!("expected Udp");
                };
                assert_eq!(
                    udp.destination(),
                    Vxlan::PORT,
                    "Vxlan conform must set UDP dst to 4789",
                );
            });
    }

    #[test]
    fn fuzz_round_trips_through_parse() {
        let generator = ChainBase::new().eth(|_| {}).ipv4(|_| {}).tcp(|_| {});

        bolero::check!()
            .with_generator(generator)
            .for_each(|headers| {
                let mut test_buffer = TestBuffer::new();
                headers.deparse(test_buffer.as_mut()).unwrap();
                let (headers2, consumed) = Headers::parse(test_buffer.as_ref()).unwrap();
                assert_eq!(consumed.get() as usize, headers.size().get() as usize);
                assert_eq!(headers, &headers2, "fuzz round-trip failed");
            });
    }

    #[test]
    fn fuzz_icmp4_with_embedded_ipv4_tcp() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .icmp4(|_| {})
                    .dest_unreachable(|_| {})
                    .embed_ipv4(|ip| {
                        ip.set_destination(std::net::Ipv4Addr::new(10, 0, 0, 1));
                    })
                    .embed_tcp(|tcp| {
                        tcp.set_destination(TcpPort::new_checked(80).unwrap());
                    }),
            )
            .for_each(|headers| {
                // Outer stack invariants.
                assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV4);
                assert!(matches!(headers.transport(), Some(Transport::Icmp4(_))));

                // Embedded headers must be present.
                let embedded = headers.embedded_ip().expect("embedded should exist");
                assert!(embedded.net_headers_len() > 0, "inner IP should be present");
                assert!(
                    embedded.transport_headers_len() > 0,
                    "inner transport should be present",
                );
            });
    }

    #[test]
    fn fuzz_icmp6_with_embedded_ipv6_udp() {
        let generator = ChainBase::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .icmp6(|_| {})
            .dest_unreachable6(|_| {})
            .embed_ipv6(|_| {})
            .embed_udp(|_| {});

        bolero::check!()
            .with_generator(generator)
            .for_each(|headers| {
                assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);
                assert!(matches!(headers.transport(), Some(Transport::Icmp6(_))));
                assert!(headers.embedded_ip().is_some());
            });
    }

    #[test]
    fn fuzz_icmp4_embedded_net_with_udp() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|eth| {
                        eth.set_destination(
                            Mac([0x02, 0xCA, 0xFA, 0xBA, 0xBE, 0x01])
                                .try_into()
                                .unwrap(),
                        );
                    })
                    .ipv4(|ip| {
                        ip.set_destination([192, 168, 1, 2].into());
                    })
                    .icmp4(|_| {})
                    .dest_unreachable(|_| {})
                    .embed_ipv4(|ip| {
                        ip.set_destination([169, 254, 32, 53].into());
                    })
                    .embed_udp(|udp| {
                        udp.set_destination(80.try_into().unwrap());
                    }),
            )
            .for_each(|headers| {
                assert!(matches!(headers.transport(), Some(Transport::Icmp4(_))));
                let embedded = headers.embedded_ip().expect("embedded should exist");
                assert!(embedded.net_headers_len() > 0);
                let Some(inner_ip) = embedded.try_inner_ipv4() else {
                    panic!("no embedded ipv4");
                };
                assert_eq!(inner_ip.destination().octets(), [169, 254, 32, 53]);
            });
    }

    #[test]
    fn fuzz_ipv6_ext_headers() {
        let generator = ChainBase::new().eth(|_| {}).ipv6(|_| {}).hop_by_hop(|_| {});

        bolero::check!()
            .with_generator(generator)
            .cloned()
            .for_each(|headers| {
                assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);
                assert!(
                    !headers.net_ext().is_empty(),
                    "should have extension headers"
                );
                let mut buf = vec![0u8; headers.size().get() as usize];
                headers.deparse(&mut buf).unwrap();
                let (reparsed, consumed) = Headers::parse(&buf).unwrap();
                assert_eq!(consumed.get() as usize, buf.len());
                assert_eq!(headers, reparsed, "deparse->parse round-trip failed");
            });
    }
}
