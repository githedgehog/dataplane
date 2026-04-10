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

use etherparse::{IcmpEchoHeader, Icmpv4Type, Icmpv6Type};

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
use crate::ipv4::Ipv4;
use crate::ipv4::Ipv4LengthError;
use crate::ipv6::Ipv6;
use crate::parse::DeParse;
use crate::tcp::port::TcpPort;
use crate::tcp::{Tcp, TruncatedTcp};
use crate::udp::port::UdpPort;
use crate::udp::{Udp, UdpChecksum, UdpEncap};
use crate::vlan::{Pcp, Vid, Vlan};
use crate::vxlan::{Vni, Vxlan};

use super::{Net, Transport};

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
        Icmp4::with_type(Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 0 }))
    }
}

impl Blank for Icmp6 {
    fn blank() -> Self {
        Icmp6::with_type(Icmpv6Type::EchoRequest(IcmpEchoHeader { id: 0, seq: 0 }))
    }
}

impl Blank for Vxlan {
    fn blank() -> Self {
        #[allow(clippy::unwrap_used)] // VNI 1 is always valid
        Vxlan::new(Vni::new_checked(1).unwrap())
    }
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

    // It is safe to combine values this way because the mutually exclusive values are mapped back
    // to zero (e.g. embedded_size is 0 when transport is UDP, encap_size is 0 when transport is
    // ICMP, etc.).
    // TODO: include net_ext size once IPv6 extension headers are supported.
    let ip_payload = transport_size
        .checked_add(payload_u16)
        .and_then(|v| v.checked_add(encap_size))
        .and_then(|v| v.checked_add(embedded_size))
        .ok_or(BuildError::PayloadTooLarge)?;

    match headers.transport {
        Some(Transport::Udp(ref mut udp)) => {
            // SAFETY: `transport_size >= Udp::MIN_LENGTH` when transport is UDP, so `ip_payload`
            // is guaranteed non-zero.
            let udp_len = NonZero::new(ip_payload).unwrap_or_else(|| unreachable!());
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
/// `(TypeGenerator, Fn(&mut T))` pairs.  At generation time the chain
/// walks itself recursively:
///
/// 1. Generate the inner (preceding) layers -> `(Headers, PrevLayer)`.
/// 2. Conform `PrevLayer` and install it into `Headers`.
/// 3. Generate the current layer via `TypeGenerator`.
/// 4. Apply the mutation closure.
/// 5. Return `(Headers, CurrentLayer)`.
///
/// The chain is encoded in nested generics ([`ChainBase`] -> [`FuzzLayer`] -> ...),
/// so each variant of the chain is a unique type -- Rust monomorphizes the
/// entire build at compile time.
///
/// # Examples
///
/// ```ignore
/// use net::headers::builder::*;
///
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
    /// Each implementor can produce a `(Headers, Top)` pair from a
    /// [`Driver`], where `Top` is the layer that has been generated
    /// but **not yet installed** (so the next layer can [`Within::conform`]
    /// it first).
    ///
    /// This trait is used internally by the
    /// only [`ChainBase`]
    /// and [`FuzzLayer`] implement it.
    pub trait GenerateChain: sealed::Sealed {
        /// The type of the layer currently held at the top of the chain.
        ///
        /// For [`ChainBase`] this is `()` (no layer yet).
        type Top;

        /// Walk the chain, producing a [`Headers`] and the not-yet-installed
        /// top layer.
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

    /// The starting point for a fuzz chain -- analogous to [`super::HeaderStack<()>`].
    #[derive(Default)]
    #[non_exhaustive]
    pub struct ChainBase;

    impl ChainBase {
        /// Create a new fuzz chain.
        ///
        /// Always starts empty, just like [`super::HeaderStack::new`].
        #[must_use]
        pub const fn new() -> Self {
            ChainBase
        }

        /// Push a new layer onto the chain.
        ///
        /// This is the generic version; most callers use the named
        /// convenience methods (`.eth(...)`, `.ipv4(...)`, ...).
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
            mutate: impl Fn(&mut crate::eth::Eth),
        ) -> FuzzLayer<Self, crate::eth::Eth, impl Fn(&mut crate::eth::Eth)> {
            self.stack(mutate)
        }
    }

    impl GenerateChain for ChainBase {
        type Top = ();

        fn generate_chain<D: Driver>(&self, _driver: &mut D) -> Option<(Headers, ())> {
            Some((Headers::default(), ()))
        }
    }

    /// One link in a fuzz header chain.
    ///
    /// - `Inner` -- the preceding chain ([`ChainBase`] or another `FuzzLayer`).
    /// - `Layer` -- the header type held at this position.
    /// - `Mutation`     -- the mutation closure `Fn(&mut Layer)`.
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
        Headers: Install<Inner::Top> + Install<Layer>,
    {
        type Top = Layer;

        fn generate_chain<D: Driver>(&self, driver: &mut D) -> Option<(Headers, Layer)> {
            let (mut headers, mut prev) = self.inner.generate_chain(driver)?;
            Layer::conform(&mut prev);
            headers.install(prev);

            let mut layer: Layer = driver.produce()?;
            (self.mutate)(&mut layer);
            Some((headers, layer))
        }
    }

    /// Helper macro to generate named layer methods on [`FuzzLayer`].
    ///
    /// Each method delegates to [`FuzzLayer::stack`] with the concrete
    /// header type, enforcing the `TypeGenerator + Within<Layer>` bound.
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

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Headers> {
            let (mut headers, top) = self.generate_chain(driver)?;
            headers.install(top);
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
        /// Generate headers with an explicit payload.
        ///
        /// Unlike the `ValueGenerator` impl (which uses an empty payload),
        /// this method takes a `payload` slice and passes it to
        /// [`fixup_lengths`](super::fixup_lengths) so that IP/UDP length
        /// fields account for the trailing data.
        ///
        /// Returns `None` if generation fails, or `Some(Err(...))` if
        /// length fixup overflows.
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
}

#[cfg(any(test, feature = "bolero"))]
pub use fuzz::*;

#[cfg(test)]
mod tests {
    use super::*;
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
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            }))
            .cloned()
            .for_each(|headers| {
                let Transport::Tcp(tcp) = headers.transport().unwrap() else {
                    panic!("expected Tcp");
                };
                assert_eq!(
                    tcp.destination(),
                    TcpPort::new_checked(80).unwrap(),
                    "destination port should have been pinned by the mutation"
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
            .cloned()
            .for_each(|headers| {
                // Eth -> IPV6
                assert_eq!(headers.eth().unwrap().ether_type(), EthType::IPV6);
                // UDP -> VXLAN port
                let Transport::Udp(udp) = headers.transport().unwrap() else {
                    panic!("expected Udp");
                };
                assert_eq!(udp.destination(), Vxlan::PORT);
            });
    }

    #[test]
    fn fuzz_round_trips_through_parse() {
        let generator = ChainBase::new().eth(|_| {}).ipv4(|_| {}).tcp(|_| {});

        bolero::check!()
            .with_generator(generator)
            .cloned()
            .for_each(|headers| {
                let mut test_buffer = vec![0u8; headers.size().get() as usize];
                headers.deparse(&mut test_buffer).unwrap();
                let (headers2, consumed) = Headers::parse(test_buffer.as_ref()).unwrap();
                assert_eq!(consumed.get() as usize, headers.size().get() as usize);
                assert_eq!(headers, headers2, "fuzz round-trip failed");
            });
    }
}
