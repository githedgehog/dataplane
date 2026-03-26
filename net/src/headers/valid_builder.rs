// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! [`ValidHeadersBuilder`] — a typestate builder for constructing structurally
//! correct packet [`Headers`].
//!
//! # Motivation
//!
//! The derive-builder [`HeadersBuilder`] provides mechanical field-by-field
//! construction but enforces no consistency between layers.  Nothing stops you
//! from pairing `EthType::IPV4` with an IPv6 network header, setting the wrong
//! `NextHeader`, or computing payload lengths in the wrong order.
//!
//! [`ValidHeadersBuilder`] prevents these classes of bugs by:
//!
//! * **Enforcing layer ordering** via typestate — you must set Ethernet before
//!   the network layer, and the network layer before transport.
//! * **Auto-setting structural fields** — `EthType`, `NextHeader`, IP payload
//!   length, UDP datagram length, and checksums are all computed by the
//!   builder.
//! * **Validating cross-layer consistency** at `build()` time — ICMP4 requires
//!   IPv4, VXLAN requires UDP, embedded headers require ICMP, etc.
//!
//! # When to use each construction mechanism
//!
//! | Mechanism                             | Use case                                   |
//! |---------------------------------------|--------------------------------------------|
//! | [`ValidHeadersBuilder`]               | Correct-by-construction test packets       |
//! | [`HeadersBuilder`] (derive-builder)   | Malformed / adversarial packets            |
//! | Bolero generators                     | Random exploration, fuzz testing           |
//!
//! # Scope — what is **not** yet supported
//!
//! * **Network extension headers** (`IpAuth`, `Ipv6Ext`).  These require
//!   `NextHeader` chaining and are deferred to a future phase.  Use
//!   [`HeadersBuilder`] if you need them today.
//! * **Automatic ICMP payload-length fields** (RFC 4884).  This requires
//!   writing directly to the wire buffer after deparsing.
//!
//! # Feature gate
//!
//! This module is available when the **`packet-builder`** Cargo feature is
//! enabled.  It is independent of the `bolero` and `test_buffer` features.
//!
//! [`HeadersBuilder`]: super::HeadersBuilder

use arrayvec::ArrayVec;
use std::marker::PhantomData;
use std::num::NonZero;

use crate::eth::ethtype::EthType;
use crate::eth::mac::{DestinationMac, Mac, SourceMac};
use crate::eth::Eth;
use crate::headers::{EmbeddedHeadersBuilder, EmbeddedTransport, Headers};
use crate::icmp4::Icmp4;
use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::Icmp6;
use crate::icmp6::TruncatedIcmp6;
use crate::ip::NextHeader;
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::parse::DeParse;
use crate::tcp::port::TcpPort;
use crate::tcp::{Tcp, TruncatedTcp};
use crate::udp::port::UdpPort;
use crate::udp::{Udp, UdpChecksum, UdpEncap};
use crate::checksum::Checksum;
use crate::vlan::Vid;
use crate::vxlan::{Vni, Vxlan};

use super::{Net, Transport};

// ---------------------------------------------------------------------------
// State marker types
// ---------------------------------------------------------------------------

/// Initial state — no headers have been set.
#[derive(Debug)]
pub struct Empty;

/// Ethernet (and optionally VLAN) headers have been set.
#[derive(Debug)]
pub struct WithEth;

/// A network (IP) layer has been set.
#[derive(Debug)]
pub struct WithNet;

/// A transport layer has been set.
#[derive(Debug)]
pub struct WithTransport;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when building headers via [`ValidHeadersBuilder`].
#[derive(Debug, thiserror::Error)]
pub enum ValidHeadersBuildError {
    /// ICMPv4 transport paired with an IPv6 network header.
    #[error("ICMPv4 transport requires IPv4 network layer")]
    Icmp4WithIpv6,

    /// ICMPv6 transport paired with an IPv4 network header.
    #[error("ICMPv6 transport requires IPv6 network layer")]
    Icmp6WithIpv4,

    /// VXLAN encapsulation present but transport is not UDP.
    #[error("VXLAN encapsulation requires UDP transport")]
    VxlanWithoutUdp,

    /// Embedded (ICMP-error) headers present but transport is not ICMP.
    #[error("embedded headers require an ICMP transport layer")]
    EmbeddedWithoutIcmp,

    /// Both embedded headers and VXLAN encapsulation were set.
    #[error("cannot have both embedded headers and VXLAN encapsulation")]
    EmbeddedAndVxlanConflict,

    /// The embedded headers have no network layer, which would produce a
    /// zero-sized `EmbeddedHeaders` (illegal).
    #[error("embedded headers must contain at least a network layer")]
    EmbeddedMissingNet,

    /// The computed IP payload length or UDP datagram length overflows `u16`.
    #[error("payload too large for IP/UDP length fields")]
    PayloadTooLarge,

    /// An IPv4 payload-length error propagated from [`Ipv4::set_payload_len`].
    #[error("IPv4 payload length overflow")]
    Ipv4PayloadOverflow,

    /// Too many VLAN tags were pushed (exceeds the parser limit).
    #[error("too many VLAN tags (max {max})", max = super::MAX_VLANS)]
    TooManyVlans,
}

// ---------------------------------------------------------------------------
// Internal accumulator shared across all states
// ---------------------------------------------------------------------------

/// Private accumulator that holds every field the builder may touch.
///
/// The typestate on [`ValidHeadersBuilder`] guarantees which fields have been
/// populated at any given point; the `Option` wrappers are a mechanical
/// necessity, not a sign that the fields might legitimately be `None`.
struct BuilderInner {
    eth_src: Option<SourceMac>,
    eth_dst: Option<DestinationMac>,
    vlans: ArrayVec<Vid, { super::MAX_VLANS }>,
    net: Option<Net>,
    transport: Option<Transport>,
    udp_encap: Option<UdpEncap>,
    embedded_ip: Option<super::EmbeddedHeaders>,
}

impl BuilderInner {
    /// Create a fresh, empty accumulator.
    fn new() -> Self {
        Self {
            eth_src: None,
            eth_dst: None,
            vlans: ArrayVec::new(),
            net: None,
            transport: None,
            udp_encap: None,
            embedded_ip: None,
        }
    }

    // -- validation --------------------------------------------------------

    /// Run cross-layer consistency checks.
    fn validate(&self) -> Result<(), ValidHeadersBuildError> {
        // ICMP / Net consistency
        match (&self.net, &self.transport) {
            (Some(Net::Ipv6(_)), Some(Transport::Icmp4(_))) => {
                return Err(ValidHeadersBuildError::Icmp4WithIpv6);
            }
            (Some(Net::Ipv4(_)), Some(Transport::Icmp6(_))) => {
                return Err(ValidHeadersBuildError::Icmp6WithIpv4);
            }
            _ => {}
        }

        // VXLAN requires UDP
        if self.udp_encap.is_some() && !matches!(self.transport, Some(Transport::Udp(_))) {
            return Err(ValidHeadersBuildError::VxlanWithoutUdp);
        }

        // Embedded headers require ICMP
        if self.embedded_ip.is_some()
            && !matches!(
                self.transport,
                Some(Transport::Icmp4(_) | Transport::Icmp6(_))
            )
        {
            return Err(ValidHeadersBuildError::EmbeddedWithoutIcmp);
        }

        // Cannot have both embedded headers and VXLAN
        if self.embedded_ip.is_some() && self.udp_encap.is_some() {
            return Err(ValidHeadersBuildError::EmbeddedAndVxlanConflict);
        }

        // If embedded headers are present, they must have a network layer
        if let Some(ref eh) = self.embedded_ip {
            if eh.net_headers_len() == 0 {
                return Err(ValidHeadersBuildError::EmbeddedMissingNet);
            }
        }

        Ok(())
    }

    // -- final assembly ----------------------------------------------------

    /// Consume the accumulator and produce a validated, length-correct,
    /// checksum-correct [`Headers`].
    ///
    /// `payload` is the byte content that will follow all headers on the wire.
    /// It is used for:
    /// * IP total/payload length calculation
    /// * UDP datagram length calculation
    /// * Transport and IP checksum computation
    ///
    /// Pass `&[]` when there is no trailing payload (e.g. ICMP errors where
    /// the embedded headers carry the interesting data).
    fn finalize(mut self, payload: &[u8]) -> Result<Headers, ValidHeadersBuildError> {
        self.validate()?;

        // ---- sizes of optional components --------------------------------

        let transport_size: u16 = self
            .transport
            .as_ref()
            .map_or(0, |t| t.size().get());

        let embedded_size: u16 = self
            .embedded_ip
            .as_ref()
            .map_or(0, |e| e.size().get());

        let encap_size: u16 = match &self.udp_encap {
            Some(UdpEncap::Vxlan(v)) => v.size().get(),
            None => 0,
        };

        #[allow(clippy::cast_possible_truncation)] // builder is test-facing; 64 KiB is plenty
        let payload_u16 = u16::try_from(payload.len())
            .map_err(|_| ValidHeadersBuildError::PayloadTooLarge)?;

        // ---- UDP datagram length -----------------------------------------

        if let Some(Transport::Udp(ref mut udp)) = self.transport {
            let udp_total = Udp::MIN_LENGTH
                .get()
                .checked_add(encap_size)
                .and_then(|v| v.checked_add(payload_u16))
                .and_then(NonZero::new)
                .ok_or(ValidHeadersBuildError::PayloadTooLarge)?;

            #[allow(unsafe_code)]
            // SAFETY: `udp_total >= Udp::MIN_LENGTH` by construction — we
            // start from `Udp::MIN_LENGTH` and only add non-negative terms.
            unsafe {
                udp.set_length(udp_total);
            }
        }

        // ---- IP payload length -------------------------------------------
        //
        // The IP payload encompasses everything after the IP header:
        // transport header + embedded headers + encap header + user payload.
        //
        // Note: net extension headers are not yet supported (Phase 1), so
        // they contribute 0 to the calculation.

        let ip_payload = transport_size
            .checked_add(embedded_size)
            .and_then(|v| v.checked_add(encap_size))
            .and_then(|v| v.checked_add(payload_u16))
            .ok_or(ValidHeadersBuildError::PayloadTooLarge)?;

        match &mut self.net {
            Some(Net::Ipv4(ip)) => {
                ip.set_payload_len(ip_payload)
                    .map_err(|_| ValidHeadersBuildError::Ipv4PayloadOverflow)?;
            }
            Some(Net::Ipv6(ip)) => {
                ip.set_payload_length(ip_payload);
            }
            None => {} // unreachable via typestate, but harmless
        }

        // ---- Ethernet + VLAN chain ---------------------------------------
        //
        // We construct the Ethernet header with the correct EthType for the
        // network layer, then use the existing `Headers::push_vlan` logic to
        // insert VLAN tags (which adjusts EthType automatically).

        let net_ethtype = match &self.net {
            Some(Net::Ipv4(_)) => EthType::IPV4,
            Some(Net::Ipv6(_)) => EthType::IPV6,
            None => EthType::IPV4, // unreachable via typestate
        };

        // `eth_src` / `eth_dst` are guaranteed `Some` by the typestate —
        // the `WithEth` → `WithNet` path requires `.eth()` first.
        let eth = match (self.eth_src, self.eth_dst) {
            (Some(src), Some(dst)) => Some(Eth::new(src, dst, net_ethtype)),
            _ => None,
        };

        let mut headers = Headers {
            eth,
            vlan: ArrayVec::new(),
            net: self.net,
            net_ext: ArrayVec::new(), // Phase 1: extensions not yet supported
            transport: self.transport,
            udp_encap: self.udp_encap,
            embedded_ip: self.embedded_ip,
        };

        // Push VLANs using the existing method (handles EthType chaining).
        for vid in &self.vlans {
            headers
                .push_vlan(*vid)
                .map_err(|_| ValidHeadersBuildError::TooManyVlans)?;
        }

        // ---- checksums ---------------------------------------------------
        //
        // `update_checksums` handles:
        //   1. IPv4 header checksum (from header fields only)
        //   2. Inner (embedded) IPv4 header checksum
        //   3. Transport checksum (TCP / UDP / ICMP over payload)
        //   4. VXLAN special-case (skips transport checksum)

        headers.update_checksums(payload);

        Ok(headers)
    }
}

// ---------------------------------------------------------------------------
// ValidHeadersBuilder — the public API
// ---------------------------------------------------------------------------

/// A typestate builder that produces structurally valid [`Headers`].
///
/// See the [module-level documentation](self) for motivation and examples.
///
/// # Example
///
/// ```ignore
/// use dataplane_net::headers::valid_builder::ValidHeadersBuilder;
///
/// let headers = ValidHeadersBuilder::new()
///     .eth_defaults()
///     .ipv4(|ip| {
///         ip.set_source(src_addr);
///         ip.set_destination(dst_addr);
///         ip.set_ttl(64);
///     })
///     .tcp(src_port, dst_port, |tcp| {
///         tcp.set_syn(true);
///     })
///     .build(&[])
///     .unwrap();
/// ```
#[must_use = "builders do nothing unless `.build()` is called"]
pub struct ValidHeadersBuilder<State> {
    inner: BuilderInner,
    _state: PhantomData<State>,
}

// Manually implement `Debug` because `BuilderInner` is private and
// `PhantomData<State>` prints oddly.
impl<State> std::fmt::Debug for ValidHeadersBuilder<State> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidHeadersBuilder")
            .field("state", &std::any::type_name::<State>())
            .finish()
    }
}

// ---- Empty state ---------------------------------------------------------

impl ValidHeadersBuilder<Empty> {
    /// Create a new builder in the [`Empty`] state.
    pub fn new() -> Self {
        Self {
            inner: BuilderInner::new(),
            _state: PhantomData,
        }
    }

    /// Set the Ethernet source and destination MAC addresses.
    ///
    /// The `EthType` field is **not** set here — it is determined
    /// automatically when you call [`.ipv4()`](ValidHeadersBuilder::ipv4) or
    /// [`.ipv6()`](ValidHeadersBuilder::ipv6).
    pub fn eth(
        mut self,
        src: SourceMac,
        dst: DestinationMac,
    ) -> ValidHeadersBuilder<WithEth> {
        self.inner.eth_src = Some(src);
        self.inner.eth_dst = Some(dst);
        ValidHeadersBuilder {
            inner: self.inner,
            _state: PhantomData,
        }
    }

    /// Set the Ethernet header to well-known test defaults.
    ///
    /// * Source: `02:00:00:00:00:01`
    /// * Destination: `02:00:00:00:00:02`
    ///
    /// These are locally-administered unicast addresses that will not collide
    /// with real hardware.
    pub fn eth_defaults(self) -> ValidHeadersBuilder<WithEth> {
        // The `unwrap` calls are safe: the byte values are valid by
        // inspection (locally-administered, unicast bit set).
        #[allow(clippy::unwrap_used)]
        let src = SourceMac::new(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])).unwrap();
        #[allow(clippy::unwrap_used)]
        let dst = DestinationMac::new(Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])).unwrap();
        self.eth(src, dst)
    }
}

impl Default for ValidHeadersBuilder<Empty> {
    fn default() -> Self {
        Self::new()
    }
}

// ---- WithEth state -------------------------------------------------------

impl ValidHeadersBuilder<WithEth> {
    /// Push a VLAN tag onto the stack.
    ///
    /// May be called repeatedly to build Q-in-Q (double-tagged) frames up to
    /// the parser limit.  VLAN tags are pushed in "closest to IP first" order:
    /// the first call inserts the innermost tag, and subsequent calls push
    /// outer tags.
    ///
    /// # Errors
    ///
    /// Returns [`ValidHeadersBuildError::TooManyVlans`] if the stack is full.
    pub fn vlan(mut self, vid: Vid) -> Result<Self, ValidHeadersBuildError> {
        if self.inner.vlans.len() >= super::MAX_VLANS {
            return Err(ValidHeadersBuildError::TooManyVlans);
        }
        self.inner.vlans.push(vid);
        Ok(self)
    }

    /// Set the network layer to IPv4.
    ///
    /// The closure receives a default-initialized [`Ipv4`] header for
    /// customization.  The builder automatically sets:
    ///
    /// * `EthType::IPV4` on the Ethernet (or innermost VLAN) header
    /// * `NextHeader` when a transport method is called later
    /// * `payload_len` / `total_length` at `build()` time
    /// * The IPv4 header checksum at `build()` time
    pub fn ipv4(
        mut self,
        f: impl FnOnce(&mut Ipv4),
    ) -> ValidHeadersBuilder<WithNet> {
        let mut ipv4 = Ipv4::default();
        f(&mut ipv4);
        self.inner.net = Some(Net::Ipv4(ipv4));
        ValidHeadersBuilder {
            inner: self.inner,
            _state: PhantomData,
        }
    }

    /// Set the network layer to IPv6.
    ///
    /// The closure receives a default-initialized [`Ipv6`] header for
    /// customization.  The builder automatically sets:
    ///
    /// * `EthType::IPV6` on the Ethernet (or innermost VLAN) header
    /// * `NextHeader` when a transport method is called later
    /// * `payload_length` at `build()` time
    pub fn ipv6(
        mut self,
        f: impl FnOnce(&mut Ipv6),
    ) -> ValidHeadersBuilder<WithNet> {
        let mut ipv6 = Ipv6::default();
        f(&mut ipv6);
        self.inner.net = Some(Net::Ipv6(ipv6));
        ValidHeadersBuilder {
            inner: self.inner,
            _state: PhantomData,
        }
    }
}

// ---- WithNet state -------------------------------------------------------

impl ValidHeadersBuilder<WithNet> {
    /// Set the transport layer to TCP.
    ///
    /// `src` and `dst` are the mandatory source/destination ports.  The
    /// closure allows further configuration (SYN, sequence numbers, etc.).
    ///
    /// The builder automatically sets `NextHeader::TCP` on the IP header.
    pub fn tcp(
        mut self,
        src: TcpPort,
        dst: TcpPort,
        f: impl FnOnce(&mut Tcp),
    ) -> ValidHeadersBuilder<WithTransport> {
        set_net_next_header(&mut self.inner.net, NextHeader::TCP);
        let mut tcp = Tcp::new(src, dst);
        f(&mut tcp);
        self.inner.transport = Some(Transport::Tcp(tcp));
        ValidHeadersBuilder {
            inner: self.inner,
            _state: PhantomData,
        }
    }

    /// Set the transport layer to UDP.
    ///
    /// `src` and `dst` are the mandatory source/destination ports.  The
    /// closure allows further configuration.
    ///
    /// The builder automatically sets `NextHeader::UDP` on the IP header and
    /// computes the UDP datagram length at `build()` time.
    pub fn udp(
        mut self,
        src: UdpPort,
        dst: UdpPort,
        f: impl FnOnce(&mut Udp),
    ) -> ValidHeadersBuilder<WithTransport> {
        set_net_next_header(&mut self.inner.net, NextHeader::UDP);
        let mut udp = Udp::new(src, dst);
        f(&mut udp);
        self.inner.transport = Some(Transport::Udp(udp));
        ValidHeadersBuilder {
            inner: self.inner,
            _state: PhantomData,
        }
    }

    /// Set the transport layer to ICMPv4.
    ///
    /// The caller supplies a fully-constructed [`Icmp4`] value (echo request,
    /// destination unreachable, etc.).
    ///
    /// The builder automatically sets `NextHeader::ICMP` on the IP header.
    pub fn icmp4(mut self, icmp: Icmp4) -> ValidHeadersBuilder<WithTransport> {
        set_net_next_header(&mut self.inner.net, NextHeader::ICMP);
        self.inner.transport = Some(Transport::Icmp4(icmp));
        ValidHeadersBuilder {
            inner: self.inner,
            _state: PhantomData,
        }
    }

    /// Set the transport layer to ICMPv6.
    ///
    /// The caller supplies a fully-constructed [`Icmp6`] value.
    ///
    /// The builder automatically sets `NextHeader::ICMP6` on the IP header.
    pub fn icmp6(mut self, icmp: Icmp6) -> ValidHeadersBuilder<WithTransport> {
        set_net_next_header(&mut self.inner.net, NextHeader::ICMP6);
        self.inner.transport = Some(Transport::Icmp6(icmp));
        ValidHeadersBuilder {
            inner: self.inner,
            _state: PhantomData,
        }
    }

    /// Build headers for an IP-only packet (no transport layer).
    ///
    /// `payload` is the byte content that follows the IP header on the wire.
    /// It is used for IP length and checksum calculations.  Pass `&[]` for a
    /// bare IP header with no payload.
    ///
    /// # Note
    ///
    /// The IP header's `NextHeader` / `Protocol` field is **not** set
    /// automatically (there is no transport to infer it from).  Set it
    /// explicitly in your `.ipv4()` / `.ipv6()` closure if it matters for your
    /// test.
    ///
    /// # Errors
    ///
    /// Returns [`ValidHeadersBuildError`] if the payload is too large or
    /// cross-layer validation fails.
    pub fn build(self, payload: &[u8]) -> Result<Headers, ValidHeadersBuildError> {
        self.inner.finalize(payload)
    }
}

// ---- WithTransport state -------------------------------------------------

impl ValidHeadersBuilder<WithTransport> {
    /// Attach ICMP-error embedded headers.
    ///
    /// The closure receives a fresh [`EmbeddedAssembler`] and should configure
    /// the inner network and (optionally) transport headers that represent the
    /// *offending original packet*.
    ///
    /// The assembler automatically sets:
    /// * The inner IP header's `NextHeader` based on the inner transport
    /// * The inner IP header's `payload_len` to match the inner transport size
    ///
    /// # Example
    ///
    /// ```ignore
    /// .embedded(|inner| {
    ///     inner
    ///         .ipv4(|ip| {
    ///             ip.set_source(inner_src);
    ///             ip.set_destination(inner_dst);
    ///             ip.set_ttl(4);
    ///         })
    ///         .tcp(inner_sport, inner_dport, |_| {})
    /// })
    /// ```
    pub fn embedded(
        mut self,
        f: impl FnOnce(EmbeddedAssembler) -> EmbeddedAssembler,
    ) -> Self {
        let assembler = f(EmbeddedAssembler::new());
        self.inner.embedded_ip = Some(assembler.finish());
        self
    }

    /// Attach a VXLAN encapsulation header.
    ///
    /// This is only valid when the transport layer is UDP.  The builder will
    /// return an error at `build()` time if the transport is not UDP.
    ///
    /// The UDP checksum is set to zero per the VXLAN specification.
    pub fn vxlan(mut self, vni: Vni) -> Self {
        // Per VXLAN spec, UDP checksum SHOULD be zero.
        if let Some(Transport::Udp(ref mut udp)) = self.inner.transport {
            udp.set_checksum(UdpChecksum::ZERO)
                .unwrap_or_else(|()| unreachable!());
        }
        self.inner.udp_encap = Some(UdpEncap::Vxlan(Vxlan::new(vni)));
        self
    }

    /// Build the assembled [`Headers`].
    ///
    /// `payload` is the byte content that follows **all** headers on the wire.
    /// It is used for:
    /// * IP payload-length / total-length calculation
    /// * UDP datagram-length calculation
    /// * Transport and IP checksum computation
    ///
    /// Pass `&[]` when there is no trailing payload (the common case for ICMP
    /// error packets where the interesting data is in the embedded headers).
    ///
    /// For VXLAN packets, `payload` is the serialized inner Ethernet frame.
    ///
    /// # Errors
    ///
    /// Returns [`ValidHeadersBuildError`] if cross-layer validation fails or
    /// the total size overflows `u16` limits.
    pub fn build(self, payload: &[u8]) -> Result<Headers, ValidHeadersBuildError> {
        self.inner.finalize(payload)
    }
}

// ---------------------------------------------------------------------------
// EmbeddedAssembler — sub-builder for ICMP error embedded headers
// ---------------------------------------------------------------------------

/// Sub-builder for the headers embedded inside an ICMP error message.
///
/// This builder mirrors the main [`ValidHeadersBuilder`] API but without the
/// Ethernet / VLAN layers (embedded headers start at the IP layer).  It does
/// not use typestate — all validation happens when the parent builder calls
/// `build()`.
///
/// The assembler automatically sets:
/// * The inner IP's `NextHeader` to match the chosen transport
/// * The inner IP's payload length to equal the transport header size
///   (representing a minimal "original" packet with no application data)
#[must_use]
pub struct EmbeddedAssembler {
    net: Option<Net>,
    transport: Option<EmbeddedTransport>,
}

impl EmbeddedAssembler {
    /// Create a new, empty embedded assembler.
    fn new() -> Self {
        Self {
            net: None,
            transport: None,
        }
    }

    /// Set the inner network layer to IPv4.
    ///
    /// The closure receives a default [`Ipv4`] for customization.  `NextHeader`
    /// and `payload_len` are set automatically when a transport method is
    /// called (or in `finish()` if no transport is set).
    pub fn ipv4(mut self, f: impl FnOnce(&mut Ipv4)) -> Self {
        let mut ipv4 = Ipv4::default();
        f(&mut ipv4);
        self.net = Some(Net::Ipv4(ipv4));
        self
    }

    /// Set the inner network layer to IPv6.
    ///
    /// The closure receives a default [`Ipv6`] for customization.
    pub fn ipv6(mut self, f: impl FnOnce(&mut Ipv6)) -> Self {
        let mut ipv6 = Ipv6::default();
        f(&mut ipv6);
        self.net = Some(Net::Ipv6(ipv6));
        self
    }

    /// Set the inner transport to a full TCP header.
    ///
    /// `src` and `dst` are the source/destination ports.  The closure allows
    /// further configuration.
    ///
    /// Automatically sets the inner IP's `NextHeader` to [`NextHeader::TCP`].
    pub fn tcp(
        mut self,
        src: TcpPort,
        dst: TcpPort,
        f: impl FnOnce(&mut Tcp),
    ) -> Self {
        set_net_next_header(&mut self.net, NextHeader::TCP);
        let mut tcp = Tcp::new(src, dst);
        f(&mut tcp);
        self.transport = Some(EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(tcp)));
        self
    }

    /// Set the inner transport to a full UDP header.
    ///
    /// Automatically sets the inner IP's `NextHeader` to [`NextHeader::UDP`].
    pub fn udp(
        mut self,
        src: UdpPort,
        dst: UdpPort,
        f: impl FnOnce(&mut Udp),
    ) -> Self {
        set_net_next_header(&mut self.net, NextHeader::UDP);
        let mut udp = Udp::new(src, dst);
        f(&mut udp);
        self.transport = Some(EmbeddedTransport::Udp(crate::udp::TruncatedUdp::FullHeader(udp)));
        self
    }

    /// Set the inner transport to a full ICMPv4 header.
    ///
    /// Automatically sets the inner IP's `NextHeader` to [`NextHeader::ICMP`].
    pub fn icmp4(mut self, icmp: Icmp4) -> Self {
        set_net_next_header(&mut self.net, NextHeader::ICMP);
        self.transport = Some(EmbeddedTransport::Icmp4(TruncatedIcmp4::FullHeader(icmp)));
        self
    }

    /// Set the inner transport to a full ICMPv6 header.
    ///
    /// Automatically sets the inner IP's `NextHeader` to
    /// [`NextHeader::ICMP6`].
    pub fn icmp6(mut self, icmp: Icmp6) -> Self {
        set_net_next_header(&mut self.net, NextHeader::ICMP6);
        self.transport = Some(EmbeddedTransport::Icmp6(TruncatedIcmp6::FullHeader(icmp)));
        self
    }

    /// Consume the assembler and produce an [`EmbeddedHeaders`] value.
    ///
    /// The inner IP's payload length is set to the transport header size,
    /// representing a minimal "original" packet.
    fn finish(mut self) -> super::EmbeddedHeaders {
        // Auto-set inner IP payload length to match the embedded transport
        // header size, representing a minimal "original" packet.
        let transport_size = self
            .transport
            .as_ref()
            .map_or(0u16, |t| t.size().get());

        match &mut self.net {
            Some(Net::Ipv4(ip)) => {
                // Ignore errors — the transport size is always small enough.
                let _ = ip.set_payload_len(transport_size);
                // Update the inner IPv4 header checksum so the embedded
                // headers are consistent when inspected directly.
                ip.update_checksum(&())
                    .unwrap_or_else(|()| unreachable!());
            }
            Some(Net::Ipv6(ip)) => {
                ip.set_payload_length(transport_size);
            }
            None => {}
        }

        let mut builder = EmbeddedHeadersBuilder::default();
        builder.net(self.net);
        builder.transport(self.transport);
        // `build()` cannot fail: all fields have defaults via
        // `#[builder(default)]`.
        #[allow(clippy::unwrap_used)]
        builder.build().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]
mod tests {
    use super::*;
    use crate::headers::{TryEth, TryIcmp4, TryIpv4, TryIpv6, TryTcp, TryUdp, TryVxlan};
    use crate::ipv4::addr::UnicastIpv4Addr;
    use crate::ipv6::addr::UnicastIpv6Addr;
    use crate::parse::Parse;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use etherparse::icmpv4::DestUnreachableHeader;
    use etherparse::{IcmpEchoHeader, Icmpv4Header, Icmpv4Type};

    // -- shared helpers ----------------------------------------------------

    /// Deparse → parse roundtrip check.
    ///
    /// Serialises `headers` and `payload` into a flat buffer, then parses the
    /// buffer back.  Asserts that consumed bytes match header size and that
    /// the parsed headers equal the originals.
    fn assert_roundtrip(headers: &Headers, payload: &[u8]) {
        let hdr_size = headers.size().get() as usize;
        let total = hdr_size + payload.len();
        let mut buf = vec![0u8; total];
        headers
            .deparse(&mut buf)
            .expect("deparse should succeed for a valid header set");
        buf[hdr_size..].copy_from_slice(payload);

        let (parsed, consumed) = Headers::parse(&buf).expect("parse should succeed");
        assert_eq!(
            consumed.get() as usize, hdr_size,
            "consumed bytes mismatch: expected {hdr_size}, got {}",
            consumed.get()
        );
        assert_eq!(headers, &parsed, "roundtrip mismatch");
    }

    // -- address / port factories ------------------------------------------

    fn test_src_v4() -> UnicastIpv4Addr {
        UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap()
    }
    fn test_dst_v4() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 2)
    }
    fn test_src_v6() -> UnicastIpv6Addr {
        UnicastIpv6Addr::new("fd00::1".parse().unwrap()).unwrap()
    }
    fn test_dst_v6() -> Ipv6Addr {
        "fd00::2".parse().unwrap()
    }
    fn tcp_sport() -> TcpPort {
        TcpPort::new_checked(12345).unwrap()
    }
    fn tcp_dport() -> TcpPort {
        TcpPort::new_checked(80).unwrap()
    }
    fn udp_sport() -> UdpPort {
        UdpPort::new_checked(5000).unwrap()
    }
    fn udp_dport() -> UdpPort {
        UdpPort::new_checked(53).unwrap()
    }

    // -- ICMPv4 factory helpers --------------------------------------------

    fn make_icmp4_echo() -> Icmp4 {
        Icmp4(Icmpv4Header::new(Icmpv4Type::EchoRequest(IcmpEchoHeader {
            id: 0xBEEF,
            seq: 1,
        })))
    }

    fn make_icmp4_dest_unreachable() -> Icmp4 {
        Icmp4(Icmpv4Header::new(Icmpv4Type::DestinationUnreachable(
            DestUnreachableHeader::Network,
        )))
    }

    // =====================================================================
    // IPv4 / TCP
    // =====================================================================

    #[test]
    fn ipv4_tcp_roundtrip() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .tcp(tcp_sport(), tcp_dport(), |tcp| {
                tcp.set_syn(true);
            })
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
    }

    #[test]
    fn ipv4_tcp_roundtrip_with_payload() {
        let payload = [0x42u8; 100];
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .build(&payload)
            .unwrap();

        assert_roundtrip(&headers, &payload);
    }

    #[test]
    fn ipv4_tcp_ethtype_is_ipv4() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|_| {})
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .build(&[])
            .unwrap();

        let eth = headers.try_eth().unwrap();
        assert_eq!(eth.ether_type(), EthType::IPV4);
    }

    #[test]
    fn ipv4_tcp_next_header_is_tcp() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|_| {})
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .build(&[])
            .unwrap();

        let ipv4 = headers.try_ipv4().unwrap();
        assert_eq!(ipv4.protocol(), NextHeader::TCP.into());
    }

    #[test]
    fn ipv4_tcp_payload_length_computed() {
        let payload = [0xAAu8; 50];
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .build(&payload)
            .unwrap();

        let ipv4 = headers.try_ipv4().unwrap();
        let expected_total = Ipv4::MIN_LEN.get() + Tcp::MIN_LENGTH.get() + payload.len() as u16;
        assert_eq!(
            ipv4.total_len(),
            expected_total,
            "IPv4 total length should include IP header ({}) + TCP header ({}) + payload ({})",
            Ipv4::MIN_LEN,
            Tcp::MIN_LENGTH,
            payload.len()
        );
    }

    // =====================================================================
    // IPv6 / TCP
    // =====================================================================

    #[test]
    fn ipv6_tcp_roundtrip() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv6(|ip| {
                ip.set_source(test_src_v6());
                ip.set_destination(test_dst_v6());
                ip.set_hop_limit(64);
            })
            .tcp(tcp_sport(), tcp_dport(), |tcp| {
                tcp.set_syn(true);
            })
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
    }

    #[test]
    fn ipv6_tcp_ethtype_is_ipv6() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv6(|_| {})
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .build(&[])
            .unwrap();

        let eth = headers.try_eth().unwrap();
        assert_eq!(eth.ether_type(), EthType::IPV6);
    }

    #[test]
    fn ipv6_tcp_next_header_is_tcp() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv6(|_| {})
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .build(&[])
            .unwrap();

        let ipv6 = headers.try_ipv6().unwrap();
        assert_eq!(ipv6.next_header(), NextHeader::TCP);
    }

    // =====================================================================
    // IPv4 / UDP
    // =====================================================================

    #[test]
    fn ipv4_udp_roundtrip() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .udp(udp_sport(), udp_dport(), |_| {})
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
    }

    #[test]
    fn ipv4_udp_length_computed() {
        let payload = [0xBBu8; 32];
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .udp(udp_sport(), udp_dport(), |_| {})
            .build(&payload)
            .unwrap();

        let udp = headers.try_udp().unwrap();
        let expected_udp_len = Udp::MIN_LENGTH.get() + payload.len() as u16;
        assert_eq!(
            udp.length().get(),
            expected_udp_len,
            "UDP length should be header ({}) + payload ({})",
            Udp::MIN_LENGTH,
            payload.len()
        );
    }

    // =====================================================================
    // IPv6 / UDP
    // =====================================================================

    #[test]
    fn ipv6_udp_roundtrip() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv6(|ip| {
                ip.set_source(test_src_v6());
                ip.set_destination(test_dst_v6());
                ip.set_hop_limit(64);
            })
            .udp(udp_sport(), udp_dport(), |_| {})
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
    }

    // =====================================================================
    // ICMPv4 echo
    // =====================================================================

    #[test]
    fn icmp4_echo_roundtrip() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .icmp4(make_icmp4_echo())
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
    }

    #[test]
    fn icmp4_echo_next_header_is_icmp() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|_| {})
            .icmp4(make_icmp4_echo())
            .build(&[])
            .unwrap();

        let ipv4 = headers.try_ipv4().unwrap();
        assert_eq!(ipv4.protocol(), NextHeader::ICMP.into());
    }

    // =====================================================================
    // ICMPv4 error with embedded headers
    // =====================================================================

    #[test]
    fn icmp4_error_embedded_tcp_roundtrip() {
        let inner_sport = TcpPort::new_checked(9999).unwrap();
        let inner_dport = TcpPort::new_checked(443).unwrap();

        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .icmp4(make_icmp4_dest_unreachable())
            .embedded(|inner| {
                inner
                    .ipv4(|ip| {
                        ip.set_source(
                            UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 100)).unwrap(),
                        );
                        ip.set_destination(Ipv4Addr::new(203, 0, 113, 1));
                        ip.set_ttl(4);
                    })
                    .tcp(inner_sport, inner_dport, |_| {})
            })
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);

        // Verify the outer ICMP header is present
        assert!(headers.try_icmp4().is_some());

        // Verify embedded headers are present
        let embedded = headers.embedded_ip().expect("embedded headers should exist");
        assert!(embedded.net_headers_len() > 0, "embedded net headers should be present");
        assert!(
            embedded.transport_headers_len() > 0,
            "embedded transport headers should be present"
        );
    }

    #[test]
    fn icmp4_error_embedded_udp_roundtrip() {
        let inner_sport = UdpPort::new_checked(5555).unwrap();
        let inner_dport = UdpPort::new_checked(53).unwrap();

        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .icmp4(make_icmp4_dest_unreachable())
            .embedded(|inner| {
                inner
                    .ipv4(|ip| {
                        ip.set_source(
                            UnicastIpv4Addr::new(Ipv4Addr::new(172, 16, 0, 1)).unwrap(),
                        );
                        ip.set_destination(Ipv4Addr::new(8, 8, 8, 8));
                        ip.set_ttl(30);
                    })
                    .udp(inner_sport, inner_dport, |_| {})
            })
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
    }

    #[test]
    fn icmp4_error_payload_length_includes_embedded() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .icmp4(make_icmp4_dest_unreachable())
            .embedded(|inner| {
                inner
                    .ipv4(|ip| {
                        ip.set_source(
                            UnicastIpv4Addr::new(Ipv4Addr::new(1, 2, 3, 4)).unwrap(),
                        );
                        ip.set_destination(Ipv4Addr::new(5, 6, 7, 8));
                    })
                    .tcp(tcp_sport(), tcp_dport(), |_| {})
            })
            .build(&[])
            .unwrap();

        let ipv4 = headers.try_ipv4().unwrap();
        let icmp4 = headers.try_icmp4().unwrap();
        let embedded = headers.embedded_ip().unwrap();

        // IP payload = ICMP header + embedded headers (inner IP + inner TCP)
        let expected_ip_payload =
            icmp4.size().get() + embedded.size().get();
        let expected_total = Ipv4::MIN_LEN.get() + expected_ip_payload;

        assert_eq!(
            ipv4.total_len(),
            expected_total,
            "IPv4 total_len should account for ICMP ({}) + embedded ({})",
            icmp4.size(),
            embedded.size()
        );
    }

    // =====================================================================
    // VXLAN
    // =====================================================================

    #[test]
    fn vxlan_ipv4_roundtrip() {
        let vni = Vni::new_checked(42).unwrap();
        // Dummy inner frame bytes — the builder doesn't parse them
        let inner_frame = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                           0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
                           0x40, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
                           0x05, 0x06, 0x07, 0x08];

        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .udp(udp_sport(), Vxlan::PORT, |_| {})
            .vxlan(vni)
            .build(&inner_frame)
            .unwrap();

        assert_roundtrip(&headers, &inner_frame);

        // Verify VXLAN is present and has the right VNI
        let vxlan = headers.try_vxlan().unwrap();
        assert_eq!(vxlan.vni(), vni);
    }

    #[test]
    fn vxlan_udp_checksum_is_zero() {
        let vni = Vni::new_checked(100).unwrap();
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .udp(udp_sport(), Vxlan::PORT, |_| {})
            .vxlan(vni)
            .build(&[])
            .unwrap();

        let udp = headers.try_udp().unwrap();
        assert_eq!(
            udp.checksum(),
            Some(UdpChecksum::ZERO),
            "VXLAN UDP checksum should be zero per specification"
        );
    }

    #[test]
    fn vxlan_udp_length_includes_inner_frame() {
        let vni = Vni::new_checked(200).unwrap();
        let inner_frame = [0u8; 64];

        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .udp(udp_sport(), Vxlan::PORT, |_| {})
            .vxlan(vni)
            .build(&inner_frame)
            .unwrap();

        let udp = headers.try_udp().unwrap();
        let expected_len =
            Udp::MIN_LENGTH.get() + Vxlan::MIN_LENGTH.get() + inner_frame.len() as u16;
        assert_eq!(
            udp.length().get(),
            expected_len,
            "UDP length = UDP header ({}) + VXLAN header ({}) + inner frame ({})",
            Udp::MIN_LENGTH,
            Vxlan::MIN_LENGTH,
            inner_frame.len()
        );
    }

    // =====================================================================
    // VLAN
    // =====================================================================

    #[test]
    fn single_vlan_roundtrip() {
        let vid = Vid::MIN;

        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .vlan(vid)
            .unwrap()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .tcp(tcp_sport(), tcp_dport(), |tcp| {
                tcp.set_syn(true);
            })
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
        assert_eq!(headers.vlan().len(), 1, "should have exactly one VLAN tag");

        // Eth EthType should be VLAN (push_vlan sets it)
        let eth = headers.try_eth().unwrap();
        assert_eq!(eth.ether_type(), EthType::VLAN);
    }

    #[test]
    fn double_vlan_roundtrip() {
        let vid1 = Vid::new(10).unwrap();
        let vid2 = Vid::new(20).unwrap();

        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .vlan(vid1)
            .unwrap()
            .vlan(vid2)
            .unwrap()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
        assert_eq!(headers.vlan().len(), 2, "should have two VLAN tags");
    }

    // =====================================================================
    // IP-only (no transport)
    // =====================================================================

    #[test]
    fn ip_only_no_transport_roundtrip() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);

        // No transport should be present
        assert!(headers.transport().is_none());
    }

    #[test]
    fn ip_only_with_payload_roundtrip() {
        let payload = [0xCCu8; 200];
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(test_src_v4());
                ip.set_destination(test_dst_v4());
                ip.set_ttl(64);
            })
            .build(&payload)
            .unwrap();

        assert_roundtrip(&headers, &payload);

        let ipv4 = headers.try_ipv4().unwrap();
        let expected_total = Ipv4::MIN_LEN.get() + payload.len() as u16;
        assert_eq!(ipv4.total_len(), expected_total);
    }

    #[test]
    fn ipv6_only_no_transport_roundtrip() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv6(|ip| {
                ip.set_source(test_src_v6());
                ip.set_destination(test_dst_v6());
                ip.set_hop_limit(64);
            })
            .build(&[])
            .unwrap();

        assert_roundtrip(&headers, &[]);
        assert!(headers.transport().is_none());
    }

    // =====================================================================
    // Ethernet defaults
    // =====================================================================

    #[test]
    fn eth_defaults_produces_expected_macs() {
        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|_| {})
            .build(&[])
            .unwrap();

        let eth = headers.try_eth().unwrap();
        assert_eq!(eth.source().inner(), Mac([0x02, 0, 0, 0, 0, 0x01]));
        assert_eq!(eth.destination().inner(), Mac([0x02, 0, 0, 0, 0, 0x02]));
    }

    #[test]
    fn custom_eth_macs() {
        let src = SourceMac::new(Mac([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE])).unwrap();
        let dst = DestinationMac::new(Mac([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])).unwrap();

        let headers = ValidHeadersBuilder::new()
            .eth(src, dst)
            .ipv4(|_| {})
            .build(&[])
            .unwrap();

        let eth = headers.try_eth().unwrap();
        assert_eq!(eth.source().inner(), Mac([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]));
        assert_eq!(eth.destination().inner(), Mac([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]));
    }

    // =====================================================================
    // Error cases
    // =====================================================================

    #[test]
    fn error_icmp4_requires_ipv4() {
        let result = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv6(|_| {})
            .icmp4(make_icmp4_echo())
            .build(&[]);

        assert!(
            matches!(result, Err(ValidHeadersBuildError::Icmp4WithIpv6)),
            "expected Icmp4WithIpv6, got: {result:?}"
        );
    }

    #[test]
    fn error_vxlan_requires_udp() {
        let vni = Vni::new_checked(100).unwrap();
        let result = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|_| {})
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .vxlan(vni)
            .build(&[]);

        assert!(
            matches!(result, Err(ValidHeadersBuildError::VxlanWithoutUdp)),
            "expected VxlanWithoutUdp, got: {result:?}"
        );
    }

    #[test]
    fn error_embedded_requires_icmp() {
        let result = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|_| {})
            .tcp(tcp_sport(), tcp_dport(), |_| {})
            .embedded(|inner| inner.ipv4(|_| {}))
            .build(&[]);

        assert!(
            matches!(result, Err(ValidHeadersBuildError::EmbeddedWithoutIcmp)),
            "expected EmbeddedWithoutIcmp, got: {result:?}"
        );
    }

    #[test]
    fn error_embedded_missing_net() {
        // An embedded assembler with only transport (no IP) is invalid.
        let result = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|_| {})
            .icmp4(make_icmp4_dest_unreachable())
            .embedded(|inner| {
                // Deliberately omit .ipv4() / .ipv6()
                inner
            })
            .build(&[]);

        assert!(
            matches!(result, Err(ValidHeadersBuildError::EmbeddedMissingNet)),
            "expected EmbeddedMissingNet, got: {result:?}"
        );
    }

    #[test]
    fn error_too_many_vlans() {
        let vid = Vid::MIN;
        let result = ValidHeadersBuilder::new()
            .eth_defaults()
            .vlan(vid).unwrap()
            .vlan(vid).unwrap()
            .vlan(vid).unwrap()
            .vlan(vid).unwrap()
            .vlan(vid); // 5th push should fail

        assert!(
            matches!(result, Err(ValidHeadersBuildError::TooManyVlans)),
            "expected TooManyVlans, got: {result:?}"
        );
    }

    // =====================================================================
    // Builder is Debug and Default
    // =====================================================================

    #[test]
    fn builder_is_debug() {
        let builder = ValidHeadersBuilder::new();
        let debug_str = format!("{builder:?}");
        assert!(
            debug_str.contains("ValidHeadersBuilder"),
            "Debug output should contain the type name"
        );
    }

    #[test]
    fn builder_default_is_new() {
        // Just verify it compiles and doesn't panic.
        let _builder = ValidHeadersBuilder::default();
    }

    // =====================================================================
    // Comparison: ValidHeadersBuilder vs manual test_utils construction
    // =====================================================================

    /// This test demonstrates the ergonomic improvement over the manual
    /// approach in `test_utils::build_test_ipv4_packet_with_transport`.
    ///
    /// The manual version is ~30 lines; the builder version is ~10 lines.
    #[test]
    fn comparison_ipv4_tcp_vs_manual() {
        let src = UnicastIpv4Addr::new(Ipv4Addr::new(1, 2, 3, 4)).unwrap();
        let dst = Ipv4Addr::new(5, 6, 7, 8);
        let sport = TcpPort::new_checked(123).unwrap();
        let dport = TcpPort::new_checked(456).unwrap();

        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(src);
                ip.set_destination(dst);
                ip.set_ttl(64);
            })
            .tcp(sport, dport, |tcp| {
                tcp.set_syn(true);
                tcp.set_sequence_number(1);
            })
            .build(&[])
            .unwrap();

        // Verify it produces a complete, valid header set
        assert!(headers.try_eth().is_some());
        assert!(headers.try_ipv4().is_some());
        assert!(headers.try_tcp().is_some());
        assert_roundtrip(&headers, &[]);
    }

    /// This test demonstrates the ergonomic improvement for ICMP error
    /// construction.  Compare with `test_utils::
    /// build_test_icmp4_destination_unreachable_packet` (106 lines).
    #[test]
    fn comparison_icmp4_error_vs_manual() {
        let outer_src = UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 0, 1)).unwrap();
        let outer_dst = Ipv4Addr::new(10, 0, 0, 2);
        let inner_src = UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap();
        let inner_dst = Ipv4Addr::new(172, 16, 0, 1);
        let inner_sport = TcpPort::new_checked(12345).unwrap();
        let inner_dport = TcpPort::new_checked(80).unwrap();

        let headers = ValidHeadersBuilder::new()
            .eth_defaults()
            .ipv4(|ip| {
                ip.set_source(outer_src);
                ip.set_destination(outer_dst);
                ip.set_ttl(64);
            })
            .icmp4(make_icmp4_dest_unreachable())
            .embedded(|inner| {
                inner
                    .ipv4(|ip| {
                        ip.set_source(inner_src);
                        ip.set_destination(inner_dst);
                        ip.set_ttl(4);
                    })
                    .tcp(inner_sport, inner_dport, |_| {})
            })
            .build(&[])
            .unwrap();

        assert!(headers.try_eth().is_some());
        assert!(headers.try_ipv4().is_some());
        assert!(headers.try_icmp4().is_some());
        assert!(headers.embedded_ip().is_some());
        assert_roundtrip(&headers, &[]);
    }
}