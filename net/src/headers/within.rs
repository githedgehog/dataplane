// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Layer-ordering constraints for the network header stack.
//!
//! [`Within<T>`] encodes which header type may directly follow which other
//! header type in a well-formed packet.  The trait serves two purposes:
//!
//! 1. **Compile-time ordering** -- used as a bound on generic builder and
//!    matcher methods so that invalid layer transitions are compile errors.
//! 2. **Parent conformance** -- [`Within::conform`] adjusts structural fields
//!    on a parent header to be consistent with a given child (e.g. setting
//!    `EthType::IPV4` on an Ethernet header when IPv4 is stacked on top).
//!
//! Absence of an `impl Within<T> for U` means "U cannot directly follow T",
//! which the compiler enforces automatically.

use super::{Net, Transport};
use crate::checksum::Checksum;
use crate::eth::Eth;
use crate::eth::ethtype::EthType;
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::ip::NextHeader;
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::tcp::Tcp;
use crate::udp::{Udp, UdpChecksum};
use crate::vlan::Vlan;
use crate::vxlan::Vxlan;

/// Declares that `Self` is a valid child of layer `T`.
///
/// This trait serves two purposes:
///
/// 1. **Compile-time ordering** -- used as a bound on builder and matcher
///    methods so that invalid layer transitions are compile errors.
/// 2. **Parent conformance** -- [`conform`](Within::conform) adjusts
///    structural fields on the parent to be consistent with the child
///    (e.g. setting `EthType::IPV4` on an Ethernet header when IPv4 is
///    stacked on top).
///
/// Conformance is called automatically by `HeaderStack::stack` before
/// the parent is installed into [`Headers`](super::Headers).
///
/// # Enum-level impls
///
/// Some impls exist for enum types ([`Net`], [`Transport`],
/// [`EmbeddedTransport`]) with no-op [`conform`](Within::conform) bodies.
/// These serve the pattern matcher ([`pat`](super::pat)) only -- they let
/// callers write `.net().tcp()` to match "any IP version followed by TCP"
/// without committing to IPv4 vs IPv6.
///
/// The builder is safe from these impls because `HeaderStack::stack`
/// additionally requires `Blank`, which is not implemented for enum
/// types.  Attempting to stack `Net` or `Transport` directly in the
/// builder is a compile error.
pub trait Within<T> {
    /// Adjust `parent` so its protocol/type fields are consistent with `Self`.
    fn conform(parent: &mut T);
}

// ---- Eth (entry layer) ----------------------------------------------------

impl Within<()> for Eth {
    fn conform(_parent: &mut ()) {}
}

// ---- Vlan -----------------------------------------------------------------

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

// ---- Ipv4 -----------------------------------------------------------------

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

// ---- Ipv6 -----------------------------------------------------------------

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

// ---- Transport after IP ---------------------------------------------------

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

// ---- UDP encapsulation ----------------------------------------------------

impl Within<Udp> for Vxlan {
    fn conform(parent: &mut Udp) {
        let _ = parent.set_checksum(UdpChecksum::ZERO);
        parent.set_destination(Vxlan::PORT);
    }
}

// ---------------------------------------------------------------------------
// IPv6 extension headers (RFC 8200 section 4.1 ordering)
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

// ---------------------------------------------------------------------------
// EmbeddedHeaders -- follows ICMP error messages
// ---------------------------------------------------------------------------

use super::{EmbeddedHeaders, EmbeddedTransport};
use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::TruncatedIcmp6;
use crate::tcp::TruncatedTcp;
use crate::udp::TruncatedUdp;

/// Marker type for the starting position of an [`EmbeddedMatcher`].
///
/// Embedded headers begin at the network layer (no Eth, no VLAN), so
/// `Within<EmbeddedStart>` is implemented for Ipv4, Ipv6, and Net.
pub struct EmbeddedStart;

impl Within<EmbeddedStart> for Ipv4 {
    fn conform(_parent: &mut EmbeddedStart) {}
}
impl Within<EmbeddedStart> for Ipv6 {
    fn conform(_parent: &mut EmbeddedStart) {}
}
impl Within<EmbeddedStart> for Net {
    fn conform(_parent: &mut EmbeddedStart) {}
}

impl Within<Icmp4> for EmbeddedHeaders {
    fn conform(_parent: &mut Icmp4) {}
}

impl Within<Icmp6> for EmbeddedHeaders {
    fn conform(_parent: &mut Icmp6) {}
}

// -- Truncated transport types (inside EmbeddedHeaders) --
// Same Within graph as the full transport types, but for TruncatedTcp etc.
// conform is no-op (these are never used in the builder).

macro_rules! impl_truncated_within {
    ($T:ty, [$($Parent:ty),*]) => {$(
        impl Within<$Parent> for $T {
            fn conform(_parent: &mut $Parent) {}
        }
    )*};
}

impl_truncated_within!(
    TruncatedTcp,
    [
        Ipv4, Ipv6, Net, HopByHop, DestOpts, Routing, Fragment, Ipv4Auth, Ipv6Auth
    ]
);
impl_truncated_within!(
    TruncatedUdp,
    [
        Ipv4, Ipv6, Net, HopByHop, DestOpts, Routing, Fragment, Ipv4Auth, Ipv6Auth
    ]
);
impl_truncated_within!(TruncatedIcmp4, [Ipv4, Ipv4Auth]);
impl_truncated_within!(
    TruncatedIcmp6,
    [Ipv6, HopByHop, DestOpts, Routing, Fragment, Ipv6Auth]
);

// EmbeddedTransport enum -- same positions as Transport
impl_truncated_within!(
    EmbeddedTransport,
    [
        Ipv4, Ipv6, Net, HopByHop, DestOpts, Routing, Fragment, Ipv4Auth, Ipv6Auth
    ]
);

// ---------------------------------------------------------------------------
// Enum-level impls for the pattern matcher
// ---------------------------------------------------------------------------
//
// These allow the pattern matcher to return `&Net` or `&Transport` directly
// so callers can branch on the variant themselves (e.g. `.net().tcp()`
// matches "any IP version followed by TCP").
//
// The `conform` bodies are no-ops because the correct protocol field
// depends on the runtime variant, which is unavailable in the static
// `conform` context.
//
// Safety from builder misuse: `HeaderStack::stack` requires `Blank`,
// which is NOT implemented for these enum types.  Attempting to stack
// `Net` or `Transport` in the builder is a compile error.

// -- Net: valid after Eth or Vlan (same positions as Ipv4/Ipv6) --

impl Within<Eth> for Net {
    fn conform(_parent: &mut Eth) {}
}

impl Within<Vlan> for Net {
    fn conform(_parent: &mut Vlan) {}
}

// -- Transport: valid after any IP or extension header --

impl Within<Ipv4> for Transport {
    fn conform(_parent: &mut Ipv4) {}
}

impl Within<Ipv6> for Transport {
    fn conform(_parent: &mut Ipv6) {}
}

impl Within<Net> for Transport {
    fn conform(_parent: &mut Net) {}
}

impl Within<HopByHop> for Transport {
    fn conform(_parent: &mut HopByHop) {}
}

impl Within<DestOpts> for Transport {
    fn conform(_parent: &mut DestOpts) {}
}

impl Within<Routing> for Transport {
    fn conform(_parent: &mut Routing) {}
}

impl Within<Fragment> for Transport {
    fn conform(_parent: &mut Fragment) {}
}

impl Within<Ipv4Auth> for Transport {
    fn conform(_parent: &mut Ipv4Auth) {}
}

impl Within<Ipv6Auth> for Transport {
    fn conform(_parent: &mut Ipv6Auth) {}
}

// -- Concrete transport types after Net (valid for both IPv4 and IPv6) --
// Icmp4 and Icmp6 are NOT Within<Net> because they are version-specific.

impl Within<Net> for Tcp {
    fn conform(_parent: &mut Net) {}
}

impl Within<Net> for Udp {
    fn conform(_parent: &mut Net) {}
}
