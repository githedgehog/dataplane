// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type-carried structural proofs over [`EmbeddedHeaders`].
//!
//! This module mirrors [`window`](super::window) for the inner headers
//! carried in the payload of an ICMP error message.  An embedded shape
//! tuple `U` describes the layer sequence inside an [`EmbeddedHeaders`];
//! the runtime check is performed by
//! [`EmbeddedShape`]'s sealed `matches`, and downstream code recovers
//! typed references via [`EmbeddedLook::look`] without re-validating.
//!
//! Differences from [`window`](super::window):
//!
//! * Embedded shapes begin at the network layer -- there is no Ethernet
//!   or VLAN inside an ICMP error payload, so there is no `vlan_cursor`.
//! * Transport layers are the truncated variants ([`TruncatedTcp`],
//!   [`TruncatedUdp`], [`TruncatedIcmp4`], [`TruncatedIcmp6`]) and the
//!   [`EmbeddedTransport`] enum, because the inner packet may have been
//!   truncated by the ICMP source.
//! * IPv6 extension-header gap-check semantics carry over unchanged via
//!   the embedded variants on [`ExtGapCheck`](super::pat::ExtGapCheck)
//!   (`ext_gap_ok_embedded`).
//!
//! No public surface exposes the matching logic yet; the `EmbeddedWindow`
//! wrapper that closes over a proven outer [`Window`](super::window::Window)
//! and a proven inner shape lands in a follow-up commit.  Until then,
//! these primitives can be exercised directly via the crate-private
//! sealed trait in tests.

#![allow(private_bounds)]
// `EmbeddedShape: embedded_sealed::Sealed` is the seal; external impls are the point we seal against.
#![allow(clippy::inline_always)] // step / accessor scaffolding mirrors `window.rs`; see its module docs.

use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::TruncatedIcmp6;
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::tcp::TruncatedTcp;
use crate::udp::TruncatedUdp;

use super::pat::ExtGapCheck;
use super::{EmbeddedHeaders, EmbeddedStart, EmbeddedTransport, Net, NetExt, Within};

// ===========================================================================
// EmbeddedShape
// ===========================================================================

/// Declared, checkable shapes for embedded ICMP-error payloads.
///
/// Any tuple whose layers chain through the [`Within<T>`] adjacency
/// graph and the [`EmbeddedStep<Pos>`] trait is a valid embedded shape.
/// External crates cannot add new shapes (they cannot implement
/// [`EmbeddedStep`]), but they can write any existing shape at the type
/// level and let the trait bounds do the filtering.
pub trait EmbeddedShape: embedded_sealed::Sealed {}

pub(crate) mod embedded_sealed {
    use super::EmbeddedHeaders;

    pub trait Sealed {
        /// Check that `e`'s structure matches this embedded shape.
        fn matches(e: &EmbeddedHeaders) -> bool;
    }
}

// ===========================================================================
// EmbeddedStep: per-layer extraction with extension-cursor threading
// ===========================================================================
//
// Each `EmbeddedStep<Pos>` impl mirrors the corresponding
// `EmbeddedMatcher` method in `pat.rs`: net-layer steps reset the ext
// cursor; ext-layer steps increment it; transport-layer steps run the
// `ExtGapCheck::ext_gap_ok_embedded` gap check before matching the
// variant.  Because there is no VLAN, the only runtime cursor threaded
// through the chain is `ec`.

/// Crate-private: run a single-layer step of the embedded shape chain.
///
/// `step` returns `Some((&Self, new_ec))` on a hit and `None` when the
/// layer extraction or any gap check fails.  Embedded shapes' sealed
/// `matches` impls call `step` to decide presence;
/// [`EmbeddedLook::look`] (impl'd on [`EmbeddedWindow<W, U>`]) calls
/// the same function and unwraps unchecked under the wrapper's type
/// invariant.
pub(crate) trait EmbeddedStep<Pos>: Sized {
    /// Run this layer's extraction and gap check against the current
    /// cursor state.  Returns `None` on any mismatch.
    fn step(e: &EmbeddedHeaders, ec: u8) -> Option<(&Self, u8)>;
}

// ---- Net layer: match variant, reset ec -----------------------------------

macro_rules! impl_embedded_net_step {
    ($T:ty, $variant:path) => {
        impl<Pos> EmbeddedStep<Pos> for $T
        where
            $T: Within<Pos>,
        {
            #[inline(always)]
            fn step(e: &EmbeddedHeaders, _ec: u8) -> Option<(&$T, u8)> {
                match e.net() {
                    Some($variant(ip)) => Some((ip, 0)),
                    _ => None,
                }
            }
        }
    };
}

impl_embedded_net_step!(Ipv4, Net::Ipv4);
impl_embedded_net_step!(Ipv6, Net::Ipv6);

// Net enum -- returns the &Net itself, no variant filter.
impl<Pos> EmbeddedStep<Pos> for Net
where
    Net: Within<Pos>,
{
    #[inline(always)]
    fn step(e: &EmbeddedHeaders, _ec: u8) -> Option<(&Net, u8)> {
        e.net().map(|n| (n, 0))
    }
}

// ---- Extension headers: advance ec, still in-phase ------------------------

macro_rules! impl_embedded_ext_step {
    ($T:ty, $variant:path) => {
        impl<Pos> EmbeddedStep<Pos> for $T
        where
            $T: Within<Pos>,
        {
            #[inline(always)]
            fn step(e: &EmbeddedHeaders, ec: u8) -> Option<(&$T, u8)> {
                match e.net_ext().get(ec as usize) {
                    Some($variant(v)) => Some((v, ec + 1)),
                    _ => None,
                }
            }
        }
    };
}

impl_embedded_ext_step!(HopByHop, NetExt::HopByHop);
impl_embedded_ext_step!(DestOpts, NetExt::DestOpts);
impl_embedded_ext_step!(Routing, NetExt::Routing);
impl_embedded_ext_step!(Fragment, NetExt::Fragment);
impl_embedded_ext_step!(Ipv4Auth, NetExt::Ipv4Auth);
impl_embedded_ext_step!(Ipv6Auth, NetExt::Ipv6Auth);

// ---- Transport: ExtGapCheck-dispatched strictness, variant match ----------

macro_rules! impl_embedded_transport_step {
    ($T:ty, $variant:path) => {
        impl<Pos> EmbeddedStep<Pos> for $T
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
        {
            #[inline(always)]
            fn step(e: &EmbeddedHeaders, ec: u8) -> Option<(&$T, u8)> {
                if !<Pos as ExtGapCheck>::ext_gap_ok_embedded(e, ec) {
                    return None;
                }
                match e.transport() {
                    Some($variant(t)) => Some((t, ec)),
                    _ => None,
                }
            }
        }
    };
}

impl_embedded_transport_step!(TruncatedTcp, EmbeddedTransport::Tcp);
impl_embedded_transport_step!(TruncatedUdp, EmbeddedTransport::Udp);
impl_embedded_transport_step!(TruncatedIcmp4, EmbeddedTransport::Icmp4);
impl_embedded_transport_step!(TruncatedIcmp6, EmbeddedTransport::Icmp6);

// EmbeddedTransport enum -- returns &EmbeddedTransport itself.
impl<Pos> EmbeddedStep<Pos> for EmbeddedTransport
where
    EmbeddedTransport: Within<Pos>,
    Pos: ExtGapCheck,
{
    #[inline(always)]
    fn step(e: &EmbeddedHeaders, ec: u8) -> Option<(&EmbeddedTransport, u8)> {
        if !<Pos as ExtGapCheck>::ext_gap_ok_embedded(e, ec) {
            return None;
        }
        e.transport().map(|t| (t, ec))
    }
}

// ===========================================================================
// EmbeddedHeaders accessors used by the step impls
// ===========================================================================
//
// These read-only views are kept as small private accessors here so the
// step impls don't need to reach into the (crate-private) fields of
// `EmbeddedHeaders` directly.

impl EmbeddedHeaders {
    #[inline(always)]
    fn net(&self) -> Option<&Net> {
        self.net.as_ref()
    }

    #[inline(always)]
    fn net_ext(&self) -> &[NetExt] {
        &self.net_ext
    }

    #[inline(always)]
    fn transport(&self) -> Option<&EmbeddedTransport> {
        self.transport.as_ref()
    }
}

// ===========================================================================
// Per-arity EmbeddedShape / Sealed impls
// ===========================================================================
//
// Embedded shapes max out at arity 3 in realistic ICMP error payloads
// (net + at most one extension + transport).  If a deeper shape ever
// appears, extend the arity range by adding a new arm below.

macro_rules! impl_embedded_arity_1 {
    ($A:ident) => {
        impl<'x, $A> EmbeddedShape for (&'x $A,) where $A: EmbeddedStep<EmbeddedStart> {}

        impl<'x, $A> embedded_sealed::Sealed for (&'x $A,)
        where
            $A: EmbeddedStep<EmbeddedStart>,
        {
            #[inline(always)]
            fn matches(e: &EmbeddedHeaders) -> bool {
                $A::step(e, 0).is_some()
            }
        }
    };
}

macro_rules! impl_embedded_arity_2 {
    ($A:ident, $B:ident) => {
        impl<'x, $A, $B> EmbeddedShape for (&'x $A, &'x $B)
        where
            $A: EmbeddedStep<EmbeddedStart>,
            $B: EmbeddedStep<$A>,
        {
        }

        impl<'x, $A, $B> embedded_sealed::Sealed for (&'x $A, &'x $B)
        where
            $A: EmbeddedStep<EmbeddedStart>,
            $B: EmbeddedStep<$A>,
        {
            #[inline(always)]
            fn matches(e: &EmbeddedHeaders) -> bool {
                let Some((_, ec)) = $A::step(e, 0) else {
                    return false;
                };
                $B::step(e, ec).is_some()
            }
        }
    };
}

macro_rules! impl_embedded_arity_3 {
    ($A:ident, $B:ident, $C:ident) => {
        impl<'x, $A, $B, $C> EmbeddedShape for (&'x $A, &'x $B, &'x $C)
        where
            $A: EmbeddedStep<EmbeddedStart>,
            $B: EmbeddedStep<$A>,
            $C: EmbeddedStep<$B>,
        {
        }

        impl<'x, $A, $B, $C> embedded_sealed::Sealed for (&'x $A, &'x $B, &'x $C)
        where
            $A: EmbeddedStep<EmbeddedStart>,
            $B: EmbeddedStep<$A>,
            $C: EmbeddedStep<$B>,
        {
            #[inline(always)]
            fn matches(e: &EmbeddedHeaders) -> bool {
                let Some((_, ec)) = $A::step(e, 0) else {
                    return false;
                };
                let Some((_, ec)) = $B::step(e, ec) else {
                    return false;
                };
                $C::step(e, ec).is_some()
            }
        }
    };
}

impl_embedded_arity_1!(A);
impl_embedded_arity_2!(A, B);
impl_embedded_arity_3!(A, B, C);

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::Headers;
    use crate::headers::builder::{HeaderStack, header_chain};

    /// Convenience: run the sealed `matches` for shape `U` against `e`.
    #[inline]
    fn matches<U>(e: &EmbeddedHeaders) -> bool
    where
        U: EmbeddedShape,
    {
        <U as embedded_sealed::Sealed>::matches(e)
    }

    /// Build an outer ICMP-error packet carrying the supplied embedded
    /// builder fragment, return its parsed [`Headers`].
    fn icmp4_with_embedded<F>(f: F) -> Headers
    where
        F: FnOnce(
            super::super::builder::EmbeddedAssembler,
        ) -> super::super::builder::EmbeddedAssembler,
    {
        HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .icmp4(|_| {})
            .dest_unreachable(|_| {})
            .embedded(f)
            .build_headers()
            .unwrap()
    }

    fn icmp6_with_embedded<F>(f: F) -> Headers
    where
        F: FnOnce(
            super::super::builder::EmbeddedAssembler,
        ) -> super::super::builder::EmbeddedAssembler,
    {
        HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .icmp6(|_| {})
            .dest_unreachable6(|_| {})
            .embedded(f)
            .build_headers()
            .unwrap()
    }

    // ---- Positive: arity 2 (net + transport) -------------------------------

    #[test]
    fn ipv4_truncated_tcp_matches_full_inner_packet() {
        use crate::tcp::TcpPort;
        let h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let e = h.embedded_ip().expect("embedded must be present");
        assert!(matches::<(&Ipv4, &TruncatedTcp)>(e));
    }

    #[test]
    fn ipv6_truncated_udp_matches_full_inner_packet() {
        use crate::udp::UdpPort;
        let h = icmp6_with_embedded(|a| {
            a.ipv6(|_| {}).udp(
                UdpPort::new_checked(53).unwrap(),
                UdpPort::new_checked(53).unwrap(),
                |_| {},
            )
        });
        let e = h.embedded_ip().expect("embedded must be present");
        assert!(matches::<(&Ipv6, &TruncatedUdp)>(e));
    }

    // ---- Wrong variant is a miss ------------------------------------------

    #[test]
    fn wrong_inner_transport_misses() {
        use crate::tcp::TcpPort;
        let h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let e = h.embedded_ip().unwrap();
        assert!(matches::<(&Ipv4, &TruncatedTcp)>(e));
        assert!(!matches::<(&Ipv4, &TruncatedUdp)>(e));
    }

    #[test]
    fn wrong_inner_net_misses() {
        use crate::tcp::TcpPort;
        let h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let e = h.embedded_ip().unwrap();
        assert!(!matches::<(&Ipv6, &TruncatedTcp)>(e));
    }

    // ---- Net-only inner shape (arity 1) -----------------------------------

    #[test]
    fn ipv4_only_inner_matches_minimal_payload() {
        let h = icmp4_with_embedded(|a| a.ipv4(|_| {}));
        let e = h.embedded_ip().unwrap();
        assert!(matches::<(&Ipv4,)>(e));
        assert!(matches::<(&Net,)>(e));
        assert!(!matches::<(&Ipv6,)>(e));
    }

    // ---- Cross-consistency with pat.rs `.embedded()` ----------------------

    #[test]
    fn ipv4_tcp_inner_agrees_with_pat_matcher() {
        use crate::tcp::TcpPort;
        let plain = header_chain()
            .eth(|_| {})
            .ipv4(|_| {})
            .icmp4(|_| {})
            .dest_unreachable(|_| {})
            .embed_ipv4(|_| {})
            .embed_tcp(|tcp| {
                tcp.set_destination(TcpPort::new_checked(80).unwrap());
            });
        bolero::check!()
            .with_generator(plain)
            .for_each(|h: &Headers| {
                let pat_hit = h
                    .pat()
                    .eth()
                    .ipv4()
                    .icmp4()
                    .embedded()
                    .ipv4()
                    .tcp()
                    .done()
                    .is_some();
                let win_hit = h
                    .embedded_ip()
                    .is_some_and(matches::<(&Ipv4, &TruncatedTcp)>);
                assert_eq!(
                    pat_hit, win_hit,
                    "EmbeddedShape disagrees with pat.rs .embedded() chain"
                );
            });
    }

    #[test]
    fn ipv6_udp_inner_agrees_with_pat_matcher() {
        let chain = header_chain()
            .eth(|_| {})
            .ipv6(|_| {})
            .icmp6(|_| {})
            .dest_unreachable6(|_| {})
            .embed_ipv6(|_| {})
            .embed_udp(|_| {});
        bolero::check!()
            .with_generator(chain)
            .for_each(|h: &Headers| {
                let pat_hit = h
                    .pat()
                    .eth()
                    .ipv6()
                    .icmp6()
                    .embedded()
                    .ipv6()
                    .udp()
                    .done()
                    .is_some();
                let win_hit = h
                    .embedded_ip()
                    .is_some_and(matches::<(&Ipv6, &TruncatedUdp)>);
                assert_eq!(pat_hit, win_hit);
            });
    }

    // Variant mismatch must agree across APIs: outer matcher hits but
    // the requested embedded transport variant is wrong, both APIs must
    // report a miss.
    #[test]
    fn ipv4_tcp_shape_against_udp_inner_misses_consistently() {
        let chain = header_chain()
            .eth(|_| {})
            .ipv4(|_| {})
            .icmp4(|_| {})
            .dest_unreachable(|_| {})
            .embed_ipv4(|_| {})
            .embed_udp(|_| {});
        bolero::check!()
            .with_generator(chain)
            .for_each(|h: &Headers| {
                let pat_tcp = h
                    .pat()
                    .eth()
                    .ipv4()
                    .icmp4()
                    .embedded()
                    .ipv4()
                    .tcp()
                    .done()
                    .is_some();
                let win_tcp = h
                    .embedded_ip()
                    .is_some_and(matches::<(&Ipv4, &TruncatedTcp)>);
                assert!(!pat_tcp, "pat.rs must miss TCP when inner is UDP");
                assert!(!win_tcp, "EmbeddedShape must miss TCP when inner is UDP");
                assert_eq!(pat_tcp, win_tcp);
            });
    }
}
