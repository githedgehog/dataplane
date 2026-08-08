// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type-carried structural proofs over [`EmbeddedHeaders`].
//!
//! This module mirrors [`view`](super::view) for the inner headers
//! carried in the payload of an ICMP error message.  An embedded shape
//! tuple `U` describes the layer sequence inside an [`EmbeddedHeaders`];
//! the runtime check is performed by
//! [`EmbeddedShape`]'s sealed `matches`, and downstream code recovers
//! typed references via [`EmbeddedLook::look`] without re-validating.
//!
//! Differences from [`view`](super::view):
//!
//! * Embedded shapes begin at the network layer -- there is no Ethernet
//!   or VLAN inside an ICMP error payload, so there is no `vlan_cursor`.
//! * Transport layers are the truncated variants ([`TruncatedTcp`],
//!   [`TruncatedUdp`], [`TruncatedIcmp4`], [`TruncatedIcmp6`]) and the
//!   [`EmbeddedTransport`] enum, because the inner packet may have been
//!   truncated by the ICMP source.
//! * IPv6 extension-header gap-check semantics carry over unchanged via
//!   the embedded variants on [`ExtGapCheck`]
//!   (`ext_gap_ok_embedded`).
//!
//! [`EmbeddedHeadersView<W, U>`] is the type-level qualifier that closes
//! over a proven outer encapsulator `W` (today: [`HeadersView<T>`]) and a
//! proven inner embedded shape `U`.  It is `repr(transparent)` over
//! `W`, so a `&HeadersView<T>` can be re-borrowed as a
//! `&EmbeddedHeadersView<HeadersView<T>, U>` after a single shape check, and
//! [`EmbeddedHeadersView::outer`] re-borrows back to `&W` for free.
//!
//! Construction goes through [`HeadersView::as_embedded`], which is gated
//! per outer arity by `EmbeddedHeaders: Within<LastLayer>` -- in
//! practice that bound restricts the call site to outer shapes
//! ending in [`Icmp4`](crate::icmp4::Icmp4) or
//! [`Icmp6`](crate::icmp6::Icmp6).
//!
//! [`EmbeddedLook::look`] returns the inner refs only.  Walk back
//! through `outer()` if you also need the encapsulating layers.

#![allow(private_bounds)]
// `EmbeddedShape: embedded_sealed::Sealed` is the seal; external impls are the point we seal against.
#![allow(unsafe_code, clippy::inline_always)] // scaffolding mirrors `view.rs`; see its module docs.

use core::marker::PhantomData;

use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::TruncatedIcmp6;
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::tcp::TruncatedTcp;
use crate::udp::TruncatedUdp;

use super::pat::{EmbeddedMatcherMut, ExtGapCheck, TupleAppend};
use super::view::{HeadersView, Shape};
use super::{EmbeddedHeaders, EmbeddedStart, EmbeddedTransport, Headers, Net, NetExt, Within};

// ===========================================================================
// EmbeddedShape
// ===========================================================================

/// Declared, checkable shapes for embedded ICMP-error payloads.
///
/// Any tuple whose layers chain through the [`Within<T>`] adjacency
/// graph and the `EmbeddedStep<Pos>` trait is a valid embedded shape.
/// External crates cannot add new shapes (they cannot implement
/// `EmbeddedStep`), but they can write any existing shape at the type
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
/// [`EmbeddedLook::look`] (impl'd on [`EmbeddedHeadersView<W, U>`]) calls
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
// EmbeddedStepMut: mutable per-layer dispatch onto pat::EmbeddedMatcherMut
// ===========================================================================
//
// Mirrors [`EmbeddedStep`] but for the mutable side, dispatching through
// [`pat::EmbeddedMatcherMut`].  Each impl is a one-liner delegating to
// the matching `EmbeddedMatcherMut` method (`.ipv4()`, `.tcp()`, ...);
// reusing `EmbeddedMatcherMut` lets us share its pre-split
// [`pat::EmbeddedFields`] aliasing solution rather than reimplementing
// disjoint mut access into [`EmbeddedHeaders`] here.

/// Crate-private: extend an [`EmbeddedMatcherMut`] chain by one layer.
pub(crate) trait EmbeddedStepMut<Pos>: Sized {
    /// Chain this layer onto `m`.
    fn chain<'a, OAcc, IAcc>(
        m: EmbeddedMatcherMut<'a, Pos, OAcc, IAcc>,
    ) -> EmbeddedMatcherMut<'a, Self, OAcc, <IAcc as TupleAppend<&'a mut Self>>::Output>
    where
        IAcc: TupleAppend<&'a mut Self>;
}

// ---- Net layer (Ipv4 / Ipv6) and Net enum ---------------------------------

macro_rules! impl_embedded_net_step_mut {
    ($T:ty, $method:ident) => {
        impl<Pos> EmbeddedStepMut<Pos> for $T
        where
            $T: Within<Pos>,
        {
            #[inline(always)]
            fn chain<'a, OAcc, IAcc>(
                m: EmbeddedMatcherMut<'a, Pos, OAcc, IAcc>,
            ) -> EmbeddedMatcherMut<'a, $T, OAcc, <IAcc as TupleAppend<&'a mut $T>>::Output>
            where
                IAcc: TupleAppend<&'a mut $T>,
            {
                m.$method()
            }
        }
    };
}

impl_embedded_net_step_mut!(Ipv4, ipv4);
impl_embedded_net_step_mut!(Ipv6, ipv6);
impl_embedded_net_step_mut!(Net, net);

// ---- Extension headers ----------------------------------------------------

macro_rules! impl_embedded_ext_step_mut {
    ($T:ty, $method:ident) => {
        impl<Pos> EmbeddedStepMut<Pos> for $T
        where
            $T: Within<Pos>,
        {
            #[inline(always)]
            fn chain<'a, OAcc, IAcc>(
                m: EmbeddedMatcherMut<'a, Pos, OAcc, IAcc>,
            ) -> EmbeddedMatcherMut<'a, $T, OAcc, <IAcc as TupleAppend<&'a mut $T>>::Output>
            where
                IAcc: TupleAppend<&'a mut $T>,
            {
                m.$method()
            }
        }
    };
}

impl_embedded_ext_step_mut!(HopByHop, hop_by_hop);
impl_embedded_ext_step_mut!(DestOpts, dest_opts);
impl_embedded_ext_step_mut!(Routing, routing);
impl_embedded_ext_step_mut!(Fragment, fragment);
impl_embedded_ext_step_mut!(Ipv4Auth, ipv4_auth);
impl_embedded_ext_step_mut!(Ipv6Auth, ipv6_auth);

// ---- Truncated transport layers -------------------------------------------

macro_rules! impl_embedded_transport_step_mut {
    ($T:ty, $method:ident) => {
        impl<Pos> EmbeddedStepMut<Pos> for $T
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
        {
            #[inline(always)]
            fn chain<'a, OAcc, IAcc>(
                m: EmbeddedMatcherMut<'a, Pos, OAcc, IAcc>,
            ) -> EmbeddedMatcherMut<'a, $T, OAcc, <IAcc as TupleAppend<&'a mut $T>>::Output>
            where
                IAcc: TupleAppend<&'a mut $T>,
            {
                m.$method()
            }
        }
    };
}

impl_embedded_transport_step_mut!(TruncatedTcp, tcp);
impl_embedded_transport_step_mut!(TruncatedUdp, udp);
impl_embedded_transport_step_mut!(TruncatedIcmp4, icmp4);
impl_embedded_transport_step_mut!(TruncatedIcmp6, icmp6);

// EmbeddedTransport enum -- delegates to EmbeddedMatcherMut::transport.
impl<Pos> EmbeddedStepMut<Pos> for EmbeddedTransport
where
    EmbeddedTransport: Within<Pos>,
    Pos: ExtGapCheck,
{
    #[inline(always)]
    fn chain<'a, OAcc, IAcc>(
        m: EmbeddedMatcherMut<'a, Pos, OAcc, IAcc>,
    ) -> EmbeddedMatcherMut<
        'a,
        EmbeddedTransport,
        OAcc,
        <IAcc as TupleAppend<&'a mut EmbeddedTransport>>::Output,
    >
    where
        IAcc: TupleAppend<&'a mut EmbeddedTransport>,
    {
        m.transport()
    }
}

// ===========================================================================
// EmbeddedHeaders accessors used by the step impls
// ===========================================================================
//
// These read-only views are kept as small crate-private accessors here so the
// step impls don't need to reach into the (crate-private) fields of
// `EmbeddedHeaders` directly.

impl EmbeddedHeaders {
    #[inline(always)]
    pub(crate) fn net(&self) -> Option<&Net> {
        self.net.as_ref()
    }

    #[inline(always)]
    pub(crate) fn net_ext(&self) -> &[NetExt] {
        &self.net_ext
    }

    #[inline(always)]
    pub(crate) fn transport(&self) -> Option<&EmbeddedTransport> {
        self.transport.as_ref()
    }
}

// ===========================================================================
// EmbeddedHeadersView<W, U> + the cd-up trait
// ===========================================================================

/// Crate-private contract: implementor refers to a packet's [`Headers`].
///
/// Used by [`EmbeddedHeadersView`] to navigate from a generic outer
/// encapsulator `W` down to the underlying [`Headers`] (and from there
/// to the embedded sub-section).  Today only [`HeadersView<T>`] implements
/// this trait, but future encapsulator wrappers (Geneve, Vxlan, ...)
/// will impl it the same way, letting `EmbeddedHeadersView` work uniformly
/// over any "proven outer" type without per-W look impls.
pub(crate) trait HasHeaders {
    fn as_headers(&self) -> &Headers;
}

impl<T> HasHeaders for HeadersView<T> {
    #[inline(always)]
    fn as_headers(&self) -> &Headers {
        // HeadersView<T> is repr(transparent) over Headers; pat_mut/pat
        // expose the same via &self.0.  Use the existing pub(crate)
        // accessor to avoid re-implementing the cast here.
        HeadersView::as_headers(self)
    }
}

/// Mutable counterpart of [`HasHeaders`].
///
/// Implementors expose `&mut Headers` for embedded mutable extraction.
/// Today only [`HeadersView<T>`] implements this trait; same future-proofing
/// rationale as [`HasHeaders`].
pub(crate) trait HasHeadersMut: HasHeaders {
    fn as_headers_mut(&mut self) -> &mut Headers;
}

impl<T> HasHeadersMut for HeadersView<T> {
    #[inline(always)]
    fn as_headers_mut(&mut self) -> &mut Headers {
        HeadersView::as_headers_mut(self)
    }
}

/// A type-level qualifier that closes over a proven outer encapsulator
/// `W` and a proven inner [`EmbeddedShape`] `U`.
///
/// `EmbeddedHeadersView<W, U>` is `#[repr(transparent)]` over `W`, so a
/// `&EmbeddedHeadersView<W, U>` is layout-equivalent to a `&W` and the
/// [`outer`](Self::outer) re-borrow is a free reinterpret.
///
/// Today the only outer in use is [`HeadersView<T>`]; future encapsulator
/// types (Geneve, Vxlan, nested embedded) will compose the same way:
/// `EmbeddedHeadersView<GeneveWindow<HeadersView<T>, V>, U>` etc.  The recursive
/// narrowing pattern means each level of encapsulation adds one
/// type-level qualifier without mutating the layers below.
///
/// Construction goes through [`HeadersView::as_embedded`].  There is no
/// owning constructor; private fields and the per-arity construction
/// path together prevent forging an instance with a `U` proof that
/// doesn't actually hold.
///
/// # Soundness
///
/// The `compile_fail` examples below lock in the rules that keep
/// `EmbeddedHeadersView<W, U>` sound, mirroring the soundness doctests on
/// [`HeadersView`].
///
/// ## No owning constructor
///
/// Private fields prevent forging an `EmbeddedHeadersView<W, U>` from an
/// arbitrary `W` (E0423).  The only entry point
/// ([`HeadersView::as_embedded`]) runs
/// [`embedded_sealed::Sealed::matches`](EmbeddedShape) before handing
/// out a reference.
///
/// ```compile_fail,E0423
/// use dataplane_net::eth::Eth;
/// use dataplane_net::ipv4::Ipv4;
/// use dataplane_net::tcp::TruncatedTcp;
/// use dataplane_net::headers::{EmbeddedHeadersView, Headers, HeadersView};
/// let h = Headers::default();
/// let w: &HeadersView<(&Eth,)> = h.as_view().unwrap();
/// let _ew: EmbeddedHeadersView<&HeadersView<(&Eth,)>, (&Ipv4, &TruncatedTcp)> =
///     EmbeddedHeadersView(w, std::marker::PhantomData);
/// ```
///
/// ## `EmbeddedHeadersView<W, U>` is not [`Clone`]
///
/// Same rationale as [`HeadersView<T>`]: cloning through a reference would
/// produce an owned proven value that bypasses the borrow lifecycle
/// (E0277: `EmbeddedHeadersView<W, U>: Clone` unsatisfied).
///
/// ```compile_fail,E0277
/// use dataplane_net::eth::Eth;
/// use dataplane_net::icmp4::Icmp4;
/// use dataplane_net::ipv4::Ipv4;
/// use dataplane_net::tcp::TruncatedTcp;
/// use dataplane_net::headers::{EmbeddedHeadersView, Headers, HeadersView};
/// fn clone_it<T: Clone>(x: &T) -> T { x.clone() }
/// let h = Headers::default();
/// let outer: &HeadersView<(&Eth, &Ipv4, &Icmp4)> = h.as_view().unwrap();
/// let ew = outer.as_embedded::<(&Ipv4, &TruncatedTcp)>().unwrap();
/// let _owned: EmbeddedHeadersView<HeadersView<(&Eth, &Ipv4, &Icmp4)>, (&Ipv4, &TruncatedTcp)> =
///     clone_it(ew);
/// ```
///
/// ## No `as_embedded` on outer shapes that don't end in ICMP
///
/// `as_embedded` is only available on outer windows whose final layer
/// is one for which `EmbeddedHeaders: Within<LastLayer>` holds (i.e.
/// `Icmp4` or `Icmp6`).  A plain `(Eth, Ipv4, Tcp)` outer cannot reach
/// `as_embedded` (E0599: method not found).
///
/// ```compile_fail,E0599
/// use dataplane_net::eth::Eth;
/// use dataplane_net::ipv4::Ipv4;
/// use dataplane_net::tcp::{Tcp, TruncatedTcp};
/// use dataplane_net::headers::{Headers, HeadersView};
/// let h = Headers::default();
/// let w: &HeadersView<(&Eth, &Ipv4, &Tcp)> = h.as_view().unwrap();
/// let _ew = w.as_embedded::<(&Ipv4, &TruncatedTcp)>();
/// ```
#[repr(transparent)]
pub struct EmbeddedHeadersView<W, U>(W, PhantomData<U>);

impl<W, U> EmbeddedHeadersView<W, U> {
    /// Re-borrow this qualifier as the encapsulating outer.
    ///
    /// This is the `cd ..` of the encapsulation lattice -- a free
    /// reinterpret of the same allocation, since
    /// `EmbeddedHeadersView<W, U>` is `#[repr(transparent)]` over `W`.
    /// The `U` proof is dropped; the `W` proof is preserved.
    #[inline(always)]
    #[must_use]
    pub fn outer(&self) -> &W {
        // SAFETY: EmbeddedHeadersView<W, U> is repr(transparent) over W,
        // so a &EmbeddedHeadersView<W, U> and a &W have identical layout.
        // Dropping the U-side phantom does not change the W proof.
        let p = std::ptr::from_ref(self).cast::<W>();
        unsafe { p.as_ref_unchecked() }
    }

    /// Mutable counterpart of [`Self::outer`].
    ///
    /// Same `repr(transparent)` reborrow, exclusive variant.
    #[inline(always)]
    #[must_use]
    pub fn outer_mut(&mut self) -> &mut W {
        // SAFETY: same as outer(), exclusive borrow preserved.
        let p = std::ptr::from_mut(self).cast::<W>();
        unsafe { p.as_mut_unchecked() }
    }
}

// ===========================================================================
// EmbeddedLook
// ===========================================================================

/// Extract typed references to the layers an [`EmbeddedHeadersView`] holds.
///
/// Implemented for each valid inner shape tuple `U`.  Returns refs to
/// the *inner* layers only -- to also see the encapsulating layers,
/// re-borrow via [`EmbeddedHeadersView::outer`] and call
/// [`Look::look`](super::view::Look::look) on it.
pub trait EmbeddedLook<U> {
    /// The tuple of typed references produced by [`Self::look`].
    type Refs<'a>
    where
        Self: 'a;

    /// Extract typed references to the matched inner layers.
    ///
    /// Compiles to the same sequence of variant reads as
    /// `embedded_sealed::Sealed::matches`, plus `unwrap_unchecked`
    /// at each step; the `EmbeddedHeadersView<W, U>` type invariant
    /// guarantees success so the `None` branches are pruned by the
    /// optimizer.
    fn look<'a>(&'a self) -> Self::Refs<'a>
    where
        Self: 'a;
}

/// Mutable counterpart of [`EmbeddedLook`].
///
/// Yields a tuple of `&mut` references to the matched inner layers.
/// Aliasing between the returned references is handled by
/// [`pat::EmbeddedMatcherMut`](super::pat::EmbeddedMatcherMut)'s pre-split
/// fields helper -- `look_mut` delegates to an `EmbeddedMatcherMut`
/// chain (built directly from the embedded section, bypassing the
/// outer chain) and unwraps the chain's `Option<((), inner)>`
/// unchecked under the `EmbeddedHeadersView<W, U>` shape invariant.
pub trait EmbeddedLookMut<U> {
    /// The tuple of typed `&mut` references produced by [`Self::look_mut`].
    type RefsMut<'a>
    where
        Self: 'a;

    /// Extract typed `&mut` references to the matched inner layers.
    fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
    where
        Self: 'a;
}

// ===========================================================================
// Per-arity EmbeddedShape / Sealed / EmbeddedLook impls
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

        impl<'x, W, $A> EmbeddedLook<(&'x $A,)> for EmbeddedHeadersView<W, (&'x $A,)>
        where
            W: HasHeaders,
            $A: EmbeddedStep<EmbeddedStart>,
            Self: 'x,
        {
            type Refs<'a>
                = (&'a $A,)
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                let h = self.outer().as_headers();
                // SAFETY: EmbeddedHeadersView invariant: outer's embedded_ip is Some
                // and matches() was true on it at construction.
                let e = unsafe { h.embedded_ip().unwrap_unchecked() };
                unsafe {
                    core::hint::assert_unchecked(<(&'x $A,) as embedded_sealed::Sealed>::matches(
                        e,
                    ));
                    let (a, _) = $A::step(e, 0).unwrap_unchecked();
                    (a,)
                }
            }
        }

        impl<'x, W, $A> EmbeddedLookMut<(&'x $A,)> for EmbeddedHeadersView<W, (&'x $A,)>
        where
            W: HasHeadersMut,
            $A: EmbeddedStep<EmbeddedStart> + EmbeddedStepMut<EmbeddedStart>,
            Self: 'x,
        {
            type RefsMut<'a>
                = (&'a mut $A,)
            where
                Self: 'a;

            #[inline(always)]
            fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
            where
                Self: 'a,
            {
                let h = self.outer_mut().as_headers_mut();
                // SAFETY: EmbeddedHeadersView invariant.
                let e = unsafe { h.embedded_ip_mut().unwrap_unchecked() };
                let m = EmbeddedMatcherMut::from_embedded_only(e);
                let m = <$A as EmbeddedStepMut<EmbeddedStart>>::chain(m);
                // .done() on EmbeddedMatcherMut returns OuterAcc.append(InnerAcc);
                // OuterAcc = (), so we get ((InnerAcc,)).
                match m.done() {
                    Some(((a,),)) => (a,),
                    // SAFETY: EmbeddedHeadersView invariant guarantees the chain hits.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
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

        impl<'x, W, $A, $B> EmbeddedLook<(&'x $A, &'x $B)>
            for EmbeddedHeadersView<W, (&'x $A, &'x $B)>
        where
            W: HasHeaders,
            $A: EmbeddedStep<EmbeddedStart>,
            $B: EmbeddedStep<$A>,
            Self: 'x,
        {
            type Refs<'a>
                = (&'a $A, &'a $B)
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                let h = self.outer().as_headers();
                // SAFETY: EmbeddedHeadersView invariant.
                let e = unsafe { h.embedded_ip().unwrap_unchecked() };
                unsafe {
                    core::hint::assert_unchecked(
                        <(&'x $A, &'x $B) as embedded_sealed::Sealed>::matches(e),
                    );
                    let (a, ec) = $A::step(e, 0).unwrap_unchecked();
                    let (b, _) = $B::step(e, ec).unwrap_unchecked();
                    (a, b)
                }
            }
        }

        impl<'x, W, $A, $B> EmbeddedLookMut<(&'x $A, &'x $B)>
            for EmbeddedHeadersView<W, (&'x $A, &'x $B)>
        where
            W: HasHeadersMut,
            $A: EmbeddedStep<EmbeddedStart> + EmbeddedStepMut<EmbeddedStart>,
            $B: EmbeddedStep<$A> + EmbeddedStepMut<$A>,
            Self: 'x,
        {
            type RefsMut<'a>
                = (&'a mut $A, &'a mut $B)
            where
                Self: 'a;

            #[inline(always)]
            fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
            where
                Self: 'a,
            {
                let h = self.outer_mut().as_headers_mut();
                // SAFETY: EmbeddedHeadersView invariant.
                let e = unsafe { h.embedded_ip_mut().unwrap_unchecked() };
                let m = EmbeddedMatcherMut::from_embedded_only(e);
                let m = <$A as EmbeddedStepMut<EmbeddedStart>>::chain(m);
                let m = <$B as EmbeddedStepMut<$A>>::chain(m);
                match m.done() {
                    Some(((a, b),)) => (a, b),
                    // SAFETY: EmbeddedHeadersView invariant.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
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

        impl<'x, W, $A, $B, $C> EmbeddedLook<(&'x $A, &'x $B, &'x $C)>
            for EmbeddedHeadersView<W, (&'x $A, &'x $B, &'x $C)>
        where
            W: HasHeaders,
            $A: EmbeddedStep<EmbeddedStart>,
            $B: EmbeddedStep<$A>,
            $C: EmbeddedStep<$B>,
            Self: 'x,
        {
            type Refs<'a>
                = (&'a $A, &'a $B, &'a $C)
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                let h = self.outer().as_headers();
                // SAFETY: EmbeddedHeadersView invariant.
                let e = unsafe { h.embedded_ip().unwrap_unchecked() };
                unsafe {
                    core::hint::assert_unchecked(
                        <(&'x $A, &'x $B, &'x $C) as embedded_sealed::Sealed>::matches(e),
                    );
                    let (a, ec) = $A::step(e, 0).unwrap_unchecked();
                    let (b, ec) = $B::step(e, ec).unwrap_unchecked();
                    let (c, _) = $C::step(e, ec).unwrap_unchecked();
                    (a, b, c)
                }
            }
        }

        impl<'x, W, $A, $B, $C> EmbeddedLookMut<(&'x $A, &'x $B, &'x $C)>
            for EmbeddedHeadersView<W, (&'x $A, &'x $B, &'x $C)>
        where
            W: HasHeadersMut,
            $A: EmbeddedStep<EmbeddedStart> + EmbeddedStepMut<EmbeddedStart>,
            $B: EmbeddedStep<$A> + EmbeddedStepMut<$A>,
            $C: EmbeddedStep<$B> + EmbeddedStepMut<$B>,
            Self: 'x,
        {
            type RefsMut<'a>
                = (&'a mut $A, &'a mut $B, &'a mut $C)
            where
                Self: 'a;

            #[inline(always)]
            fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
            where
                Self: 'a,
            {
                let h = self.outer_mut().as_headers_mut();
                // SAFETY: EmbeddedHeadersView invariant.
                let e = unsafe { h.embedded_ip_mut().unwrap_unchecked() };
                let m = EmbeddedMatcherMut::from_embedded_only(e);
                let m = <$A as EmbeddedStepMut<EmbeddedStart>>::chain(m);
                let m = <$B as EmbeddedStepMut<$A>>::chain(m);
                let m = <$C as EmbeddedStepMut<$B>>::chain(m);
                match m.done() {
                    Some(((a, b, c),)) => (a, b, c),
                    // SAFETY: EmbeddedHeadersView invariant.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
        }
    };
}

impl_embedded_arity_1!(A);
impl_embedded_arity_2!(A, B);
impl_embedded_arity_3!(A, B, C);

// ===========================================================================
// HeadersView<T>::as_embedded -- per-outer-arity construction
// ===========================================================================
//
// One impl per outer arity, gated by `EmbeddedHeaders: Within<LastLayer>`.
// In practice the bound restricts callers to outer shapes whose final
// layer is Icmp4 or Icmp6 (those are the only `Within<Icmp_>` impls for
// `EmbeddedHeaders`).  Each impl runs the inner shape's `matches` and
// the outer's `embedded_ip().is_some()` check, then casts &HeadersView<...>
// to &EmbeddedHeadersView<HeadersView<...>, U> via the repr(transparent) layout.

macro_rules! impl_as_embedded_arity_1 {
    ($A:ident) => {
        impl<'x, $A> HeadersView<(&'x $A,)>
        where
            (&'x $A,): Shape,
            EmbeddedHeaders: Within<$A>,
        {
            /// Re-borrow this outer view as an [`EmbeddedHeadersView`] if
            /// the embedded section is present and matches `U`.
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                // SAFETY: EmbeddedHeadersView<Self, U> is repr(transparent)
                // over Self.  matches(e) was just verified and
                // embedded_ip() returned Some, so the U + outer
                // invariants hold.  The reference cast preserves the
                // shared borrow lifetime.
                let p = std::ptr::from_ref(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }

            /// Mutable counterpart of [`Self::as_embedded`].
            #[inline]
            #[must_use]
            pub fn as_embedded_mut<U>(&mut self) -> Option<&mut EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let matched = self
                    .as_headers()
                    .embedded_ip()
                    .is_some_and(<U as embedded_sealed::Sealed>::matches);
                if !matched {
                    return None;
                }
                // SAFETY: same as as_embedded, exclusive borrow preserved.
                let p = std::ptr::from_mut(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_mut_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_2 {
    ($A:ident, $B:ident) => {
        impl<'x, $A, $B> HeadersView<(&'x $A, &'x $B)>
        where
            (&'x $A, &'x $B): Shape,
            EmbeddedHeaders: Within<$B>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }

            /// Mutable counterpart of [`Self::as_embedded`].
            #[inline]
            #[must_use]
            pub fn as_embedded_mut<U>(&mut self) -> Option<&mut EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let matched = self
                    .as_headers()
                    .embedded_ip()
                    .is_some_and(<U as embedded_sealed::Sealed>::matches);
                if !matched {
                    return None;
                }
                let p = std::ptr::from_mut(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_mut_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_3 {
    ($A:ident, $B:ident, $C:ident) => {
        impl<'x, $A, $B, $C> HeadersView<(&'x $A, &'x $B, &'x $C)>
        where
            (&'x $A, &'x $B, &'x $C): Shape,
            EmbeddedHeaders: Within<$C>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }

            /// Mutable counterpart of [`Self::as_embedded`].
            #[inline]
            #[must_use]
            pub fn as_embedded_mut<U>(&mut self) -> Option<&mut EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let matched = self
                    .as_headers()
                    .embedded_ip()
                    .is_some_and(<U as embedded_sealed::Sealed>::matches);
                if !matched {
                    return None;
                }
                let p = std::ptr::from_mut(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_mut_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_4 {
    ($A:ident, $B:ident, $C:ident, $D:ident) => {
        impl<'x, $A, $B, $C, $D> HeadersView<(&'x $A, &'x $B, &'x $C, &'x $D)>
        where
            (&'x $A, &'x $B, &'x $C, &'x $D): Shape,
            EmbeddedHeaders: Within<$D>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }

            /// Mutable counterpart of [`Self::as_embedded`].
            #[inline]
            #[must_use]
            pub fn as_embedded_mut<U>(&mut self) -> Option<&mut EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let matched = self
                    .as_headers()
                    .embedded_ip()
                    .is_some_and(<U as embedded_sealed::Sealed>::matches);
                if !matched {
                    return None;
                }
                let p = std::ptr::from_mut(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_mut_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_5 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident) => {
        impl<'x, $A, $B, $C, $D, $E> HeadersView<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)>
        where
            (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E): Shape,
            EmbeddedHeaders: Within<$E>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }

            /// Mutable counterpart of [`Self::as_embedded`].
            #[inline]
            #[must_use]
            pub fn as_embedded_mut<U>(&mut self) -> Option<&mut EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let matched = self
                    .as_headers()
                    .embedded_ip()
                    .is_some_and(<U as embedded_sealed::Sealed>::matches);
                if !matched {
                    return None;
                }
                let p = std::ptr::from_mut(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_mut_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_6 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F>
            HeadersView<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)>
        where
            (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F): Shape,
            EmbeddedHeaders: Within<$F>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }

            /// Mutable counterpart of [`Self::as_embedded`].
            #[inline]
            #[must_use]
            pub fn as_embedded_mut<U>(&mut self) -> Option<&mut EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let matched = self
                    .as_headers()
                    .embedded_ip()
                    .is_some_and(<U as embedded_sealed::Sealed>::matches);
                if !matched {
                    return None;
                }
                let p = std::ptr::from_mut(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_mut_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_7 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident, $G:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F, $G>
            HeadersView<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)>
        where
            (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G): Shape,
            EmbeddedHeaders: Within<$G>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }

            /// Mutable counterpart of [`Self::as_embedded`].
            #[inline]
            #[must_use]
            pub fn as_embedded_mut<U>(&mut self) -> Option<&mut EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let matched = self
                    .as_headers()
                    .embedded_ip()
                    .is_some_and(<U as embedded_sealed::Sealed>::matches);
                if !matched {
                    return None;
                }
                let p = std::ptr::from_mut(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_mut_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_8 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident, $G:ident, $H:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F, $G, $H>
            HeadersView<(
                &'x $A,
                &'x $B,
                &'x $C,
                &'x $D,
                &'x $E,
                &'x $F,
                &'x $G,
                &'x $H,
            )>
        where
            (
                &'x $A,
                &'x $B,
                &'x $C,
                &'x $D,
                &'x $E,
                &'x $F,
                &'x $G,
                &'x $H,
            ): Shape,
            EmbeddedHeaders: Within<$H>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }

            /// Mutable counterpart of [`Self::as_embedded`].
            #[inline]
            #[must_use]
            pub fn as_embedded_mut<U>(&mut self) -> Option<&mut EmbeddedHeadersView<Self, U>>
            where
                U: EmbeddedShape,
            {
                let matched = self
                    .as_headers()
                    .embedded_ip()
                    .is_some_and(<U as embedded_sealed::Sealed>::matches);
                if !matched {
                    return None;
                }
                let p = std::ptr::from_mut(self).cast::<EmbeddedHeadersView<Self, U>>();
                Some(unsafe { p.as_mut_unchecked() })
            }
        }
    };
}

impl_as_embedded_arity_1!(A);
impl_as_embedded_arity_2!(A, B);
impl_as_embedded_arity_3!(A, B, C);
impl_as_embedded_arity_4!(A, B, C, D);
impl_as_embedded_arity_5!(A, B, C, D, E);
impl_as_embedded_arity_6!(A, B, C, D, E, F);
impl_as_embedded_arity_7!(A, B, C, D, E, F, G);
impl_as_embedded_arity_8!(A, B, C, D, E, F, G, H);

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

    // -----------------------------------------------------------------------
    // EmbeddedHeadersView<W, U> use-site tests
    // -----------------------------------------------------------------------

    use crate::eth::Eth;
    use crate::headers::HeadersView;
    use crate::icmp4::Icmp4;
    use crate::icmp6::Icmp6;

    type OuterIcmp4 = (&'static Eth, &'static Ipv4, &'static Icmp4);
    type OuterIcmp6 = (&'static Eth, &'static Ipv6, &'static Icmp6);
    type InnerV4Tcp = (&'static Ipv4, &'static TruncatedTcp);
    type InnerV6Udp = (&'static Ipv6, &'static TruncatedUdp);

    #[test]
    fn as_embedded_v4_tcp_yields_proven_window() {
        use crate::tcp::TcpPort;
        let h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let outer: &HeadersView<OuterIcmp4> = h.as_view().expect("outer shape matches");
        let ew: &EmbeddedHeadersView<HeadersView<OuterIcmp4>, InnerV4Tcp> = outer
            .as_embedded::<InnerV4Tcp>()
            .expect("inner shape matches");
        let (inner_ip, inner_tcp) = ew.look();
        // Inner refs must point to the same EmbeddedHeaders the
        // pat.rs `.embedded()` chain selects.
        let (_, _, _, (pat_ip, pat_tcp)) = h
            .pat()
            .eth()
            .ipv4()
            .icmp4()
            .embedded()
            .ipv4()
            .tcp()
            .done()
            .expect("pat.rs must agree");
        assert!(std::ptr::eq(inner_ip, pat_ip));
        assert!(std::ptr::eq(inner_tcp, pat_tcp));
    }

    // outer() is a free reborrow back to the encapsulating HeadersView<T>:
    // the returned reference must point at the same allocation as the
    // original outer, so a roundtrip preserves identity at the byte
    // level.  Because HeadersView<T> is repr(transparent) over Headers and
    // EmbeddedHeadersView<HeadersView<T>, U> is repr(transparent) over HeadersView<T>,
    // the cast is purely a type-level move.
    #[test]
    fn outer_round_trip_preserves_pointer_identity() {
        use crate::tcp::TcpPort;
        let h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let outer: &HeadersView<OuterIcmp4> = h.as_view().unwrap();
        let outer_addr = std::ptr::from_ref(outer);
        let ew = outer.as_embedded::<InnerV4Tcp>().unwrap();
        let outer_back = ew.outer();
        assert!(std::ptr::eq(outer_back, outer_addr));
    }

    // Wrong inner shape returns None; the outer HeadersView stays valid.
    #[test]
    fn wrong_inner_shape_returns_none() {
        use crate::tcp::TcpPort;
        let h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let outer: &HeadersView<OuterIcmp4> = h.as_view().unwrap();
        // Inner is TCP; ask for UDP -> must miss.
        assert!(outer.as_embedded::<(&Ipv4, &TruncatedUdp)>().is_none());
        // But TCP is fine.
        assert!(outer.as_embedded::<InnerV4Tcp>().is_some());
    }

    // No embedded section -> as_embedded returns None even with a
    // valid outer ICMP shape.  Echo replies are not error messages, so
    // the builder doesn't attach an embedded payload.
    #[test]
    fn icmp_without_embedded_payload_misses() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .icmp4(|_| {})
            .echo_request(|_| {})
            .build_headers()
            .unwrap();
        let outer: &HeadersView<OuterIcmp4> = h.as_view().unwrap();
        assert!(outer.as_embedded::<InnerV4Tcp>().is_none());
        assert!(outer.as_embedded::<(&Ipv4,)>().is_none());
    }

    // IPv6/UDP path mirrors the v4/TCP integration test.
    #[test]
    fn as_embedded_v6_udp_yields_proven_window() {
        use crate::udp::UdpPort;
        let h = icmp6_with_embedded(|a| {
            a.ipv6(|_| {}).udp(
                UdpPort::new_checked(53).unwrap(),
                UdpPort::new_checked(53).unwrap(),
                |_| {},
            )
        });
        let outer: &HeadersView<OuterIcmp6> = h.as_view().unwrap();
        let ew = outer
            .as_embedded::<InnerV6Udp>()
            .expect("inner shape matches");
        let (inner_ip, inner_udp) = ew.look();
        let (_, _, _, (pat_ip, pat_udp)) = h
            .pat()
            .eth()
            .ipv6()
            .icmp6()
            .embedded()
            .ipv6()
            .udp()
            .done()
            .unwrap();
        assert!(std::ptr::eq(inner_ip, pat_ip));
        assert!(std::ptr::eq(inner_udp, pat_udp));
    }

    // Net-enum on the inner side -- the inner shape uses &Net rather
    // than the concrete &Ipv4 / &Ipv6 variant.  Useful for shapes that
    // accept either inner IP version.
    #[test]
    fn as_embedded_inner_net_enum_works() {
        use crate::tcp::TcpPort;
        let h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let outer: &HeadersView<OuterIcmp4> = h.as_view().unwrap();
        let ew = outer
            .as_embedded::<(&Net, &TruncatedTcp)>()
            .expect("Net+Tcp inner shape matches");
        let (net, _tcp) = ew.look();
        assert!(matches!(net, Net::Ipv4(_)));
    }

    // Cross-consistency under fuzz: as_embedded()'s hit/miss must
    // agree with pat.rs's full chain (eth().ipv4().icmp4().embedded()
    // .ipv4().tcp().done()) for every generated header chain.
    #[test]
    fn as_embedded_v4_tcp_agrees_with_pat_matcher() {
        let chain = header_chain()
            .eth(|_| {})
            .ipv4(|_| {})
            .icmp4(|_| {})
            .dest_unreachable(|_| {})
            .embed_ipv4(|_| {})
            .embed_tcp(|_| {});
        bolero::check!()
            .with_generator(chain)
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
                    .as_view::<OuterIcmp4>()
                    .and_then(|w| w.as_embedded::<InnerV4Tcp>())
                    .is_some();
                assert_eq!(
                    pat_hit, win_hit,
                    "as_embedded disagrees with pat.rs full chain"
                );
            });
    }

    // -----------------------------------------------------------------------
    // EmbeddedLookMut + as_embedded_mut tests
    // -----------------------------------------------------------------------

    // look_mut yields refs at the same addresses as look on the same
    // EmbeddedHeaders, so the two paths agree on which inner slots
    // they pick.  Holding `&h` and `&mut h` simultaneously is
    // impossible, so we fix `h` in memory across both invocations and
    // compare raw pointers afterwards.
    #[test]
    fn look_mut_agrees_with_look_for_v4_tcp() {
        use crate::tcp::TcpPort;
        use std::ptr::from_ref;
        let mut h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });

        let imm: (*const Ipv4, *const TruncatedTcp) = {
            let outer: &HeadersView<OuterIcmp4> = h.as_view().unwrap();
            let ew = outer.as_embedded::<InnerV4Tcp>().unwrap();
            let (ip, tcp) = ew.look();
            (from_ref(ip), from_ref(tcp))
        };
        let mutp: (*const Ipv4, *const TruncatedTcp) = {
            let outer: &mut HeadersView<OuterIcmp4> = h.as_view_mut().unwrap();
            let ew = outer.as_embedded_mut::<InnerV4Tcp>().unwrap();
            let (ip, tcp) = ew.look_mut();
            (from_ref(&*ip), from_ref(&*tcp))
        };
        assert_eq!(
            imm, mutp,
            "look_mut picked different (Ipv4, TruncatedTcp) slots"
        );
    }

    // Mutation through look_mut must take effect on the backing
    // EmbeddedHeaders.  Round-trip via Look afterwards to observe.
    #[test]
    fn look_mut_mutation_propagates() {
        use crate::tcp::TcpPort;
        let initial_dst = TcpPort::new_checked(443).unwrap();
        let updated_dst = TcpPort::new_checked(8443).unwrap();

        let mut h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {})
                .tcp(TcpPort::new_checked(80).unwrap(), initial_dst, |_| {})
        });

        {
            let outer = h.as_view_mut::<OuterIcmp4>().unwrap();
            let ew = outer.as_embedded_mut::<InnerV4Tcp>().unwrap();
            let (_, tcp_mut) = ew.look_mut();
            // TruncatedTcp::FullHeader holds a Tcp; mutate via that.
            if let crate::tcp::TruncatedTcp::FullHeader(t) = tcp_mut {
                t.set_destination(updated_dst);
            } else {
                panic!("expected full TCP header in test packet");
            }
        }

        let outer = h.as_view::<OuterIcmp4>().unwrap();
        let ew = outer.as_embedded::<InnerV4Tcp>().unwrap();
        let (_, tcp) = ew.look();
        match tcp {
            crate::tcp::TruncatedTcp::FullHeader(t) => assert_eq!(t.destination(), updated_dst),
            crate::tcp::TruncatedTcp::PartialHeader(_) => {
                panic!("expected full TCP header in test packet")
            }
        }
    }

    // outer_mut roundtrip preserves pointer identity, same as outer.
    #[test]
    fn outer_mut_round_trip_preserves_pointer_identity() {
        use crate::tcp::TcpPort;
        let mut h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let outer_addr;
        {
            let outer = h.as_view_mut::<OuterIcmp4>().unwrap();
            outer_addr = std::ptr::from_mut(outer).cast_const();
        }
        let outer = h.as_view_mut::<OuterIcmp4>().unwrap();
        // Re-take the borrow at the same address to confirm.
        assert!(std::ptr::eq(
            std::ptr::from_mut(outer).cast_const(),
            outer_addr
        ));
        let ew = outer.as_embedded_mut::<InnerV4Tcp>().unwrap();
        let outer_back: &mut HeadersView<OuterIcmp4> = ew.outer_mut();
        assert!(std::ptr::eq(
            std::ptr::from_mut(outer_back).cast_const(),
            outer_addr,
        ));
    }

    // Wrong inner shape via the mut path -> None.
    #[test]
    fn as_embedded_mut_wrong_inner_shape_returns_none() {
        use crate::tcp::TcpPort;
        let mut h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {}).tcp(
                TcpPort::new_checked(80).unwrap(),
                TcpPort::new_checked(443).unwrap(),
                |_| {},
            )
        });
        let outer = h.as_view_mut::<OuterIcmp4>().unwrap();
        assert!(outer.as_embedded_mut::<(&Ipv4, &TruncatedUdp)>().is_none());
    }

    // EmbeddedTransport enum on the mut path: the inner shape uses
    // `&EmbeddedTransport` rather than the concrete variant, so the
    // returned ref is the enum itself.  Mutate through the enum and
    // observe the change via a follow-up immutable look.
    #[test]
    fn as_embedded_mut_inner_transport_enum_works() {
        use crate::tcp::{TcpPort, TruncatedTcp};
        let initial_dst = TcpPort::new_checked(443).unwrap();
        let updated_dst = TcpPort::new_checked(8443).unwrap();
        let mut h = icmp4_with_embedded(|a| {
            a.ipv4(|_| {})
                .tcp(TcpPort::new_checked(80).unwrap(), initial_dst, |_| {})
        });

        {
            let outer = h.as_view_mut::<OuterIcmp4>().unwrap();
            let ew = outer
                .as_embedded_mut::<(&Net, &EmbeddedTransport)>()
                .expect("Net+EmbeddedTransport inner shape matches");
            let (_net, transport) = ew.look_mut();
            match transport {
                EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(t)) => {
                    t.set_destination(updated_dst);
                }
                _ => panic!("expected EmbeddedTransport::Tcp(FullHeader) in test packet"),
            }
        }

        let outer = h.as_view::<OuterIcmp4>().unwrap();
        let ew = outer.as_embedded::<(&Net, &EmbeddedTransport)>().unwrap();
        let (_net, transport) = ew.look();
        match transport {
            EmbeddedTransport::Tcp(TruncatedTcp::FullHeader(t)) => {
                assert_eq!(t.destination(), updated_dst);
            }
            _ => panic!("post-mutation: expected EmbeddedTransport::Tcp(FullHeader)"),
        }
    }
}

// ===========================================================================
// Differential properties
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // fine to unwrap in tests
mod embedded_view_properties {
    use super::*;
    use crate::eth::Eth;
    use crate::headers::{Headers, ShapedIcmpError, ShapedQuote};
    use crate::icmp4::Icmp4;
    use crate::icmp6::Icmp6;
    use crate::vlan::Vlan;

    /// Both structural walks over a quoted packet, across the range of outer and inner shapes.
    ///
    /// The pairing this checks is the one soundness rests on, and it is not the obvious one.
    /// `as_embedded`/`as_embedded_mut` *decide* with [`embedded_sealed::Sealed::matches`], which
    /// walks [`EmbeddedHeaders`] through [`EmbeddedStep`]. [`EmbeddedLookMut::look_mut`] then
    /// *delivers* through [`EmbeddedMatcherMut`], a completely separate implementation with its own
    /// pre-split [`EmbeddedFields`](super::super::pat::EmbeddedFields) and its own gap check, and it
    /// unwraps that chain with `unreachable_unchecked` on the strength of the first one's answer.
    /// Two implementations, one of them licensing the other to skip its own `None` branch. If they
    /// ever disagree the result is undefined behaviour, not a wrong answer.
    ///
    /// So the oracle here is `pat()`/`pat_mut()`'s `.embedded()` chain, which is the same machinery
    /// `look_mut` uses -- making this differential test exactly the invariant `look_mut` assumes.
    ///
    /// Arity matters twice over, because `matches`, `look` and `look_mut` are generated per *inner*
    /// arity while `as_embedded`/`as_embedded_mut` are generated per *outer* arity, each threading
    /// the extension cursor by hand. Before this the suite reached one outer arity and one inner
    /// arity, of eight and three.
    macro_rules! embedded_agrees {
        (
            $read:ident, $mutable:ident,
            ($outer:ty, $($ol:ident),+),
            ($inner:ty, $($il:ident),+)
        ) => {
            #[test]
            fn $read() {
                use concurrency::sync::atomic::{AtomicUsize, Ordering};
                static SEEN: AtomicUsize = AtomicUsize::new(0);
                static HIT: AtomicUsize = AtomicUsize::new(0);
                bolero::check!()
                    .with_generator(ShapedIcmpError)
                    .for_each(|h: &Headers| {
                        SEEN.fetch_add(1, Ordering::Relaxed);
                        let licensed = h
                            .as_view::<$outer>()
                            .is_some_and(|w| w.as_embedded::<$inner>().is_some());
                        if licensed {
                            HIT.fetch_add(1, Ordering::Relaxed);
                        }
                        let deliverable =
                            h.pat()$(.$ol())+.embedded()$(.$il())+.done().is_some();
                        assert_eq!(
                            licensed, deliverable,
                            concat!(
                                "`matches` and the read walk disagree for ",
                                stringify!($inner),
                                " inside ",
                                stringify!($outer),
                                ", so `look` would reach `unreachable_unchecked`: {:?}"
                            ),
                            h
                        );
                    });
                agreement_is_not_vacuous(
                    concat!(stringify!($inner), " in ", stringify!($outer)),
                    SEEN.load(Ordering::Relaxed),
                    HIT.load(Ordering::Relaxed),
                );
            }

            #[test]
            fn $mutable() {
                use concurrency::sync::atomic::{AtomicUsize, Ordering};
                static SEEN: AtomicUsize = AtomicUsize::new(0);
                static HIT: AtomicUsize = AtomicUsize::new(0);
                bolero::check!()
                    .with_generator(ShapedIcmpError)
                    .for_each(|h: &Headers| {
                        let mut owned = h.clone();
                        SEEN.fetch_add(1, Ordering::Relaxed);
                        // `as_embedded_mut`'s reference cannot outlive the `and_then` closure it
                        // would be produced in, so this asks the question without keeping it.
                        let licensed = match owned.as_view_mut::<$outer>() {
                            Some(w) => w.as_embedded_mut::<$inner>().is_some(),
                            None => false,
                        };
                        if licensed {
                            HIT.fetch_add(1, Ordering::Relaxed);
                        }
                        let deliverable =
                            owned.pat_mut()$(.$ol())+.embedded()$(.$il())+.done().is_some();
                        assert_eq!(
                            licensed, deliverable,
                            concat!(
                                "`matches` and the mutable walk disagree for ",
                                stringify!($inner),
                                " inside ",
                                stringify!($outer),
                                ", so `look_mut` would reach `unreachable_unchecked`: {:?}"
                            ),
                            h
                        );
                    });
                agreement_is_not_vacuous(
                    concat!(stringify!($inner), " in ", stringify!($outer)),
                    SEEN.load(Ordering::Relaxed),
                    HIT.load(Ordering::Relaxed),
                );
            }
        };
    }

    /// A shape the generator never produces makes its property pass for the wrong reason.
    ///
    /// Two shapes compound here -- an outer arity and an inner one -- so a property can starve much
    /// more quietly than in [`view`](super::super::view): demanding four VLAN tags *and* a
    /// particular extension inside the quoted packet multiplies two small probabilities. Each pair
    /// reports its own hit rate, and the pairs are chosen to vary one dimension at a time for
    /// exactly that reason.
    fn agreement_is_not_vacuous(shape: &str, seen: usize, hit: usize) {
        println!("{shape}: matched {hit} of {seen}");
        // Twenty thousand rather than [`view`](super::super::view)'s five hundred, because
        // compounding costs an order of magnitude: the widest pair here matches about one packet in
        // twenty, and `(&Ipv6, &HopByHop, &TruncatedTcp)` inside an ICMPv6 error matches about one
        // in a thousand. Five hundred cases at that rate would fail this check outright half the
        // time it ran. A default one-second run manages twenty-five thousand, so the guard still
        // bites in CI; a deliberately short run should say nothing rather than say something false.
        if seen > 20_000 {
            assert!(
                hit > 0,
                "{shape} never matched in {seen} packets: the two walks agree only because the \
                 generator cannot produce this shape"
            );
        }
    }

    type O4V4 = (&'static Eth, &'static Ipv4, &'static Icmp4);
    type O4V6 = (&'static Eth, &'static Ipv6, &'static Icmp6);

    // ---- Inner shapes, at the one outer arity the builders could already express ----------
    //
    // Varying the inner shape alone: network layer, both enum forms, every truncated transport,
    // and the extension region.
    embedded_agrees!(
        read_inner_v4_tcp,
        mutable_inner_v4_tcp,
        (O4V4, eth, ipv4, icmp4),
        ((&Ipv4, &TruncatedTcp), ipv4, tcp)
    );
    embedded_agrees!(
        read_inner_v6_udp,
        mutable_inner_v6_udp,
        (O4V6, eth, ipv6, icmp6),
        ((&Ipv6, &TruncatedUdp), ipv6, udp)
    );
    embedded_agrees!(
        read_inner_net_only,
        mutable_inner_net_only,
        (O4V4, eth, ipv4, icmp4),
        ((&Net,), net)
    );
    embedded_agrees!(
        read_inner_v6_only,
        mutable_inner_v6_only,
        (O4V6, eth, ipv6, icmp6),
        ((&Ipv6,), ipv6)
    );
    // An ICMP error quoting an ICMP packet -- a `TruncatedIcmp4` inside an `Icmp4`. Legitimate:
    // an unreachable in response to a ping quotes the echo request.
    embedded_agrees!(
        read_inner_icmp_in_icmp4,
        mutable_inner_icmp_in_icmp4,
        (O4V4, eth, ipv4, icmp4),
        ((&Ipv4, &TruncatedIcmp4), ipv4, icmp4)
    );
    embedded_agrees!(
        read_inner_icmp_in_icmp6,
        mutable_inner_icmp_in_icmp6,
        (O4V6, eth, ipv6, icmp6),
        ((&Ipv6, &TruncatedIcmp6), ipv6, icmp6)
    );

    // ---- The embedded extension region ---------------------------------------------------
    //
    // `ext_gap_ok_embedded` versus `ext_gap_ok_mut_embedded`: naming an extension switches the
    // quoted packet from skip-extensions-silently to consume-them-all, so these match only a quote
    // carrying that extension and no other. The read pair shares `ext_gap_ok_embedded` between the
    // two walks and so tests the by-hand `ec` threading; the mutable pair runs two genuinely
    // different implementations against each other, one over `EmbeddedHeaders` and one over a
    // pre-split `EmbeddedFields`.
    embedded_agrees!(
        read_inner_ext_v6,
        mutable_inner_ext_v6,
        (O4V6, eth, ipv6, icmp6),
        ((&Ipv6, &HopByHop, &TruncatedTcp), ipv6, hop_by_hop, tcp)
    );
    embedded_agrees!(
        read_inner_ext_v4_auth,
        mutable_inner_ext_v4_auth,
        (O4V4, eth, ipv4, icmp4),
        ((&Ipv4, &Ipv4Auth, &TruncatedTcp), ipv4, ipv4_auth, tcp)
    );
    // Entering the region and stopping there: the gap check runs at the transport step, so with no
    // transport named the remaining extensions are simply left unvisited. Telling this apart from
    // the two above is the whole reason the check sits where it does.
    embedded_agrees!(
        read_inner_ext_no_transport,
        mutable_inner_ext_no_transport,
        (O4V6, eth, ipv6, icmp6),
        ((&Ipv6, &HopByHop), ipv6, hop_by_hop)
    );

    // ---- Outer arities -------------------------------------------------------------------
    //
    // `as_embedded` and `as_embedded_mut` are written out once per outer arity, eight times. Arities
    // 1 and 2 cannot be instantiated: both require `EmbeddedHeaders: Within<LastLayer>`, which holds
    // only for `Icmp4` and `Icmp6`, and neither can appear that early. `Eth` is the only layer with
    // `Within<()>`, so an arity-1 shape must be `(&Eth,)`; an arity-2 shape must then end in
    // something `Within<Eth>`, and no ICMP layer is. Asking for either is a compile error --
    // `Icmp4: Within<()> is not satisfied` and `Icmp4: Within<eth::Eth> is not satisfied` -- so those
    // two macro arms are 44 lines that can never run and could be deleted.
    //
    // 3 through 8 is therefore all of them. The inner shape is held cheap on purpose here, so that a
    // thin outer shape is the only improbable thing each property asks for.
    embedded_agrees!(
        read_outer_4,
        mutable_outer_4,
        ((&Eth, &Vlan, &Ipv4, &Icmp4), eth, vlan, ipv4, icmp4),
        ((&Ipv4, &TruncatedTcp), ipv4, tcp)
    );
    embedded_agrees!(
        read_outer_5,
        mutable_outer_5,
        (
            (&Eth, &Vlan, &Vlan, &Ipv6, &Icmp6),
            eth,
            vlan,
            vlan,
            ipv6,
            icmp6
        ),
        ((&Ipv6, &TruncatedUdp), ipv6, udp)
    );
    embedded_agrees!(
        read_outer_6,
        mutable_outer_6,
        (
            (&Eth, &Vlan, &Vlan, &Vlan, &Ipv4, &Icmp4),
            eth,
            vlan,
            vlan,
            vlan,
            ipv4,
            icmp4
        ),
        // An inner shape that can miss on a quote that *is* present, so the shape check's own
        // rejection is reached rather than only the absent-quote early return above it.
        ((&Ipv4, &TruncatedTcp), ipv4, tcp)
    );
    embedded_agrees!(
        read_outer_7,
        mutable_outer_7,
        (
            (&Eth, &Vlan, &Vlan, &Vlan, &Vlan, &Ipv4, &Icmp4),
            eth,
            vlan,
            vlan,
            vlan,
            vlan,
            ipv4,
            icmp4
        ),
        ((&Ipv4, &TruncatedTcp), ipv4, tcp)
    );
    // Arity 8, and the only outer shape that also enters the *outer* extension region: `Icmp6`
    // directly after a `HopByHop` makes the outer gap check strict too.
    embedded_agrees!(
        read_outer_8,
        mutable_outer_8,
        (
            (&Eth, &Vlan, &Vlan, &Vlan, &Vlan, &Ipv6, &HopByHop, &Icmp6),
            eth,
            vlan,
            vlan,
            vlan,
            vlan,
            ipv6,
            hop_by_hop,
            icmp6
        ),
        // `Ipv6` rather than `Net`: a quote of the other family misses, which is the only way to
        // reach this arity's shape-check rejection.
        ((&Ipv6,), ipv6)
    );

    // The `EmbeddedTransport` enum has no read-side property above, and that is an asymmetry in
    // `pat.rs` rather than a choice here: `EmbeddedMatcherMut::transport` exists but
    // `EmbeddedMatcher::transport` does not, so the immutable oracle cannot name the enum even
    // though every concrete variant and every other layer is paired between the two. The mutable
    // side is checked below; adding the missing method would let the read side follow in one line.
    #[test]
    fn mutable_inner_transport_enum() {
        use concurrency::sync::atomic::{AtomicUsize, Ordering};
        static SEEN: AtomicUsize = AtomicUsize::new(0);
        static HIT: AtomicUsize = AtomicUsize::new(0);
        bolero::check!()
            .with_generator(ShapedIcmpError)
            .for_each(|h: &Headers| {
                let mut owned = h.clone();
                SEEN.fetch_add(1, Ordering::Relaxed);
                let licensed = match owned.as_view_mut::<O4V4>() {
                    Some(w) => w.as_embedded_mut::<(&Net, &EmbeddedTransport)>().is_some(),
                    None => false,
                };
                if licensed {
                    HIT.fetch_add(1, Ordering::Relaxed);
                }
                let deliverable = owned
                    .pat_mut()
                    .eth()
                    .ipv4()
                    .icmp4()
                    .embedded()
                    .net()
                    .transport()
                    .done()
                    .is_some();
                assert_eq!(
                    licensed, deliverable,
                    "`matches` and the mutable walk disagree for (&Net, &EmbeddedTransport): {h:?}"
                );
            });
        agreement_is_not_vacuous(
            "(&Net, &EmbeddedTransport)",
            SEEN.load(Ordering::Relaxed),
            HIT.load(Ordering::Relaxed),
        );
    }

    // ---- Delivering, not merely deciding -------------------------------------------------

    /// Write through every reference `look_mut` hands out, in the extension-region shape.
    ///
    /// The properties above compare *decisions*. This one takes the decision up on its offer: it
    /// calls `look_mut`, which runs the `unreachable_unchecked` the decision licenses, and then
    /// writes through all three references. The assertions are close to beside the point -- what
    /// matters is that three `&mut` into one `EmbeddedHeaders` are created and written through, so
    /// that miri with stacked borrows enabled can judge whether
    /// [`EmbeddedFields`](super::super::pat::EmbeddedFields) handed out two paths to the same
    /// layer. The arity-3 shape is the one that borrows from all three of its fields at once,
    /// including a slice element, which is the hardest of them to split soundly.
    fn exercise_the_embedded_split() {
        bolero::check!()
            .with_generator(ShapedIcmpError)
            .for_each(|h: &Headers| {
                let mut owned = h.clone();
                let Some(outer) = owned.as_view_mut::<O4V6>() else {
                    return;
                };
                let Some(ew) = outer.as_embedded_mut::<(&Ipv6, &HopByHop, &TruncatedTcp)>() else {
                    return;
                };
                let (ip, ext, tcp) = ew.look_mut();

                let want_hops = ip.hop_limit().wrapping_add(1);
                ip.set_hop_limit(want_hops);
                let seen_ext = ext.next_header();
                let seen_tcp = matches!(tcp, TruncatedTcp::FullHeader(_));

                assert_eq!(
                    ip.hop_limit(),
                    want_hops,
                    "the write through ipv6 did not stick"
                );
                assert_eq!(
                    ext.next_header(),
                    seen_ext,
                    "the extension header changed under a write to ipv6"
                );
                assert_eq!(
                    matches!(tcp, TruncatedTcp::FullHeader(_)),
                    seen_tcp,
                    "the quoted transport changed under a write to ipv6"
                );
            });
    }

    /// Shards of [`exercise_the_embedded_split`], so the machine can be used.
    ///
    /// Same reasoning as the shards in [`view`](super::super::view): under miri this is the
    /// expensive property and the one that matters most, and its cost is wall-clock rather than
    /// cores. Each shard seeds itself from the OS, so `N` shards explore `N` independent streams
    /// and nextest runs them concurrently. Eight rather than sixteen -- `view`'s split is the wider
    /// one and should keep the larger share of the cores.
    macro_rules! split_shards {
        ($($name:ident),* $(,)?) => {
            $(
                #[test]
                fn $name() {
                    exercise_the_embedded_split();
                }
            )*
        };
    }

    split_shards!(
        the_embedded_split_hands_out_distinct_layers,
        embedded_split_shard_2,
        embedded_split_shard_3,
        embedded_split_shard_4,
        embedded_split_shard_5,
        embedded_split_shard_6,
        embedded_split_shard_7,
        embedded_split_shard_8,
    );

    /// `look` and `look_mut` pick the same slots, one inner shape per instantiation.
    ///
    /// Agreeing that a match exists is weaker than agreeing on *which* layers were selected, and
    /// this is the only thing in the suite that asks the stronger question across the family.
    ///
    /// It is also the only thing that *calls* `look` and `look_mut` at more than a couple of shapes,
    /// which matters more than it looks: the differential properties above go through
    /// [`embedded_sealed::Sealed::matches`] and so exercise [`EmbeddedStep`], while `look_mut` is the
    /// sole caller of [`EmbeddedStepMut`] -- a second, separate set of per-layer impls that delegate
    /// into [`EmbeddedMatcherMut`]. Deciding a shape matches never runs a line of it. So there is one
    /// instantiation per layer that has an `EmbeddedStepMut` impl, and the extension ones are the
    /// point: one implementation indexes `net_ext` by a cursor, the other consumes a slice, and
    /// nothing before this compared what they returned.
    macro_rules! same_layers {
        ($name:ident, $gen:expr, $outer:ty, $shape:ty, $($binding:ident),+) => {
            #[test]
            fn $name() {
                use concurrency::sync::atomic::{AtomicUsize, Ordering};
                static SEEN: AtomicUsize = AtomicUsize::new(0);
                static HIT: AtomicUsize = AtomicUsize::new(0);
                bolero::check!()
                    .with_generator($gen)
                    .for_each(|h: &Headers| {
                        let mut owned = h.clone();
                        SEEN.fetch_add(1, Ordering::Relaxed);
                        // `h` and `&mut h` cannot be held at once, so the packet is pinned across
                        // both calls and the raw addresses compared afterwards.
                        let immutable = {
                            let Some(outer) = owned.as_view::<$outer>() else {
                                return;
                            };
                            let Some(ew) = outer.as_embedded::<$shape>() else {
                                return;
                            };
                            let ($($binding,)+) = ew.look();
                            ($(std::ptr::from_ref($binding),)+)
                        };
                        HIT.fetch_add(1, Ordering::Relaxed);
                        let mutable = {
                            let outer = owned.as_view_mut::<$outer>().unwrap_or_else(|| {
                                unreachable!("the same packet matched a moment ago")
                            });
                            let ew = outer.as_embedded_mut::<$shape>().unwrap_or_else(|| {
                                unreachable!("the same shape matched a moment ago")
                            });
                            let ($($binding,)+) = ew.look_mut();
                            ($(std::ptr::from_ref(&*$binding),)+)
                        };
                        assert_eq!(
                            immutable, mutable,
                            concat!(
                                "`look` and `look_mut` selected different layers of the quoted \
                                 packet for ",
                                stringify!($shape)
                            )
                        );
                    });
                agreement_is_not_vacuous(
                    concat!("look/look_mut ", stringify!($shape)),
                    SEEN.load(Ordering::Relaxed),
                    HIT.load(Ordering::Relaxed),
                );
            }
        };
    }

    /// The strict gap check applies to the transport *enum* too, not just concrete variants.
    ///
    /// Stated as a direct assertion rather than a differential, because the immutable oracle cannot
    /// express it -- see the note above `mutable_inner_transport_enum`. That leaves the enum's own
    /// gap check with nothing else reaching it, and it is worth reaching: naming an extension makes
    /// the check strict, so a second, unnamed extension must turn a hit into a miss even though the
    /// transport pattern is the permissive one.
    ///
    /// The second extension is a clone of the first, which keeps this free of any assumption about
    /// what other extension types exist while still being two headers where the shape names one.
    #[test]
    fn the_transport_enum_still_refuses_an_unconsumed_extension() {
        bolero::check!()
            .with_generator(ShapedQuote { ext: 0, v4: false })
            .for_each(|h: &Headers| {
                let mut owned = h.clone();
                let quoted = owned
                    .embedded_ip_mut()
                    .unwrap_or_else(|| unreachable!("ShapedQuote always attaches a quote"));
                let first = quoted
                    .net_ext
                    .first()
                    .unwrap_or_else(|| unreachable!("ShapedQuote always places one extension"))
                    .clone();
                quoted.net_ext.push(first);

                let outer = owned
                    .as_view::<O4V6>()
                    .unwrap_or_else(|| unreachable!("ShapedQuote draws an ICMPv6 error"));
                assert!(
                    outer
                        .as_embedded::<(&Ipv6, &HopByHop, &EmbeddedTransport)>()
                        .is_none(),
                    "naming one extension of two matched anyway, so the gap check did not run for \
                     the transport enum"
                );
                // Not naming an extension skips the region silently, which is the other half of the
                // same rule and shows the miss above is the gap check rather than a broken shape.
                assert!(
                    outer.as_embedded::<(&Ipv6, &EmbeddedTransport)>().is_some(),
                    "a shape that never entered the extension region was refused"
                );
            });
    }

    // Network layer, both concrete and as the enum, at inner arity 1. These shapes are common
    // enough in the broad generator's output -- around one packet in twenty -- to use it.
    same_layers!(same_layers_v4_only, ShapedIcmpError, O4V4, (&Ipv4,), ip);
    same_layers!(same_layers_v6_only, ShapedIcmpError, O4V6, (&Ipv6,), ip);
    same_layers!(same_layers_net_only, ShapedIcmpError, O4V4, (&Net,), net);

    // Every truncated transport, and the transport enum.
    same_layers!(
        same_layers_v4_tcp,
        ShapedIcmpError,
        O4V4,
        (&Ipv4, &TruncatedTcp),
        ip,
        tcp
    );
    same_layers!(
        same_layers_v6_udp,
        ShapedIcmpError,
        O4V6,
        (&Ipv6, &TruncatedUdp),
        ip,
        udp
    );
    same_layers!(
        same_layers_icmp_in_icmp4,
        ShapedIcmpError,
        O4V4,
        (&Ipv4, &TruncatedIcmp4),
        ip,
        icmp
    );
    same_layers!(
        same_layers_icmp_in_icmp6,
        ShapedIcmpError,
        O4V6,
        (&Ipv6, &TruncatedIcmp6),
        ip,
        icmp
    );
    same_layers!(
        same_layers_transport_enum,
        ShapedIcmpError,
        O4V4,
        (&Net, &EmbeddedTransport),
        net,
        transport
    );

    // Every extension header, which is where the two walks diverge most: one indexes `net_ext` by a
    // cursor, the other consumes a slice. These use the narrow generator, because on the broad one
    // they matched six to twenty-three packets in twenty-four thousand -- see [`ShapedQuote`].
    //
    // Each therefore sees a quoted packet with exactly one extension, and that is not a limitation
    // of the generator but of what is expressible: embedded shapes stop at arity 3, so a shape can
    // name at most one extension, and naming one makes the gap check strict -- a second, unconsumed
    // extension is a miss. One is the only number of extensions a matching quote can carry. Cursor
    // arithmetic past position zero is consequently unreachable from here, and is covered by the
    // differential properties above, which do draw multi-extension quotes and compare the two walks
    // on the misses.
    same_layers!(
        same_layers_ext_hop_by_hop,
        ShapedQuote { ext: 0, v4: false },
        O4V6,
        (&Ipv6, &HopByHop, &TruncatedTcp),
        ip,
        ext,
        tcp
    );
    same_layers!(
        same_layers_ext_dest_opts,
        ShapedQuote { ext: 1, v4: false },
        O4V6,
        (&Ipv6, &DestOpts, &TruncatedTcp),
        ip,
        ext,
        tcp
    );
    same_layers!(
        same_layers_ext_routing,
        ShapedQuote { ext: 2, v4: false },
        O4V6,
        (&Ipv6, &Routing, &TruncatedTcp),
        ip,
        ext,
        tcp
    );
    same_layers!(
        same_layers_ext_fragment,
        ShapedQuote { ext: 3, v4: false },
        O4V6,
        (&Ipv6, &Fragment, &TruncatedTcp),
        ip,
        ext,
        tcp
    );
    same_layers!(
        same_layers_ext_v6_auth,
        ShapedQuote { ext: 4, v4: false },
        O4V6,
        (&Ipv6, &Ipv6Auth, &TruncatedTcp),
        ip,
        ext,
        tcp
    );
    same_layers!(
        same_layers_ext_v4_auth,
        ShapedQuote { ext: 0, v4: true },
        O4V4,
        (&Ipv4, &Ipv4Auth, &TruncatedTcp),
        ip,
        ext,
        tcp
    );
}
