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
//! [`EmbeddedWindow<W, U>`] is the type-level qualifier that closes
//! over a proven outer encapsulator `W` (today: [`Window<T>`]) and a
//! proven inner embedded shape `U`.  It is `repr(transparent)` over
//! `W`, so a `&Window<T>` can be re-borrowed as a
//! `&EmbeddedWindow<Window<T>, U>` after a single shape check, and
//! [`EmbeddedWindow::outer`] re-borrows back to `&W` for free.
//!
//! Construction goes through [`Window::as_embedded`], which is gated
//! per outer arity by `EmbeddedHeaders: Within<LastLayer>` -- in
//! practice that bound restricts the call site to outer shapes
//! ending in [`Icmp4`](crate::icmp4::Icmp4) or
//! [`Icmp6`](crate::icmp6::Icmp6).
//!
//! [`EmbeddedLook::look`] returns the inner refs only.  Walk back
//! through `outer()` if you also need the encapsulating layers.

#![allow(private_bounds)]
// `EmbeddedShape: embedded_sealed::Sealed` is the seal; external impls are the point we seal against.
#![allow(unsafe_code, clippy::inline_always)] // scaffolding mirrors `window.rs`; see its module docs.

use core::marker::PhantomData;

use crate::icmp4::TruncatedIcmp4;
use crate::icmp6::TruncatedIcmp6;
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::tcp::TruncatedTcp;
use crate::udp::TruncatedUdp;

use super::pat::ExtGapCheck;
use super::window::{Shape, Window};
use super::{EmbeddedHeaders, EmbeddedStart, EmbeddedTransport, Headers, Net, NetExt, Within};

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
// EmbeddedWindow<W, U> + the cd-up trait
// ===========================================================================

/// Crate-private contract: implementor refers to a packet's [`Headers`].
///
/// Used by [`EmbeddedWindow`] to navigate from a generic outer
/// encapsulator `W` down to the underlying [`Headers`] (and from there
/// to the embedded sub-section).  Today only [`Window<T>`] implements
/// this trait, but future encapsulator wrappers (Geneve, Vxlan, ...)
/// will impl it the same way, letting `EmbeddedWindow` work uniformly
/// over any "proven outer" type without per-W look impls.
pub(crate) trait HasHeaders {
    fn as_headers(&self) -> &Headers;
}

impl<T> HasHeaders for Window<T> {
    #[inline(always)]
    fn as_headers(&self) -> &Headers {
        // Window<T> is repr(transparent) over Headers; pat_mut/pat
        // expose the same via &self.0.  Use the existing pub(crate)
        // accessor to avoid re-implementing the cast here.
        Window::as_headers(self)
    }
}

/// A type-level qualifier that closes over a proven outer encapsulator
/// `W` and a proven inner [`EmbeddedShape`] `U`.
///
/// `EmbeddedWindow<W, U>` is `#[repr(transparent)]` over `W`, so a
/// `&EmbeddedWindow<W, U>` is layout-equivalent to a `&W` and the
/// [`outer`](Self::outer) re-borrow is a free reinterpret.
///
/// Today the only outer in use is [`Window<T>`]; future encapsulator
/// types (Geneve, Vxlan, nested embedded) will compose the same way:
/// `EmbeddedWindow<GeneveWindow<Window<T>, V>, U>` etc.  The recursive
/// narrowing pattern means each level of encapsulation adds one
/// type-level qualifier without mutating the layers below.
///
/// Construction goes through [`Window::as_embedded`].  There is no
/// owning constructor; private fields and the per-arity construction
/// path together prevent forging an instance with a `U` proof that
/// doesn't actually hold.
///
/// # Soundness
///
/// The `compile_fail` examples below lock in the rules that keep
/// `EmbeddedWindow<W, U>` sound, mirroring the soundness doctests on
/// [`Window`].
///
/// ## No owning constructor
///
/// Private fields prevent forging an `EmbeddedWindow<W, U>` from an
/// arbitrary `W` (E0423).  The only entry point
/// ([`Window::as_embedded`]) runs
/// [`embedded_sealed::Sealed::matches`](EmbeddedShape) before handing
/// out a reference.
///
/// ```compile_fail,E0423
/// use dataplane_net::eth::Eth;
/// use dataplane_net::ipv4::Ipv4;
/// use dataplane_net::tcp::TruncatedTcp;
/// use dataplane_net::headers::{EmbeddedWindow, Headers, Window};
/// let h = Headers::default();
/// let w: &Window<(&Eth,)> = h.as_window().unwrap();
/// let _ew: EmbeddedWindow<&Window<(&Eth,)>, (&Ipv4, &TruncatedTcp)> =
///     EmbeddedWindow(w, std::marker::PhantomData);
/// ```
///
/// ## `EmbeddedWindow<W, U>` is not [`Clone`]
///
/// Same rationale as [`Window<T>`]: cloning through a reference would
/// produce an owned proven value that bypasses the borrow lifecycle
/// (E0277: `EmbeddedWindow<W, U>: Clone` unsatisfied).
///
/// ```compile_fail,E0277
/// use dataplane_net::eth::Eth;
/// use dataplane_net::icmp4::Icmp4;
/// use dataplane_net::ipv4::Ipv4;
/// use dataplane_net::tcp::TruncatedTcp;
/// use dataplane_net::headers::{EmbeddedWindow, Headers, Window};
/// fn clone_it<T: Clone>(x: &T) -> T { x.clone() }
/// let h = Headers::default();
/// let outer: &Window<(&Eth, &Ipv4, &Icmp4)> = h.as_window().unwrap();
/// let ew = outer.as_embedded::<(&Ipv4, &TruncatedTcp)>().unwrap();
/// let _owned: EmbeddedWindow<Window<(&Eth, &Ipv4, &Icmp4)>, (&Ipv4, &TruncatedTcp)> =
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
/// use dataplane_net::headers::{Headers, Window};
/// let h = Headers::default();
/// let w: &Window<(&Eth, &Ipv4, &Tcp)> = h.as_window().unwrap();
/// let _ew = w.as_embedded::<(&Ipv4, &TruncatedTcp)>();
/// ```
#[repr(transparent)]
pub struct EmbeddedWindow<W, U>(W, PhantomData<U>);

impl<W, U> EmbeddedWindow<W, U> {
    /// Re-borrow this qualifier as the encapsulating outer.
    ///
    /// This is the `cd ..` of the encapsulation lattice -- a free
    /// reinterpret of the same allocation, since
    /// `EmbeddedWindow<W, U>` is `#[repr(transparent)]` over `W`.
    /// The `U` proof is dropped; the `W` proof is preserved.
    #[inline(always)]
    #[must_use]
    pub fn outer(&self) -> &W {
        // SAFETY: EmbeddedWindow<W, U> is repr(transparent) over W,
        // so a &EmbeddedWindow<W, U> and a &W have identical layout.
        // Dropping the U-side phantom does not change the W proof.
        let p = std::ptr::from_ref(self).cast::<W>();
        unsafe { p.as_ref_unchecked() }
    }
}

// ===========================================================================
// EmbeddedLook
// ===========================================================================

/// Extract typed references to the layers an [`EmbeddedWindow`] holds.
///
/// Implemented for each valid inner shape tuple `U`.  Returns refs to
/// the *inner* layers only -- to also see the encapsulating layers,
/// re-borrow via [`EmbeddedWindow::outer`] and call
/// [`Look::look`](super::window::Look::look) on it.
pub trait EmbeddedLook<U> {
    /// The tuple of typed references produced by [`Self::look`].
    type Refs<'a>
    where
        Self: 'a;

    /// Extract typed references to the matched inner layers.
    ///
    /// Compiles to the same sequence of variant reads as
    /// [`embedded_sealed::Sealed::matches`], plus `unwrap_unchecked`
    /// at each step; the `EmbeddedWindow<W, U>` type invariant
    /// guarantees success so the `None` branches are pruned by the
    /// optimizer.
    fn look<'a>(&'a self) -> Self::Refs<'a>
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

        impl<'x, W, $A> EmbeddedLook<(&'x $A,)> for EmbeddedWindow<W, (&'x $A,)>
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
                // SAFETY: EmbeddedWindow invariant: outer's embedded_ip is Some
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

        impl<'x, W, $A, $B> EmbeddedLook<(&'x $A, &'x $B)> for EmbeddedWindow<W, (&'x $A, &'x $B)>
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
                // SAFETY: EmbeddedWindow invariant.
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
            for EmbeddedWindow<W, (&'x $A, &'x $B, &'x $C)>
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
                // SAFETY: EmbeddedWindow invariant.
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
    };
}

impl_embedded_arity_1!(A);
impl_embedded_arity_2!(A, B);
impl_embedded_arity_3!(A, B, C);

// ===========================================================================
// Window<T>::as_embedded -- per-outer-arity construction
// ===========================================================================
//
// One impl per outer arity, gated by `EmbeddedHeaders: Within<LastLayer>`.
// In practice the bound restricts callers to outer shapes whose final
// layer is Icmp4 or Icmp6 (those are the only `Within<Icmp_>` impls for
// `EmbeddedHeaders`).  Each impl runs the inner shape's `matches` and
// the outer's `embedded_ip().is_some()` check, then casts &Window<...>
// to &EmbeddedWindow<Window<...>, U> via the repr(transparent) layout.

macro_rules! impl_as_embedded_arity_1 {
    ($A:ident) => {
        impl<'x, $A> Window<(&'x $A,)>
        where
            (&'x $A,): Shape,
            EmbeddedHeaders: Within<$A>,
        {
            /// Re-borrow this outer window as an [`EmbeddedWindow`] if
            /// the embedded section is present and matches `U`.
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedWindow<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                // SAFETY: EmbeddedWindow<Self, U> is repr(transparent)
                // over Self.  matches(e) was just verified and
                // embedded_ip() returned Some, so the U + outer
                // invariants hold.  The reference cast preserves the
                // shared borrow lifetime.
                let p = std::ptr::from_ref(self).cast::<EmbeddedWindow<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_2 {
    ($A:ident, $B:ident) => {
        impl<'x, $A, $B> Window<(&'x $A, &'x $B)>
        where
            (&'x $A, &'x $B): Shape,
            EmbeddedHeaders: Within<$B>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedWindow<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedWindow<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_3 {
    ($A:ident, $B:ident, $C:ident) => {
        impl<'x, $A, $B, $C> Window<(&'x $A, &'x $B, &'x $C)>
        where
            (&'x $A, &'x $B, &'x $C): Shape,
            EmbeddedHeaders: Within<$C>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedWindow<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedWindow<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_4 {
    ($A:ident, $B:ident, $C:ident, $D:ident) => {
        impl<'x, $A, $B, $C, $D> Window<(&'x $A, &'x $B, &'x $C, &'x $D)>
        where
            (&'x $A, &'x $B, &'x $C, &'x $D): Shape,
            EmbeddedHeaders: Within<$D>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedWindow<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedWindow<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_5 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident) => {
        impl<'x, $A, $B, $C, $D, $E> Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)>
        where
            (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E): Shape,
            EmbeddedHeaders: Within<$E>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedWindow<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedWindow<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_6 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F> Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)>
        where
            (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F): Shape,
            EmbeddedHeaders: Within<$F>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedWindow<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedWindow<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_7 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident, $G:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F, $G>
            Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)>
        where
            (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G): Shape,
            EmbeddedHeaders: Within<$G>,
        {
            #[inline]
            #[must_use]
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedWindow<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedWindow<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
            }
        }
    };
}

macro_rules! impl_as_embedded_arity_8 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident, $G:ident, $H:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F, $G, $H>
            Window<(
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
            pub fn as_embedded<U>(&self) -> Option<&EmbeddedWindow<Self, U>>
            where
                U: EmbeddedShape,
            {
                let e = self.as_headers().embedded_ip()?;
                if !<U as embedded_sealed::Sealed>::matches(e) {
                    return None;
                }
                let p = std::ptr::from_ref(self).cast::<EmbeddedWindow<Self, U>>();
                Some(unsafe { p.as_ref_unchecked() })
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
    // EmbeddedWindow<W, U> use-site tests
    // -----------------------------------------------------------------------

    use crate::eth::Eth;
    use crate::headers::Window;
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
        let outer: &Window<OuterIcmp4> = h.as_window().expect("outer shape matches");
        let ew: &EmbeddedWindow<Window<OuterIcmp4>, InnerV4Tcp> = outer
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

    // outer() is a free reborrow back to the encapsulating Window<T>:
    // the returned reference must point at the same allocation as the
    // original outer, so a roundtrip preserves identity at the byte
    // level.  Because Window<T> is repr(transparent) over Headers and
    // EmbeddedWindow<Window<T>, U> is repr(transparent) over Window<T>,
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
        let outer: &Window<OuterIcmp4> = h.as_window().unwrap();
        let outer_addr = std::ptr::from_ref(outer);
        let ew = outer.as_embedded::<InnerV4Tcp>().unwrap();
        let outer_back = ew.outer();
        assert!(std::ptr::eq(outer_back, outer_addr));
    }

    // Wrong inner shape returns None; the outer Window stays valid.
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
        let outer: &Window<OuterIcmp4> = h.as_window().unwrap();
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
        let outer: &Window<OuterIcmp4> = h.as_window().unwrap();
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
        let outer: &Window<OuterIcmp6> = h.as_window().unwrap();
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
        let outer: &Window<OuterIcmp4> = h.as_window().unwrap();
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
                    .as_window::<OuterIcmp4>()
                    .and_then(|w| w.as_embedded::<InnerV4Tcp>())
                    .is_some();
                assert_eq!(
                    pat_hit, win_hit,
                    "as_embedded disagrees with pat.rs full chain"
                );
            });
    }
}
