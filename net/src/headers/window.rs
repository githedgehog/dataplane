// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type-carried structural proofs over [`Headers`].
//!
//! A [`Window<T>`] is a [`Headers`] whose layer structure has been
//! validated against the tuple type `T`.  The validation reuses the
//! same [`Within<T>`] adjacency graph and [`ExtGapCheck`] machinery as
//! [`Matcher`](super::pat::Matcher), so a `Window` enforces the exact
//! same "no silently skipped layers" semantics:
//!
//! * VLAN tags that are not mentioned in the shape cause `as_window`
//!   to return `None`.  A `Window<(&Eth, &Ipv4, &Tcp)>` on a
//!   VLAN-tagged packet is a miss; the caller must write a shape
//!   that includes `&Vlan` to accept such a packet.
//! * IPv6 extension headers are skipped silently when the shape
//!   crosses directly from an IP layer to a transport layer, but
//!   matching becomes strict once the shape enters the extension
//!   region, with [`ExtGapCheck`] enforcing the same contract used
//!   by [`Matcher`](super::pat::Matcher).
//!
//! Downstream code that receives a `&Window<T>` can extract typed
//! references to the matched layers via the [`Look`] trait without
//! re-validating at each access site.  For mutable access, a
//! `&mut Window<T>` yields `&mut` references via [`LookMut::look_mut`],
//! which delegates to [`MatcherMut`](super::pat::MatcherMut) so the
//! multi-`&mut` tuple is built from the same pre-split
//! [`Fields`](super::pat::Fields) helper used by the rest of the
//! matcher.
//!
//! # Safety boundary
//!
//! Zero-cost extraction is achieved by informing the optimizer, via
//! `Option::unwrap_unchecked`, that the `Window` type invariant rules
//! out the `None` arms of each [`WindowStep::step`] call.  The
//! `unsafe` required for this is fully contained:
//!
//! * [`Headers::as_window`] / [`Headers::as_window_mut`] are the only
//!   ways to obtain a `&Window<T>` / `&mut Window<T>`, and they run
//!   the [`sealed::Sealed::matches`] check -- which threads the same
//!   cursors and gap checks as [`WindowStep::step`] would -- before
//!   the `#[repr(transparent)]` reference cast.
//! * [`WindowStep`] is crate-private.  Its `step` method is a safe
//!   `Option`-returning function; [`Look::look`] simply invokes it
//!   and unwraps unchecked, relying on the `Window<T>` newtype
//!   invariant.
//! * [`WindowStepMut`] is crate-private and mirrors `WindowStep` for
//!   the mutable path, dispatching to
//!   [`MatcherMut`](super::pat::MatcherMut) so aliasing of the
//!   returned `&mut` tuple is handled by the existing `Fields`
//!   pre-split.  [`LookMut::look_mut`] unwraps the chain's
//!   `Option<tuple>` unchecked under the same `Window<T>` invariant.
//! * External callers see only [`Window`], [`Look`], and [`LookMut`].
//!   They cannot implement [`WindowStep`] or [`WindowStepMut`] or call
//!   them directly, so they cannot forge a `Window<T>` that sidesteps
//!   `matches`.
//! * `Window<T>` has private fields and no owning constructor;
//!   callers can only ever hold it behind a reference borrowed from a
//!   [`Headers`].  Do not add `Clone`, `Copy`, or any API that
//!   produces an owned `Window<T>` without revisiting this contract
//!   -- cloning through `&Window<T>` would manufacture an owned
//!   shape-proven value that bypasses the borrow and outlives its
//!   source.
//!
//! This matches the "safe abstraction built from local unsafe
//! scaffolding" pattern in `development/code/unsafe-code.md`.

#![allow(private_bounds)] // `Shape: sealed::Sealed` is the seal; external impls are the point we seal against.
#![allow(unsafe_code, clippy::inline_always)] // scaffolding for safe Window abstraction; see module docs

use core::marker::PhantomData;

use crate::eth::Eth;
use crate::icmp4::Icmp4;
use crate::icmp6::Icmp6;
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::tcp::Tcp;
use crate::udp::{Udp, UdpEncap};
use crate::vlan::Vlan;
use crate::vxlan::Vxlan;

use super::pat::{ExtGapCheck, MatcherMut, TupleAppend};
use super::{Headers, Net, NetExt, Transport, Within};

// ===========================================================================
// Window<T>
// ===========================================================================

/// A [`Headers`] whose structural shape has been validated at
/// construction to match the tuple type parameter `T`.
///
/// `T` is a reference-tuple marker (e.g. `(&Eth,)`,
/// `(&Eth, &Ipv4, &Tcp)`).  Its presence at the type level asserts
/// that the underlying [`Headers`] contains those layers in that
/// order, with no silently skipped intermediate layers (see module
/// docs on VLAN and IPv6 extension header semantics).
///
/// Obtain via [`Headers::as_window`] or [`Headers::as_window_mut`].
/// Extract typed references via [`Look::look`] or
/// [`LookMut::look_mut`].
///
/// # Soundness
///
/// The `compile_fail` examples below lock in the rules that keep
/// `Window<T>` sound.  Each reproduces a would-be foot-gun and
/// documents, via the compiler, that the path is closed.
///
/// ## No owning constructor
///
/// Private fields prevent forging a `Window<T>` from an arbitrary
/// `Headers` (E0423).  The only entry points
/// ([`Headers::as_window`] / [`Headers::as_window_mut`]) run
/// [`sealed::Sealed::matches`](Shape) before handing out a
/// reference.
///
/// ```compile_fail,E0423
/// use dataplane_net::eth::Eth;
/// use dataplane_net::headers::{Headers, Window};
/// let h = Headers::default();
/// let _w: Window<(&Eth,)> = Window(h, std::marker::PhantomData);
/// ```
///
/// ## `Window<T>` is not [`Clone`]
///
/// Cloning through a `&Window<T>` would manufacture an owned
/// shape-proven value that outlives its borrow of `Headers`
/// (E0277: `Window<T>: Clone` unsatisfied).
///
/// ```compile_fail,E0277
/// use dataplane_net::eth::Eth;
/// use dataplane_net::headers::{Headers, Window};
/// fn clone_it<T: Clone>(x: &T) -> T { x.clone() }
/// let h = Headers::default();
/// let w: &Window<(&Eth,)> = h.as_window().unwrap();
/// let _owned: Window<(&Eth,)> = clone_it(w);
/// ```
///
/// ## No deref to [`Headers`]
///
/// `Window<T>` does not implement [`Deref`](std::ops::Deref) or
/// [`DerefMut`](std::ops::DerefMut) with
/// `Target = Headers`.  If it did, a caller holding
/// `&mut Window<T>` could reshape the underlying data while the
/// `PhantomData<T>` proof stayed intact (E0599: no method found --
/// `Window` does not autoderef to `Headers`).
///
/// ```compile_fail,E0599
/// use dataplane_net::eth::Eth;
/// use dataplane_net::headers::Headers;
/// let mut h = Headers::default();
/// let w = h.as_window_mut::<(&Eth,)>().unwrap();
/// let _ = w.eth_mut();
/// ```
///
/// ## [`LookMut::look_mut`] is exclusive per borrow
///
/// The `&mut` tuple returned by `look_mut` transitively borrows the
/// `Window`, so it cannot be called twice concurrently (E0499:
/// cannot borrow `*w` as mutable more than once at a time).
///
/// ```compile_fail,E0499
/// use dataplane_net::eth::Eth;
/// use dataplane_net::headers::{Headers, LookMut};
/// let mut h = Headers::default();
/// let w = h.as_window_mut::<(&Eth,)>().unwrap();
/// let (eth1,) = w.look_mut();
/// let (_eth2,) = w.look_mut();
/// let _keepalive = eth1;
/// ```
///
/// ## `WindowStep` is crate-private
///
/// External crates cannot implement `WindowStep`, so they cannot
/// add new per-layer extraction logic and thereby forge a
/// `Window<T>` that sidesteps `matches` (E0603: trait is private).
///
/// ```compile_fail,E0603
/// use dataplane_net::headers::window::WindowStep;
/// ```
///
/// ## `WindowStepMut` is crate-private
///
/// Same seal on the mutable side (E0603).
///
/// ```compile_fail,E0603
/// use dataplane_net::headers::window::WindowStepMut;
/// ```
///
/// ## `Shape` is sealed
///
/// Implementing `Shape` externally requires implementing the
/// crate-private `sealed::Sealed` supertrait -- which is
/// impossible -- so the set of valid shapes is fixed by this
/// module (E0277: `Fake: sealed::Sealed` unsatisfied).
///
/// ```compile_fail,E0277
/// use dataplane_net::headers::Shape;
/// struct Fake;
/// impl Shape for Fake {}
/// ```
#[repr(transparent)]
pub struct Window<T>(Headers, PhantomData<T>);

// ===========================================================================
// Shape
// ===========================================================================

/// Declared, checkable shapes for [`Window<T>`].
///
/// Any tuple whose layers chain through the [`Within<T>`] adjacency
/// graph and the [`WindowStep<Pos>`] trait is a [`Shape`].  External
/// crates cannot add new shapes (they cannot implement `WindowStep`),
/// but they can write any existing shape at the type level and let the
/// trait bounds do the filtering.
pub trait Shape: sealed::Sealed {}

mod sealed {
    use super::Headers;

    pub trait Sealed {
        /// Check that `h`'s structure matches this shape.
        fn matches(h: &Headers) -> bool;
    }
}

// ===========================================================================
// ShapePrefix -- free downgrade via AsRef
// ===========================================================================

/// Type-level "Self is a prefix of `Wide`."
///
/// If `ShapePrefix<Wide>` is implemented for `Narrow`, then any
/// `Headers` that satisfies `Wide` also satisfies `Narrow`, and by
/// extension `&Window<Wide>` can be viewed as `&Window<Narrow>` for
/// free (see the [`AsRef`] blanket impl below).
///
/// Two provenance rules:
/// * Reflexive: every shape is a prefix of itself (blanket impl).
/// * Structural: an N-arity tuple is a prefix of an M-arity tuple
///   (N < M) iff both sides are valid shapes and the first N elements
///   agree.  One impl per `(N, M)` arity pair is emitted below.
///
/// Sealed via [`Shape`]: callers can use `ShapePrefix` as a bound but
/// cannot introduce new lattice elements.
pub trait ShapePrefix<Wide>: Shape
where
    Wide: Shape,
{
}

/// Reflexive: every shape is a prefix of itself.
impl<T: Shape> ShapePrefix<T> for T {}

/// Free downgrade: if `Narrow` is a prefix of `Wide`, then
/// `&Window<Wide>` can be viewed as `&Window<Narrow>` with no runtime
/// cost (same `#[repr(transparent)]` layout, narrower type-level
/// claim).
impl<Narrow, Wide> AsRef<Window<Narrow>> for Window<Wide>
where
    Narrow: ShapePrefix<Wide>,
    Wide: Shape,
{
    #[inline]
    fn as_ref(&self) -> &Window<Narrow> {
        // SAFETY: Window<_> is #[repr(transparent)] over Headers.
        // `Narrow: ShapePrefix<Wide>` plus the existing `Wide` proof
        // on `self` means `Headers` inside `self` also satisfies
        // `Narrow`; reinterpreting the reference is sound.
        let x = std::ptr::from_ref(self).cast::<Window<Narrow>>();
        unsafe { x.as_ref_unchecked() }
    }
}

// ===========================================================================
// Headers::as_window / as_window_mut
// ===========================================================================

impl Headers {
    /// Borrow `self` as a [`Window<T>`] if its structure matches `T`.
    ///
    /// Returns `None` if the shape doesn't match; does not move out
    /// of `self`.  This is the sole path to a `&Window<T>` -- there
    /// is no owning constructor.
    #[inline]
    #[must_use]
    pub fn as_window<T>(&self) -> Option<&Window<T>>
    where
        T: Shape,
    {
        if <T as sealed::Sealed>::matches(self) {
            // SAFETY: `matches` returned true, so the Window<T> shape
            // invariant holds for this Headers.  Window<T> is
            // #[repr(transparent)] over Headers, so a &Headers and
            // &Window<T> have identical representations.
            let x = std::ptr::from_ref(self).cast::<Window<T>>();
            Some(unsafe { x.as_ref_unchecked() })
        } else {
            None
        }
    }

    /// Mutable borrow of `self` as a `&mut Window<T>` if its structure
    /// matches `T`.  Same invariant and cast as [`Self::as_window`].
    #[inline]
    #[must_use]
    pub fn as_window_mut<T>(&mut self) -> Option<&mut Window<T>>
    where
        T: Shape,
    {
        if <T as sealed::Sealed>::matches(self) {
            // SAFETY: same as as_window, with exclusive borrow preserved.
            let x = std::ptr::from_mut(self).cast::<Window<T>>();
            Some(unsafe { x.as_mut_unchecked() })
        } else {
            None
        }
    }
}

impl<T> Window<T> {
    /// Crate-private accessor used by [`EmbeddedWindow`](super::embedded_window::EmbeddedWindow)
    /// to reach the underlying [`Headers`] for embedded-section navigation.
    /// Not exposed publicly: callers outside the crate must go through
    /// [`Look::look`] / [`LookMut::look_mut`] / [`Headers::as_window`].
    #[inline]
    pub(crate) fn as_headers(&self) -> &Headers {
        &self.0
    }

    /// Crate-private mutable counterpart of [`Self::as_headers`].
    /// Used by `EmbeddedWindow::look_mut` to drive the embedded matcher.
    #[inline]
    pub(crate) fn as_headers_mut(&mut self) -> &mut Headers {
        &mut self.0
    }
}

// ===========================================================================
// Look
// ===========================================================================

/// Extract typed references to the layers a [`Window<T>`] holds.
///
/// Implemented for each valid shape tuple `T`.  `Refs<'a>` is the
/// tuple of references returned by [`Self::look`].
pub trait Look<T> {
    /// The tuple of typed references produced by [`Self::look`].
    type Refs<'a>
    where
        Self: 'a;

    /// Extract typed references to the matched layers.
    ///
    /// Compiles to the same sequence of field/variant reads as
    /// [`sealed::Sealed::matches`], plus `unwrap_unchecked` at each
    /// step; the `Window` type invariant guarantees success so the
    /// `None` branches are pruned by the optimizer.
    fn look<'a>(&'a self) -> Self::Refs<'a>
    where
        Self: 'a;
}

/// Mutable counterpart of [`Look`].
///
/// Yields a tuple of `&mut` references to the matched layers.  Aliasing
/// between the returned references is handled by
/// [`MatcherMut`](super::pat::MatcherMut)'s pre-split
/// [`Fields`](super::pat::Fields) -- `look_mut` delegates to a
/// `MatcherMut` chain and unwraps the result unchecked, relying on the
/// `Window<T>` shape invariant.
pub trait LookMut<T> {
    /// The tuple of typed `&mut` references produced by [`Self::look_mut`].
    type RefsMut<'a>
    where
        Self: 'a;

    /// Extract typed `&mut` references to the matched layers.
    ///
    /// Compiles to the same [`MatcherMut`](super::pat::MatcherMut) chain
    /// as the corresponding `Matcher` chain used by [`Look::look`], but
    /// mutable.  The `Window<T>` type invariant guarantees the chain
    /// matches, so the final `.done()` is unwrapped unchecked and the
    /// optimizer prunes the miss path.
    fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
    where
        Self: 'a;
}

// ===========================================================================
// WindowStep: per-layer extraction with cursor threading + gap checks
// ===========================================================================
//
// Each WindowStep<Pos> impl mirrors the corresponding Matcher method
// in `pat.rs`: net-layer steps close the VLAN phase (gap check:
// `vlan.len() == vc`) and reset the extension cursor; transport
// steps dispatch the extension-header gap check via
// `Pos::ext_gap_ok`.  Because `matches` and `look` share the same
// `step` function, the two call sites also share a single arithmetic
// recipe, and the optimizer only has to simplify it once per shape.

/// Crate-private: run a single-layer step of the shape chain.
///
/// `step` returns `Some((&Self, new_vc, new_ec))` on a hit and `None`
/// when the layer extraction or any gap check fails.  The
/// `sealed::Sealed::matches` impls call `step` to decide presence;
/// `Look::look` calls the same function and unwraps unchecked,
/// relying on the `Window` invariant.
pub(crate) trait WindowStep<Pos>: Sized {
    /// Run this layer's extraction and gap check against the current
    /// cursor state.  Returns `None` on any mismatch.
    fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&Self, u8, u8)>;
}

// ---- Entry: Eth -----------------------------------------------------------

impl WindowStep<()> for Eth {
    #[inline(always)]
    fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&Eth, u8, u8)> {
        h.eth().map(|e| (e, vc, ec))
    }
}

// ---- VLAN: advance vc, still in-phase -------------------------------------

impl<Pos> WindowStep<Pos> for Vlan
where
    Vlan: Within<Pos>,
{
    #[inline(always)]
    fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&Vlan, u8, u8)> {
        h.vlan().get(vc as usize).map(|v| (v, vc + 1, ec))
    }
}

// ---- Net layer: close VLAN phase, match variant, reset ec -----------------

macro_rules! impl_net_step {
    ($T:ty, $variant:path) => {
        impl<Pos> WindowStep<Pos> for $T
        where
            $T: Within<Pos>,
        {
            #[inline(always)]
            fn step(h: &Headers, vc: u8, _ec: u8) -> Option<(&$T, u8, u8)> {
                if h.vlan().len() != vc as usize {
                    return None;
                }
                match h.net() {
                    Some($variant(ip)) => Some((ip, vc, 0)),
                    _ => None,
                }
            }
        }
    };
}

impl_net_step!(Ipv4, Net::Ipv4);
impl_net_step!(Ipv6, Net::Ipv6);

// Net enum -- returns the &Net itself; same VLAN gap check.
impl<Pos> WindowStep<Pos> for Net
where
    Net: Within<Pos>,
{
    #[inline(always)]
    fn step(h: &Headers, vc: u8, _ec: u8) -> Option<(&Net, u8, u8)> {
        if h.vlan().len() != vc as usize {
            return None;
        }
        h.net().map(|n| (n, vc, 0))
    }
}

// ---- Extension headers: advance ec, still in-phase ------------------------

macro_rules! impl_ext_step {
    ($T:ty, $variant:path) => {
        impl<Pos> WindowStep<Pos> for $T
        where
            $T: Within<Pos>,
        {
            #[inline(always)]
            fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&$T, u8, u8)> {
                match h.net_ext().get(ec as usize) {
                    Some($variant(v)) => Some((v, vc, ec + 1)),
                    _ => None,
                }
            }
        }
    };
}

impl_ext_step!(HopByHop, NetExt::HopByHop);
impl_ext_step!(DestOpts, NetExt::DestOpts);
impl_ext_step!(Routing, NetExt::Routing);
impl_ext_step!(Fragment, NetExt::Fragment);
impl_ext_step!(Ipv4Auth, NetExt::Ipv4Auth);
impl_ext_step!(Ipv6Auth, NetExt::Ipv6Auth);

// ---- Transport: ExtGapCheck-dispatched strictness, variant match ----------

macro_rules! impl_transport_step {
    ($T:ty, $variant:path) => {
        impl<Pos> WindowStep<Pos> for $T
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
        {
            #[inline(always)]
            fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&$T, u8, u8)> {
                if !<Pos as ExtGapCheck>::ext_gap_ok(h, ec) {
                    return None;
                }
                match h.transport() {
                    Some($variant(t)) => Some((t, vc, ec)),
                    _ => None,
                }
            }
        }
    };
}

impl_transport_step!(Tcp, Transport::Tcp);
impl_transport_step!(Udp, Transport::Udp);
impl_transport_step!(Icmp4, Transport::Icmp4);
impl_transport_step!(Icmp6, Transport::Icmp6);

// Transport enum -- returns &Transport, same ext gap check.
impl<Pos> WindowStep<Pos> for Transport
where
    Transport: Within<Pos>,
    Pos: ExtGapCheck,
{
    #[inline(always)]
    fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&Transport, u8, u8)> {
        if !<Pos as ExtGapCheck>::ext_gap_ok(h, ec) {
            return None;
        }
        h.transport().map(|t| (t, vc, ec))
    }
}

// ---- UDP encapsulation (Vxlan): no gap check ------------------------------

impl<Pos> WindowStep<Pos> for Vxlan
where
    Vxlan: Within<Pos>,
{
    #[inline(always)]
    fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&Vxlan, u8, u8)> {
        match h.udp_encap() {
            Some(UdpEncap::Vxlan(v)) => Some((v, vc, ec)),
            _ => None,
        }
    }
}

// ===========================================================================
// WindowStepMut: mutable per-layer dispatch onto MatcherMut
// ===========================================================================
//
// The mutable side of `Look` would need multiple `&mut` references into
// the same `Headers` -- direct projection of disjoint fields is sound
// but fiddly under Stacked/Tree Borrows.  Rather than reinvent that
// bookkeeping, `WindowStepMut::chain` extends a `MatcherMut` chain by
// one layer; `MatcherMut` already solves the aliasing via its pre-split
// `Fields` helper (see `pat.rs`).  Each impl is a one-liner delegating
// to the corresponding `MatcherMut` method, so the per-layer VLAN /
// extension gap-check logic lives in one place.

/// Crate-private: extend a [`MatcherMut`] chain by one layer.
///
/// Mirrors [`WindowStep`] but dispatches through
/// [`MatcherMut`](super::pat::MatcherMut).  Reusing `MatcherMut`'s
/// pre-split [`Fields`](super::pat::Fields) keeps the borrow checker
/// happy for the multi-`&mut` tuple returned by [`LookMut::look_mut`].
pub(crate) trait WindowStepMut<Pos>: Sized {
    /// Chain this layer onto `m`.  Equivalent to calling the matching
    /// `MatcherMut` method (`.eth()`, `.vlan()`, `.ipv4()`, ...).
    fn chain<'a, Acc>(
        m: MatcherMut<'a, Pos, Acc>,
    ) -> MatcherMut<'a, Self, <Acc as TupleAppend<&'a mut Self>>::Output>
    where
        Acc: TupleAppend<&'a mut Self>;
}

// ---- Entry: Eth -----------------------------------------------------------

impl WindowStepMut<()> for Eth {
    #[inline(always)]
    fn chain<'a, Acc>(
        m: MatcherMut<'a, (), Acc>,
    ) -> MatcherMut<'a, Eth, <Acc as TupleAppend<&'a mut Eth>>::Output>
    where
        Acc: TupleAppend<&'a mut Eth>,
    {
        m.eth()
    }
}

// ---- VLAN -----------------------------------------------------------------

impl<Pos> WindowStepMut<Pos> for Vlan
where
    Vlan: Within<Pos>,
{
    #[inline(always)]
    fn chain<'a, Acc>(
        m: MatcherMut<'a, Pos, Acc>,
    ) -> MatcherMut<'a, Vlan, <Acc as TupleAppend<&'a mut Vlan>>::Output>
    where
        Acc: TupleAppend<&'a mut Vlan>,
    {
        m.vlan()
    }
}

// ---- Net layer (Ipv4 / Ipv6) and Net enum ---------------------------------

macro_rules! impl_net_step_mut {
    ($T:ty, $method:ident) => {
        impl<Pos> WindowStepMut<Pos> for $T
        where
            $T: Within<Pos>,
        {
            #[inline(always)]
            fn chain<'a, Acc>(
                m: MatcherMut<'a, Pos, Acc>,
            ) -> MatcherMut<'a, $T, <Acc as TupleAppend<&'a mut $T>>::Output>
            where
                Acc: TupleAppend<&'a mut $T>,
            {
                m.$method()
            }
        }
    };
}

impl_net_step_mut!(Ipv4, ipv4);
impl_net_step_mut!(Ipv6, ipv6);
impl_net_step_mut!(Net, net);

// ---- Extension headers ----------------------------------------------------

macro_rules! impl_ext_step_mut {
    ($T:ty, $method:ident) => {
        impl<Pos> WindowStepMut<Pos> for $T
        where
            $T: Within<Pos>,
        {
            #[inline(always)]
            fn chain<'a, Acc>(
                m: MatcherMut<'a, Pos, Acc>,
            ) -> MatcherMut<'a, $T, <Acc as TupleAppend<&'a mut $T>>::Output>
            where
                Acc: TupleAppend<&'a mut $T>,
            {
                m.$method()
            }
        }
    };
}

impl_ext_step_mut!(HopByHop, hop_by_hop);
impl_ext_step_mut!(DestOpts, dest_opts);
impl_ext_step_mut!(Routing, routing);
impl_ext_step_mut!(Fragment, fragment);
impl_ext_step_mut!(Ipv4Auth, ipv4_auth);
impl_ext_step_mut!(Ipv6Auth, ipv6_auth);

// ---- Transport layer (Tcp / Udp / Icmp4 / Icmp6) and Transport enum -------

macro_rules! impl_transport_step_mut {
    ($T:ty, $method:ident) => {
        impl<Pos> WindowStepMut<Pos> for $T
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
        {
            #[inline(always)]
            fn chain<'a, Acc>(
                m: MatcherMut<'a, Pos, Acc>,
            ) -> MatcherMut<'a, $T, <Acc as TupleAppend<&'a mut $T>>::Output>
            where
                Acc: TupleAppend<&'a mut $T>,
            {
                m.$method()
            }
        }
    };
}

impl_transport_step_mut!(Tcp, tcp);
impl_transport_step_mut!(Udp, udp);
impl_transport_step_mut!(Icmp4, icmp4);
impl_transport_step_mut!(Icmp6, icmp6);
impl_transport_step_mut!(Transport, transport);

// ---- UDP encapsulation (Vxlan) --------------------------------------------

impl<Pos> WindowStepMut<Pos> for Vxlan
where
    Vxlan: Within<Pos>,
{
    #[inline(always)]
    fn chain<'a, Acc>(
        m: MatcherMut<'a, Pos, Acc>,
    ) -> MatcherMut<'a, Vxlan, <Acc as TupleAppend<&'a mut Vxlan>>::Output>
    where
        Acc: TupleAppend<&'a mut Vxlan>,
    {
        m.vxlan()
    }
}

// ===========================================================================
// Per-arity Shape / Sealed / Look impls
// ===========================================================================
//
// One arm per arity for clarity of generated code; each arm emits the
// three impls (`Shape`, `sealed::Sealed`, `Look`) plus the cursor-
// threaded `matches` and `look` bodies.  Max arity is 8 -- no
// realistic header chain exceeds that; if one ever does, extend the
// arity range by adding a new `impl_window_arity_N!` arm below.

macro_rules! impl_window_arity_1 {
    ($A:ident) => {
        impl<'x, $A> Shape for (&'x $A,) where $A: WindowStep<()> {}

        impl<'x, $A> sealed::Sealed for (&'x $A,)
        where
            $A: WindowStep<()>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                $A::step(h, 0, 0).is_some()
            }
        }

        impl<'x, $A> Look<(&'x $A,)> for Window<(&'x $A,)>
        where
            $A: WindowStep<()>,
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
                let h = &self.0;
                // SAFETY: Window<(&A,)> invariant: matches(h) was true.
                unsafe {
                    // Propagate the Window invariant to LLVM explicitly.
                    // Without this, when `look` is called in a context
                    // where `matches` is not inline-visible (e.g. the
                    // Window came in as a function parameter), LLVM
                    // doesn't backtrack `unwrap_unchecked` through the
                    // Option-of-tuple niche and leaves redundant
                    // discriminant checks / `cmove`s in the hot path.
                    core::hint::assert_unchecked(<(&'x $A,) as sealed::Sealed>::matches(h));
                    let (a, _, _) = $A::step(h, 0, 0).unwrap_unchecked();
                    (a,)
                }
            }
        }

        impl<'x, $A> LookMut<(&'x $A,)> for Window<(&'x $A,)>
        where
            $A: WindowStep<()> + WindowStepMut<()>,
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
                unsafe {
                    // SAFETY: Window invariant: matches(&self.0) was true.
                    core::hint::assert_unchecked(<(&'x $A,) as sealed::Sealed>::matches(&self.0));
                }
                let m = self.0.pat_mut();
                let m = <$A as WindowStepMut<()>>::chain(m);
                match m.done() {
                    Some(t) => t,
                    // SAFETY: Window invariant guarantees the chain hits.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
        }
    };
}

macro_rules! impl_window_arity_2 {
    ($A:ident, $B:ident) => {
        impl<'x, $A, $B> Shape for (&'x $A, &'x $B)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
        {
        }

        impl<'x, $A, $B> sealed::Sealed for (&'x $A, &'x $B)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                let Some((_, vc, ec)) = $A::step(h, 0, 0) else {
                    return false;
                };
                $B::step(h, vc, ec).is_some()
            }
        }

        impl<'x, $A, $B> Look<(&'x $A, &'x $B)> for Window<(&'x $A, &'x $B)>
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
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
                let h = &self.0;
                // SAFETY: Window invariant: matches(h) was true.
                unsafe {
                    core::hint::assert_unchecked(<(&'x $A, &'x $B) as sealed::Sealed>::matches(h));
                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                    let (b, _, _) = $B::step(h, vc, ec).unwrap_unchecked();
                    (a, b)
                }
            }
        }

        impl<'x, $A, $B> LookMut<(&'x $A, &'x $B)> for Window<(&'x $A, &'x $B)>
        where
            $A: WindowStep<()> + WindowStepMut<()>,
            $B: WindowStep<$A> + WindowStepMut<$A>,
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
                unsafe {
                    // SAFETY: Window invariant: matches(&self.0) was true.
                    core::hint::assert_unchecked(<(&'x $A, &'x $B) as sealed::Sealed>::matches(
                        &self.0,
                    ));
                }
                let m = self.0.pat_mut();
                let m = <$A as WindowStepMut<()>>::chain(m);
                let m = <$B as WindowStepMut<$A>>::chain(m);
                match m.done() {
                    Some(t) => t,
                    // SAFETY: Window invariant guarantees the chain hits.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
        }
    };
}

macro_rules! impl_window_arity_3 {
    ($A:ident, $B:ident, $C:ident) => {
        impl<'x, $A, $B, $C> Shape for (&'x $A, &'x $B, &'x $C)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
        {
        }

        impl<'x, $A, $B, $C> sealed::Sealed for (&'x $A, &'x $B, &'x $C)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                let Some((_, vc, ec)) = $A::step(h, 0, 0) else {
                    return false;
                };
                let Some((_, vc, ec)) = $B::step(h, vc, ec) else {
                    return false;
                };
                $C::step(h, vc, ec).is_some()
            }
        }

        impl<'x, $A, $B, $C> Look<(&'x $A, &'x $B, &'x $C)> for Window<(&'x $A, &'x $B, &'x $C)>
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
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
                let h = &self.0;
                // SAFETY: Window invariant: matches(h) was true.
                unsafe {
                    core::hint::assert_unchecked(
                        <(&'x $A, &'x $B, &'x $C) as sealed::Sealed>::matches(h),
                    );
                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                    let (b, vc, ec) = $B::step(h, vc, ec).unwrap_unchecked();
                    let (c, _, _) = $C::step(h, vc, ec).unwrap_unchecked();
                    (a, b, c)
                }
            }
        }

        impl<'x, $A, $B, $C> LookMut<(&'x $A, &'x $B, &'x $C)> for Window<(&'x $A, &'x $B, &'x $C)>
        where
            $A: WindowStep<()> + WindowStepMut<()>,
            $B: WindowStep<$A> + WindowStepMut<$A>,
            $C: WindowStep<$B> + WindowStepMut<$B>,
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
                unsafe {
                    // SAFETY: Window invariant: matches(&self.0) was true.
                    core::hint::assert_unchecked(
                        <(&'x $A, &'x $B, &'x $C) as sealed::Sealed>::matches(&self.0),
                    );
                }
                let m = self.0.pat_mut();
                let m = <$A as WindowStepMut<()>>::chain(m);
                let m = <$B as WindowStepMut<$A>>::chain(m);
                let m = <$C as WindowStepMut<$B>>::chain(m);
                match m.done() {
                    Some(t) => t,
                    // SAFETY: Window invariant guarantees the chain hits.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
        }
    };
}

macro_rules! impl_window_arity_4 {
    ($A:ident, $B:ident, $C:ident, $D:ident) => {
        impl<'x, $A, $B, $C, $D> Shape for (&'x $A, &'x $B, &'x $C, &'x $D)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
        {
        }

        impl<'x, $A, $B, $C, $D> sealed::Sealed for (&'x $A, &'x $B, &'x $C, &'x $D)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                let Some((_, vc, ec)) = $A::step(h, 0, 0) else {
                    return false;
                };
                let Some((_, vc, ec)) = $B::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $C::step(h, vc, ec) else {
                    return false;
                };
                $D::step(h, vc, ec).is_some()
            }
        }

        impl<'x, $A, $B, $C, $D> Look<(&'x $A, &'x $B, &'x $C, &'x $D)>
            for Window<(&'x $A, &'x $B, &'x $C, &'x $D)>
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            Self: 'x,
        {
            type Refs<'a>
                = (&'a $A, &'a $B, &'a $C, &'a $D)
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                let h = &self.0;
                // SAFETY: Window invariant: matches(h) was true.
                unsafe {
                    core::hint::assert_unchecked(
                        <(&'x $A, &'x $B, &'x $C, &'x $D) as sealed::Sealed>::matches(h),
                    );
                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                    let (b, vc, ec) = $B::step(h, vc, ec).unwrap_unchecked();
                    let (c, vc, ec) = $C::step(h, vc, ec).unwrap_unchecked();
                    let (d, _, _) = $D::step(h, vc, ec).unwrap_unchecked();
                    (a, b, c, d)
                }
            }
        }

        impl<'x, $A, $B, $C, $D> LookMut<(&'x $A, &'x $B, &'x $C, &'x $D)>
            for Window<(&'x $A, &'x $B, &'x $C, &'x $D)>
        where
            $A: WindowStep<()> + WindowStepMut<()>,
            $B: WindowStep<$A> + WindowStepMut<$A>,
            $C: WindowStep<$B> + WindowStepMut<$B>,
            $D: WindowStep<$C> + WindowStepMut<$C>,
            Self: 'x,
        {
            type RefsMut<'a>
                = (&'a mut $A, &'a mut $B, &'a mut $C, &'a mut $D)
            where
                Self: 'a;

            #[inline(always)]
            fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
            where
                Self: 'a,
            {
                unsafe {
                    // SAFETY: Window invariant: matches(&self.0) was true.
                    core::hint::assert_unchecked(
                        <(&'x $A, &'x $B, &'x $C, &'x $D) as sealed::Sealed>::matches(&self.0),
                    );
                }
                let m = self.0.pat_mut();
                let m = <$A as WindowStepMut<()>>::chain(m);
                let m = <$B as WindowStepMut<$A>>::chain(m);
                let m = <$C as WindowStepMut<$B>>::chain(m);
                let m = <$D as WindowStepMut<$C>>::chain(m);
                match m.done() {
                    Some(t) => t,
                    // SAFETY: Window invariant guarantees the chain hits.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
        }
    };
}

macro_rules! impl_window_arity_5 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident) => {
        impl<'x, $A, $B, $C, $D, $E> Shape for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
        {
        }

        impl<'x, $A, $B, $C, $D, $E> sealed::Sealed for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                let Some((_, vc, ec)) = $A::step(h, 0, 0) else {
                    return false;
                };
                let Some((_, vc, ec)) = $B::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $C::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $D::step(h, vc, ec) else {
                    return false;
                };
                $E::step(h, vc, ec).is_some()
            }
        }

        impl<'x, $A, $B, $C, $D, $E> Look<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)>
            for Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)>
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            Self: 'x,
        {
            type Refs<'a>
                = (&'a $A, &'a $B, &'a $C, &'a $D, &'a $E)
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                let h = &self.0;
                // SAFETY: Window invariant: matches(h) was true.
                unsafe {
                    core::hint::assert_unchecked(
                        <(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E) as sealed::Sealed>::matches(h),
                    );
                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                    let (b, vc, ec) = $B::step(h, vc, ec).unwrap_unchecked();
                    let (c, vc, ec) = $C::step(h, vc, ec).unwrap_unchecked();
                    let (d, vc, ec) = $D::step(h, vc, ec).unwrap_unchecked();
                    let (e, _, _) = $E::step(h, vc, ec).unwrap_unchecked();
                    (a, b, c, d, e)
                }
            }
        }

        impl<'x, $A, $B, $C, $D, $E> LookMut<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)>
            for Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)>
        where
            $A: WindowStep<()> + WindowStepMut<()>,
            $B: WindowStep<$A> + WindowStepMut<$A>,
            $C: WindowStep<$B> + WindowStepMut<$B>,
            $D: WindowStep<$C> + WindowStepMut<$C>,
            $E: WindowStep<$D> + WindowStepMut<$D>,
            Self: 'x,
        {
            type RefsMut<'a>
                = (&'a mut $A, &'a mut $B, &'a mut $C, &'a mut $D, &'a mut $E)
            where
                Self: 'a;

            #[inline(always)]
            fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
            where
                Self: 'a,
            {
                unsafe {
                    // SAFETY: Window invariant: matches(&self.0) was true.
                    core::hint::assert_unchecked(
                        <(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E) as sealed::Sealed>::matches(
                            &self.0,
                        ),
                    );
                }
                let m = self.0.pat_mut();
                let m = <$A as WindowStepMut<()>>::chain(m);
                let m = <$B as WindowStepMut<$A>>::chain(m);
                let m = <$C as WindowStepMut<$B>>::chain(m);
                let m = <$D as WindowStepMut<$C>>::chain(m);
                let m = <$E as WindowStepMut<$D>>::chain(m);
                match m.done() {
                    Some(t) => t,
                    // SAFETY: Window invariant guarantees the chain hits.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
        }
    };
}

macro_rules! impl_window_arity_6 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F> Shape for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
        {
        }

        impl<'x, $A, $B, $C, $D, $E, $F> sealed::Sealed
            for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                let Some((_, vc, ec)) = $A::step(h, 0, 0) else {
                    return false;
                };
                let Some((_, vc, ec)) = $B::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $C::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $D::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $E::step(h, vc, ec) else {
                    return false;
                };
                $F::step(h, vc, ec).is_some()
            }
        }

        impl<'x, $A, $B, $C, $D, $E, $F> Look<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)>
            for Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)>
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
            Self: 'x,
        {
            type Refs<'a>
                = (&'a $A, &'a $B, &'a $C, &'a $D, &'a $E, &'a $F)
            where
                Self: 'a;

            // `#[rustfmt::skip]` on the fn: the
            // `<(...tuple...) as Sealed>::matches(h)` turbofish
            // inside `assert_unchecked(...)` triggers a rustfmt
            // non-idempotency bug at exactly this arity (indentation
            // grows by 8 spaces per `cargo fmt` run).  Arities 7 and
            // 8 use the same construct and format cleanly -- the
            // bug interacts with arity 6's impl-header width.
                            #[rustfmt::skip]
                            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
                            where
                                Self: 'a,
                            {
                                let h = &self.0;
                                // SAFETY: Window invariant: matches(h) was true.
                                unsafe {
                                    core::hint::assert_unchecked(<(
                                        &'x $A,
                                        &'x $B,
                                        &'x $C,
                                        &'x $D,
                                        &'x $E,
                                        &'x $F,
                                    ) as sealed::Sealed>::matches(h));
                                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                                    let (b, vc, ec) = $B::step(h, vc, ec).unwrap_unchecked();
                                    let (c, vc, ec) = $C::step(h, vc, ec).unwrap_unchecked();
                                    let (d, vc, ec) = $D::step(h, vc, ec).unwrap_unchecked();
                                    let (e, vc, ec) = $E::step(h, vc, ec).unwrap_unchecked();
                                    let (f, _, _) = $F::step(h, vc, ec).unwrap_unchecked();
                                    (a, b, c, d, e, f)
                                }
                            }
        }

        impl<'x, $A, $B, $C, $D, $E, $F>
            LookMut<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)>
            for Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)>
        where
            $A: WindowStep<()> + WindowStepMut<()>,
            $B: WindowStep<$A> + WindowStepMut<$A>,
            $C: WindowStep<$B> + WindowStepMut<$B>,
            $D: WindowStep<$C> + WindowStepMut<$C>,
            $E: WindowStep<$D> + WindowStepMut<$D>,
            $F: WindowStep<$E> + WindowStepMut<$E>,
            Self: 'x,
        {
            type RefsMut<'a>
                = (&'a mut $A, &'a mut $B, &'a mut $C, &'a mut $D, &'a mut $E, &'a mut $F)
            where
                Self: 'a;

            // `#[rustfmt::skip]`: same rustfmt non-idempotency bug as
            // the `look` method above; the nested turbofish in
            // `assert_unchecked` triggers runaway indentation at arity 6.
                            #[rustfmt::skip]
                            #[inline(always)]
            fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
                            where
                                Self: 'a,
                            {
                                unsafe {
                                    // SAFETY: Window invariant: matches(&self.0) was true.
                                    core::hint::assert_unchecked(<(
                                        &'x $A,
                                        &'x $B,
                                        &'x $C,
                                        &'x $D,
                                        &'x $E,
                                        &'x $F,
                                    ) as sealed::Sealed>::matches(&self.0));
                                }
                                let m = self.0.pat_mut();
                                let m = <$A as WindowStepMut<()>>::chain(m);
                                let m = <$B as WindowStepMut<$A>>::chain(m);
                                let m = <$C as WindowStepMut<$B>>::chain(m);
                                let m = <$D as WindowStepMut<$C>>::chain(m);
                                let m = <$E as WindowStepMut<$D>>::chain(m);
                                let m = <$F as WindowStepMut<$E>>::chain(m);
                                match m.done() {
                                    Some(t) => t,
                                    // SAFETY: Window invariant guarantees the chain hits.
                                    None => unsafe { core::hint::unreachable_unchecked() },
                                }
                            }
        }
    };
}

macro_rules! impl_window_arity_7 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident, $G:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F, $G> Shape
            for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
            $G: WindowStep<$F>,
        {
        }

        impl<'x, $A, $B, $C, $D, $E, $F, $G> sealed::Sealed
            for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
            $G: WindowStep<$F>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                let Some((_, vc, ec)) = $A::step(h, 0, 0) else {
                    return false;
                };
                let Some((_, vc, ec)) = $B::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $C::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $D::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $E::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $F::step(h, vc, ec) else {
                    return false;
                };
                $G::step(h, vc, ec).is_some()
            }
        }

        impl<'x, $A, $B, $C, $D, $E, $F, $G>
            Look<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)>
            for Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)>
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
            $G: WindowStep<$F>,
            Self: 'x,
        {
            type Refs<'a>
                = (&'a $A, &'a $B, &'a $C, &'a $D, &'a $E, &'a $F, &'a $G)
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                let h = &self.0;
                // SAFETY: Window invariant: matches(h) was true.
                unsafe {
                    core::hint::assert_unchecked(<(
                        &'x $A,
                        &'x $B,
                        &'x $C,
                        &'x $D,
                        &'x $E,
                        &'x $F,
                        &'x $G,
                    ) as sealed::Sealed>::matches(h));
                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                    let (b, vc, ec) = $B::step(h, vc, ec).unwrap_unchecked();
                    let (c, vc, ec) = $C::step(h, vc, ec).unwrap_unchecked();
                    let (d, vc, ec) = $D::step(h, vc, ec).unwrap_unchecked();
                    let (e, vc, ec) = $E::step(h, vc, ec).unwrap_unchecked();
                    let (f, vc, ec) = $F::step(h, vc, ec).unwrap_unchecked();
                    let (g, _, _) = $G::step(h, vc, ec).unwrap_unchecked();
                    (a, b, c, d, e, f, g)
                }
            }
        }

        impl<'x, $A, $B, $C, $D, $E, $F, $G>
            LookMut<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)>
            for Window<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)>
        where
            $A: WindowStep<()> + WindowStepMut<()>,
            $B: WindowStep<$A> + WindowStepMut<$A>,
            $C: WindowStep<$B> + WindowStepMut<$B>,
            $D: WindowStep<$C> + WindowStepMut<$C>,
            $E: WindowStep<$D> + WindowStepMut<$D>,
            $F: WindowStep<$E> + WindowStepMut<$E>,
            $G: WindowStep<$F> + WindowStepMut<$F>,
            Self: 'x,
        {
            type RefsMut<'a>
                = (
                &'a mut $A,
                &'a mut $B,
                &'a mut $C,
                &'a mut $D,
                &'a mut $E,
                &'a mut $F,
                &'a mut $G,
            )
            where
                Self: 'a;

            #[inline(always)]
            fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
            where
                Self: 'a,
            {
                unsafe {
                    // SAFETY: Window invariant: matches(&self.0) was true.
                    core::hint::assert_unchecked(<(
                        &'x $A,
                        &'x $B,
                        &'x $C,
                        &'x $D,
                        &'x $E,
                        &'x $F,
                        &'x $G,
                    ) as sealed::Sealed>::matches(&self.0));
                }
                let m = self.0.pat_mut();
                let m = <$A as WindowStepMut<()>>::chain(m);
                let m = <$B as WindowStepMut<$A>>::chain(m);
                let m = <$C as WindowStepMut<$B>>::chain(m);
                let m = <$D as WindowStepMut<$C>>::chain(m);
                let m = <$E as WindowStepMut<$D>>::chain(m);
                let m = <$F as WindowStepMut<$E>>::chain(m);
                let m = <$G as WindowStepMut<$F>>::chain(m);
                match m.done() {
                    Some(t) => t,
                    // SAFETY: Window invariant guarantees the chain hits.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
        }
    };
}

macro_rules! impl_window_arity_8 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident, $G:ident, $H:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F, $G, $H> Shape
            for (
                &'x $A,
                &'x $B,
                &'x $C,
                &'x $D,
                &'x $E,
                &'x $F,
                &'x $G,
                &'x $H,
            )
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
            $G: WindowStep<$F>,
            $H: WindowStep<$G>,
        {
        }

        impl<'x, $A, $B, $C, $D, $E, $F, $G, $H> sealed::Sealed
            for (
                &'x $A,
                &'x $B,
                &'x $C,
                &'x $D,
                &'x $E,
                &'x $F,
                &'x $G,
                &'x $H,
            )
        where
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
            $G: WindowStep<$F>,
            $H: WindowStep<$G>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                let Some((_, vc, ec)) = $A::step(h, 0, 0) else {
                    return false;
                };
                let Some((_, vc, ec)) = $B::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $C::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $D::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $E::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $F::step(h, vc, ec) else {
                    return false;
                };
                let Some((_, vc, ec)) = $G::step(h, vc, ec) else {
                    return false;
                };
                $H::step(h, vc, ec).is_some()
            }
        }

        impl<'x, $A, $B, $C, $D, $E, $F, $G, $H>
            Look<(
                &'x $A,
                &'x $B,
                &'x $C,
                &'x $D,
                &'x $E,
                &'x $F,
                &'x $G,
                &'x $H,
            )>
            for Window<(
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
            $A: WindowStep<()>,
            $B: WindowStep<$A>,
            $C: WindowStep<$B>,
            $D: WindowStep<$C>,
            $E: WindowStep<$D>,
            $F: WindowStep<$E>,
            $G: WindowStep<$F>,
            $H: WindowStep<$G>,
            Self: 'x,
        {
            type Refs<'a>
                = (
                &'a $A,
                &'a $B,
                &'a $C,
                &'a $D,
                &'a $E,
                &'a $F,
                &'a $G,
                &'a $H,
            )
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                let h = &self.0;
                // SAFETY: Window invariant: matches(h) was true.
                unsafe {
                    core::hint::assert_unchecked(<(
                        &'x $A,
                        &'x $B,
                        &'x $C,
                        &'x $D,
                        &'x $E,
                        &'x $F,
                        &'x $G,
                        &'x $H,
                    ) as sealed::Sealed>::matches(h));
                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                    let (b, vc, ec) = $B::step(h, vc, ec).unwrap_unchecked();
                    let (c, vc, ec) = $C::step(h, vc, ec).unwrap_unchecked();
                    let (d, vc, ec) = $D::step(h, vc, ec).unwrap_unchecked();
                    let (e, vc, ec) = $E::step(h, vc, ec).unwrap_unchecked();
                    let (f, vc, ec) = $F::step(h, vc, ec).unwrap_unchecked();
                    let (g, vc, ec) = $G::step(h, vc, ec).unwrap_unchecked();
                    let (h2, _, _) = $H::step(h, vc, ec).unwrap_unchecked();
                    (a, b, c, d, e, f, g, h2)
                }
            }
        }

        impl<'x, $A, $B, $C, $D, $E, $F, $G, $H>
            LookMut<(
                &'x $A,
                &'x $B,
                &'x $C,
                &'x $D,
                &'x $E,
                &'x $F,
                &'x $G,
                &'x $H,
            )>
            for Window<(
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
            $A: WindowStep<()> + WindowStepMut<()>,
            $B: WindowStep<$A> + WindowStepMut<$A>,
            $C: WindowStep<$B> + WindowStepMut<$B>,
            $D: WindowStep<$C> + WindowStepMut<$C>,
            $E: WindowStep<$D> + WindowStepMut<$D>,
            $F: WindowStep<$E> + WindowStepMut<$E>,
            $G: WindowStep<$F> + WindowStepMut<$F>,
            $H: WindowStep<$G> + WindowStepMut<$G>,
            Self: 'x,
        {
            type RefsMut<'a>
                = (
                &'a mut $A,
                &'a mut $B,
                &'a mut $C,
                &'a mut $D,
                &'a mut $E,
                &'a mut $F,
                &'a mut $G,
                &'a mut $H,
            )
            where
                Self: 'a;

            #[inline(always)]
            fn look_mut<'a>(&'a mut self) -> Self::RefsMut<'a>
            where
                Self: 'a,
            {
                unsafe {
                    // SAFETY: Window invariant: matches(&self.0) was true.
                    core::hint::assert_unchecked(<(
                        &'x $A,
                        &'x $B,
                        &'x $C,
                        &'x $D,
                        &'x $E,
                        &'x $F,
                        &'x $G,
                        &'x $H,
                    ) as sealed::Sealed>::matches(&self.0));
                }
                let m = self.0.pat_mut();
                let m = <$A as WindowStepMut<()>>::chain(m);
                let m = <$B as WindowStepMut<$A>>::chain(m);
                let m = <$C as WindowStepMut<$B>>::chain(m);
                let m = <$D as WindowStepMut<$C>>::chain(m);
                let m = <$E as WindowStepMut<$D>>::chain(m);
                let m = <$F as WindowStepMut<$E>>::chain(m);
                let m = <$G as WindowStepMut<$F>>::chain(m);
                let m = <$H as WindowStepMut<$G>>::chain(m);
                match m.done() {
                    Some(t) => t,
                    // SAFETY: Window invariant guarantees the chain hits.
                    None => unsafe { core::hint::unreachable_unchecked() },
                }
            }
        }
    };
}

impl_window_arity_1!(A);
impl_window_arity_2!(A, B);
impl_window_arity_3!(A, B, C);
impl_window_arity_4!(A, B, C, D);
impl_window_arity_5!(A, B, C, D, E);
impl_window_arity_6!(A, B, C, D, E, F);
impl_window_arity_7!(A, B, C, D, E, F, G);
impl_window_arity_8!(A, B, C, D, E, F, G, H);

// ===========================================================================
// Structural ShapePrefix impls
// ===========================================================================
//
// Narrow tuple (&T1, ..., &Tn) is a prefix of wide tuple
// (&T1, ..., &Tn, ..., &Tm) when both sides are themselves Shapes.
// The bounds on each impl re-require both sides to be valid, so the
// prefix relationship only exists between topologically valid shapes.
// Reflexive pairs are covered by the blanket impl above.

// Spelled out per (narrow-arity, wide-arity) pair.  28 entries total;
// mechanical but exhaustive.

// -- Narrow arity 1 --
impl<'x, A, X2> ShapePrefix<(&'x A, &'x X2)> for (&'x A,)
where
    (&'x A,): Shape,
    (&'x A, &'x X2): Shape,
{
}
impl<'x, A, X2, X3> ShapePrefix<(&'x A, &'x X2, &'x X3)> for (&'x A,)
where
    (&'x A,): Shape,
    (&'x A, &'x X2, &'x X3): Shape,
{
}
impl<'x, A, X2, X3, X4> ShapePrefix<(&'x A, &'x X2, &'x X3, &'x X4)> for (&'x A,)
where
    (&'x A,): Shape,
    (&'x A, &'x X2, &'x X3, &'x X4): Shape,
{
}
impl<'x, A, X2, X3, X4, X5> ShapePrefix<(&'x A, &'x X2, &'x X3, &'x X4, &'x X5)> for (&'x A,)
where
    (&'x A,): Shape,
    (&'x A, &'x X2, &'x X3, &'x X4, &'x X5): Shape,
{
}
impl<'x, A, X2, X3, X4, X5, X6> ShapePrefix<(&'x A, &'x X2, &'x X3, &'x X4, &'x X5, &'x X6)>
    for (&'x A,)
where
    (&'x A,): Shape,
    (&'x A, &'x X2, &'x X3, &'x X4, &'x X5, &'x X6): Shape,
{
}
impl<'x, A, X2, X3, X4, X5, X6, X7>
    ShapePrefix<(&'x A, &'x X2, &'x X3, &'x X4, &'x X5, &'x X6, &'x X7)> for (&'x A,)
where
    (&'x A,): Shape,
    (&'x A, &'x X2, &'x X3, &'x X4, &'x X5, &'x X6, &'x X7): Shape,
{
}
impl<'x, A, X2, X3, X4, X5, X6, X7, X8>
    ShapePrefix<(
        &'x A,
        &'x X2,
        &'x X3,
        &'x X4,
        &'x X5,
        &'x X6,
        &'x X7,
        &'x X8,
    )> for (&'x A,)
where
    (&'x A,): Shape,
    (
        &'x A,
        &'x X2,
        &'x X3,
        &'x X4,
        &'x X5,
        &'x X6,
        &'x X7,
        &'x X8,
    ): Shape,
{
}

// -- Narrow arity 2 --
impl<'x, A, B, X3> ShapePrefix<(&'x A, &'x B, &'x X3)> for (&'x A, &'x B)
where
    (&'x A, &'x B): Shape,
    (&'x A, &'x B, &'x X3): Shape,
{
}
impl<'x, A, B, X3, X4> ShapePrefix<(&'x A, &'x B, &'x X3, &'x X4)> for (&'x A, &'x B)
where
    (&'x A, &'x B): Shape,
    (&'x A, &'x B, &'x X3, &'x X4): Shape,
{
}
impl<'x, A, B, X3, X4, X5> ShapePrefix<(&'x A, &'x B, &'x X3, &'x X4, &'x X5)> for (&'x A, &'x B)
where
    (&'x A, &'x B): Shape,
    (&'x A, &'x B, &'x X3, &'x X4, &'x X5): Shape,
{
}
impl<'x, A, B, X3, X4, X5, X6> ShapePrefix<(&'x A, &'x B, &'x X3, &'x X4, &'x X5, &'x X6)>
    for (&'x A, &'x B)
where
    (&'x A, &'x B): Shape,
    (&'x A, &'x B, &'x X3, &'x X4, &'x X5, &'x X6): Shape,
{
}
impl<'x, A, B, X3, X4, X5, X6, X7>
    ShapePrefix<(&'x A, &'x B, &'x X3, &'x X4, &'x X5, &'x X6, &'x X7)> for (&'x A, &'x B)
where
    (&'x A, &'x B): Shape,
    (&'x A, &'x B, &'x X3, &'x X4, &'x X5, &'x X6, &'x X7): Shape,
{
}
impl<'x, A, B, X3, X4, X5, X6, X7, X8>
    ShapePrefix<(&'x A, &'x B, &'x X3, &'x X4, &'x X5, &'x X6, &'x X7, &'x X8)> for (&'x A, &'x B)
where
    (&'x A, &'x B): Shape,
    (&'x A, &'x B, &'x X3, &'x X4, &'x X5, &'x X6, &'x X7, &'x X8): Shape,
{
}

// -- Narrow arity 3 --
impl<'x, A, B, C, X4> ShapePrefix<(&'x A, &'x B, &'x C, &'x X4)> for (&'x A, &'x B, &'x C)
where
    (&'x A, &'x B, &'x C): Shape,
    (&'x A, &'x B, &'x C, &'x X4): Shape,
{
}
impl<'x, A, B, C, X4, X5> ShapePrefix<(&'x A, &'x B, &'x C, &'x X4, &'x X5)>
    for (&'x A, &'x B, &'x C)
where
    (&'x A, &'x B, &'x C): Shape,
    (&'x A, &'x B, &'x C, &'x X4, &'x X5): Shape,
{
}
impl<'x, A, B, C, X4, X5, X6> ShapePrefix<(&'x A, &'x B, &'x C, &'x X4, &'x X5, &'x X6)>
    for (&'x A, &'x B, &'x C)
where
    (&'x A, &'x B, &'x C): Shape,
    (&'x A, &'x B, &'x C, &'x X4, &'x X5, &'x X6): Shape,
{
}
impl<'x, A, B, C, X4, X5, X6, X7> ShapePrefix<(&'x A, &'x B, &'x C, &'x X4, &'x X5, &'x X6, &'x X7)>
    for (&'x A, &'x B, &'x C)
where
    (&'x A, &'x B, &'x C): Shape,
    (&'x A, &'x B, &'x C, &'x X4, &'x X5, &'x X6, &'x X7): Shape,
{
}
impl<'x, A, B, C, X4, X5, X6, X7, X8>
    ShapePrefix<(&'x A, &'x B, &'x C, &'x X4, &'x X5, &'x X6, &'x X7, &'x X8)>
    for (&'x A, &'x B, &'x C)
where
    (&'x A, &'x B, &'x C): Shape,
    (&'x A, &'x B, &'x C, &'x X4, &'x X5, &'x X6, &'x X7, &'x X8): Shape,
{
}

// -- Narrow arity 4 --
impl<'x, A, B, C, D, X5> ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x X5)>
    for (&'x A, &'x B, &'x C, &'x D)
where
    (&'x A, &'x B, &'x C, &'x D): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x X5): Shape,
{
}
impl<'x, A, B, C, D, X5, X6> ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x X5, &'x X6)>
    for (&'x A, &'x B, &'x C, &'x D)
where
    (&'x A, &'x B, &'x C, &'x D): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x X5, &'x X6): Shape,
{
}
impl<'x, A, B, C, D, X5, X6, X7> ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x X5, &'x X6, &'x X7)>
    for (&'x A, &'x B, &'x C, &'x D)
where
    (&'x A, &'x B, &'x C, &'x D): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x X5, &'x X6, &'x X7): Shape,
{
}
impl<'x, A, B, C, D, X5, X6, X7, X8>
    ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x X5, &'x X6, &'x X7, &'x X8)>
    for (&'x A, &'x B, &'x C, &'x D)
where
    (&'x A, &'x B, &'x C, &'x D): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x X5, &'x X6, &'x X7, &'x X8): Shape,
{
}

// -- Narrow arity 5 --
impl<'x, A, B, C, D, E, X6> ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x E, &'x X6)>
    for (&'x A, &'x B, &'x C, &'x D, &'x E)
where
    (&'x A, &'x B, &'x C, &'x D, &'x E): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x X6): Shape,
{
}
impl<'x, A, B, C, D, E, X6, X7> ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x E, &'x X6, &'x X7)>
    for (&'x A, &'x B, &'x C, &'x D, &'x E)
where
    (&'x A, &'x B, &'x C, &'x D, &'x E): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x X6, &'x X7): Shape,
{
}
impl<'x, A, B, C, D, E, X6, X7, X8>
    ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x E, &'x X6, &'x X7, &'x X8)>
    for (&'x A, &'x B, &'x C, &'x D, &'x E)
where
    (&'x A, &'x B, &'x C, &'x D, &'x E): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x X6, &'x X7, &'x X8): Shape,
{
}

// -- Narrow arity 6 --
impl<'x, A, B, C, D, E, F, X7> ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x E, &'x F, &'x X7)>
    for (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F)
where
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F, &'x X7): Shape,
{
}
impl<'x, A, B, C, D, E, F, X7, X8>
    ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x E, &'x F, &'x X7, &'x X8)>
    for (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F)
where
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F, &'x X7, &'x X8): Shape,
{
}

// -- Narrow arity 7 --
impl<'x, A, B, C, D, E, F, G, X8>
    ShapePrefix<(&'x A, &'x B, &'x C, &'x D, &'x E, &'x F, &'x G, &'x X8)>
    for (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F, &'x G)
where
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F, &'x G): Shape,
    (&'x A, &'x B, &'x C, &'x D, &'x E, &'x F, &'x G, &'x X8): Shape,
{
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::builder::HeaderStack;

    // ---- Positive: plain Eth/Ipv4/Tcp matches ------------------------------

    #[test]
    fn eth_ipv4_tcp_matches_plain_packet() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert!(h.as_window::<(&Eth, &Ipv4, &Tcp)>().is_some());
    }

    // ---- Wrong variant is a miss, not "absent" -----------------------------

    #[test]
    fn wrong_transport_variant_misses() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .udp(|_| {})
            .build_headers()
            .unwrap();
        assert!(h.as_window::<(&Eth, &Ipv4, &Udp)>().is_some());
        assert!(h.as_window::<(&Eth, &Ipv4, &Tcp)>().is_none());
    }

    // ---- Arity-1 sanity ----------------------------------------------------

    #[test]
    fn arity_1_eth_only_matches_eth_packet() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert!(h.as_window::<(&Eth,)>().is_some());
    }

    // ---- VLAN gap-check semantics (mirror pat.rs) --------------------------

    // Invariant: Window<(&Eth, &Ipv4, &Tcp)> must REJECT a packet with
    // a VLAN tag between Eth and Ipv4.  If this returns Some, the
    // Window has drifted from pat.rs semantics.
    #[test]
    fn plain_shape_rejects_vlan_tagged_packet() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert!(
            h.as_window::<(&Eth, &Ipv4, &Tcp)>().is_none(),
            "shape (&Eth, &Ipv4, &Tcp) must not match a VLAN-tagged packet"
        );
    }

    #[test]
    fn vlan_in_shape_matches_single_tag() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert!(h.as_window::<(&Eth, &Vlan, &Ipv4, &Tcp)>().is_some());
    }

    #[test]
    fn single_vlan_shape_rejects_double_tagged_packet() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .vlan(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert!(
            h.as_window::<(&Eth, &Vlan, &Ipv4, &Tcp)>().is_none(),
            "one &Vlan in shape must not match a double-tagged packet"
        );
    }

    #[test]
    fn look_returns_cursor_indexed_vlans() {
        use crate::vlan::Vid;
        let vid_outer = Vid::try_from(100u16).unwrap();
        let vid_inner = Vid::try_from(200u16).unwrap();
        let h = HeaderStack::new()
            .eth(|_| {})
            .vlan(|v| {
                v.set_vid(vid_outer);
            })
            .vlan(|v| {
                v.set_vid(vid_inner);
            })
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        let w = h
            .as_window::<(&Eth, &Vlan, &Vlan, &Ipv4, &Tcp)>()
            .expect("double-VLAN packet should match double-VLAN shape");
        let (_eth, v0, v1, _ip, _tcp) = w.look();
        assert_eq!(v0.vid(), vid_outer);
        assert_eq!(v1.vid(), vid_inner);
    }

    // ---- IPv6 extension header semantics -----------------------------------

    #[test]
    fn ipv6_extensions_skipped_from_ip_position() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        // Shape enters transport directly from Ipv6 -> extension is skipped.
        assert!(h.as_window::<(&Eth, &Ipv6, &Tcp)>().is_some());
        // Explicitly matching the extension also works.
        assert!(h.as_window::<(&Eth, &Ipv6, &HopByHop, &Tcp)>().is_some());
    }

    #[test]
    fn ipv6_extensions_strict_when_entered() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .dest_opts(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        // Entered but incomplete: the DestOpts is unconsumed -> miss.
        assert!(
            h.as_window::<(&Eth, &Ipv6, &HopByHop, &Tcp)>().is_none(),
            "entered extension region but DestOpts unconsumed: must miss"
        );
        // Entered and complete.
        assert!(
            h.as_window::<(&Eth, &Ipv6, &HopByHop, &DestOpts, &Tcp)>()
                .is_some()
        );
        // Skipped from Ipv6 position: allowed.
        assert!(h.as_window::<(&Eth, &Ipv6, &Tcp)>().is_some());
    }

    #[test]
    fn look_returns_cursor_indexed_extensions() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .dest_opts(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        let w = h
            .as_window::<(&Eth, &Ipv6, &HopByHop, &DestOpts, &Tcp)>()
            .expect("two-extension packet should match two-extension shape");
        // Smoke test: look compiles and destructures all five refs.
        let (_eth, _ip, _hbh, _do, _tcp) = w.look();
    }

    // ---- Wrong net variant is a miss ---------------------------------------

    #[test]
    fn wrong_net_variant_misses() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv6(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();
        assert!(h.as_window::<(&Eth, &Ipv6, &Tcp)>().is_some());
        assert!(h.as_window::<(&Eth, &Ipv4, &Tcp)>().is_none());
    }

    // ---- ShapePrefix / AsRef zero-cost downgrade --------------------------

    // Exercises the `#[repr(transparent)]` reference cast in
    // `AsRef<Window<Narrow>> for Window<Wide>`.  After the downgrade,
    // `look()` on the narrow Window must return references identical
    // (by pointer) to the corresponding slots of the wide Window --
    // the whole point of the cast is that it carries no runtime work.
    #[test]
    fn wide_window_downgrades_via_as_ref() {
        let h = HeaderStack::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();

        let wide: &Window<(&Eth, &Ipv4, &Tcp)> =
            h.as_window().expect("plain L4 packet matches wide shape");
        let (eth_w, ip_w, tcp_w) = wide.look();

        // Strict prefix: drop the transport layer.
        let narrow2: &Window<(&Eth, &Ipv4)> = wide.as_ref();
        let (eth_n, ip_n) = narrow2.look();
        assert!(std::ptr::eq(eth_w, eth_n));
        assert!(std::ptr::eq(ip_w, ip_n));

        // Strict prefix all the way down to just Eth.
        let narrow1: &Window<(&Eth,)> = wide.as_ref();
        let (eth_1,) = narrow1.look();
        assert!(std::ptr::eq(eth_w, eth_1));

        // Keep tcp_w alive so clippy doesn't flag it as unused above.
        let _ = tcp_w;
    }
    // -----------------------------------------------------------------------
    // Cross-consistency with pat.rs Matcher.
    //
    // Matcher is the reference implementation of the layer-ordering and
    // gap-check semantics.  `Window` is supposed to express the same
    // semantics at the type level.  These property tests assert that the
    // two APIs cannot disagree on match/miss -- and when both hit, they
    // return references to the same layer instances.  If either
    // property fails for any generated Headers, one of the APIs has
    // drifted and the test will flag the divergence.
    // -----------------------------------------------------------------------

    use crate::headers::builder::header_chain;

    #[test]
    fn window_v4_tcp_agrees_with_matcher() {
        let plain = header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {});
        let vlan_tagged = header_chain()
            .eth(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {});
        let udp_instead = header_chain().eth(|_| {}).ipv4(|_| {}).udp(|_| {});
        let v6_instead = header_chain().eth(|_| {}).ipv6(|_| {}).tcp(|_| {});
        bolero::check!()
            .with_generator((plain, vlan_tagged, udp_instead, v6_instead))
            .for_each(|(a, b, c, d)| {
                for h in [a, b, c, d] {
                    let w = h.as_window::<(&Eth, &Ipv4, &Tcp)>();
                    let m = h.pat().eth().ipv4().tcp().done();
                    assert_eq!(w.is_some(), m.is_some(), "disagree on (Eth, Ipv4, Tcp)");
                    if let (Some(w), Some((eth_m, ip_m, tcp_m))) = (w, m) {
                        let (eth_w, ip_w, tcp_w) = w.look();
                        assert!(std::ptr::eq(eth_w, eth_m));
                        assert!(std::ptr::eq(ip_w, ip_m));
                        assert!(std::ptr::eq(tcp_w, tcp_m));
                    }
                }
            });
    }

    #[test]
    fn window_vlan_v4_tcp_agrees_with_matcher() {
        let zero = header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {});
        let one = header_chain()
            .eth(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {});
        let two = header_chain()
            .eth(|_| {})
            .vlan(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {});
        bolero::check!()
            .with_generator((zero, one, two))
            .for_each(|(a, b, c)| {
                for h in [a, b, c] {
                    let w = h.as_window::<(&Eth, &Vlan, &Ipv4, &Tcp)>();
                    let m = h.pat().eth().vlan().ipv4().tcp().done();
                    assert_eq!(
                        w.is_some(),
                        m.is_some(),
                        "disagree on (Eth, Vlan, Ipv4, Tcp)"
                    );
                    if let (Some(w), Some((eth_m, v_m, ip_m, tcp_m))) = (w, m) {
                        let (eth_w, v_w, ip_w, tcp_w) = w.look();
                        assert!(std::ptr::eq(eth_w, eth_m));
                        assert!(std::ptr::eq(v_w, v_m));
                        assert!(std::ptr::eq(ip_w, ip_m));
                        assert!(std::ptr::eq(tcp_w, tcp_m));
                    }
                }
            });
    }

    #[test]
    fn window_v6_tcp_ext_skip_agrees_with_matcher() {
        // From an IP position, extension headers are skipped silently.
        // Window and Matcher must agree on this.
        let no_ext = header_chain().eth(|_| {}).ipv6(|_| {}).tcp(|_| {});
        let one_ext = header_chain()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .tcp(|_| {});
        let two_ext = header_chain()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .dest_opts(|_| {})
            .tcp(|_| {});
        bolero::check!()
            .with_generator((no_ext, one_ext, two_ext))
            .for_each(|(a, b, c)| {
                for h in [a, b, c] {
                    let w = h.as_window::<(&Eth, &Ipv6, &Tcp)>();
                    let m = h.pat().eth().ipv6().tcp().done();
                    assert_eq!(w.is_some(), m.is_some(), "disagree on (Eth, Ipv6, Tcp)");
                    if let (Some(w), Some((eth_m, ip_m, tcp_m))) = (w, m) {
                        let (eth_w, ip_w, tcp_w) = w.look();
                        assert!(std::ptr::eq(eth_w, eth_m));
                        assert!(std::ptr::eq(ip_w, ip_m));
                        assert!(std::ptr::eq(tcp_w, tcp_m));
                    }
                }
            });
    }

    #[test]
    fn window_v6_hbh_tcp_ext_strict_agrees_with_matcher() {
        // With HopByHop in the shape, extension-header strictness kicks
        // in: trailing extensions must be consumed.  Verify Window and
        // Matcher both treat this correctly.
        let exactly_hbh = header_chain()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .tcp(|_| {});
        let hbh_plus_do = header_chain()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .dest_opts(|_| {})
            .tcp(|_| {});
        let no_ext = header_chain().eth(|_| {}).ipv6(|_| {}).tcp(|_| {});
        bolero::check!()
            .with_generator((exactly_hbh, hbh_plus_do, no_ext))
            .for_each(|(a, b, c)| {
                for h in [a, b, c] {
                    let w = h.as_window::<(&Eth, &Ipv6, &HopByHop, &Tcp)>();
                    let m = h.pat().eth().ipv6().hop_by_hop().tcp().done();
                    assert_eq!(
                        w.is_some(),
                        m.is_some(),
                        "disagree on (Eth, Ipv6, HopByHop, Tcp)"
                    );
                    if let (Some(w), Some((eth_m, ip_m, hbh_m, tcp_m))) = (w, m) {
                        let (eth_w, ip_w, hbh_w, tcp_w) = w.look();
                        assert!(std::ptr::eq(eth_w, eth_m));
                        assert!(std::ptr::eq(ip_w, ip_m));
                        assert!(std::ptr::eq(hbh_w, hbh_m));
                        assert!(std::ptr::eq(tcp_w, tcp_m));
                    }
                }
            });
    }

    // -----------------------------------------------------------------------
    // LookMut cross-consistency with Look.
    //
    // `look_mut` dispatches through `MatcherMut`, not `WindowStep::step`.
    // These tests assert that, on the same Headers, `look_mut` and `look`
    // hit the same layers and return references at identical addresses.
    // Because holding `&h` and `&mut h` simultaneously is impossible, the
    // closure clones `h` and does each path on the clone: since the clone
    // is fixed in memory for the duration of both paths, the pointers
    // must be equal if and only if both APIs pick the same layer slots.
    // -----------------------------------------------------------------------

    #[test]
    fn look_mut_v4_tcp_agrees_with_look() {
        use std::ptr::from_ref;
        let plain = header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {});
        let vlan_tagged = header_chain()
            .eth(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {});
        let udp_instead = header_chain().eth(|_| {}).ipv4(|_| {}).udp(|_| {});
        let v6_instead = header_chain().eth(|_| {}).ipv6(|_| {}).tcp(|_| {});
        bolero::check!()
            .with_generator((plain, vlan_tagged, udp_instead, v6_instead))
            .for_each(|(a, b, c, d)| {
                for src in [a, b, c, d] {
                    let mut h = src.clone();
                    let imm: Option<(*const Eth, *const Ipv4, *const Tcp)> =
                        h.as_window::<(&Eth, &Ipv4, &Tcp)>().map(|w| {
                            let (e, i, t) = w.look();
                            (from_ref(e), from_ref(i), from_ref(t))
                        });
                    let mutp: Option<(*const Eth, *const Ipv4, *const Tcp)> =
                        h.as_window_mut::<(&Eth, &Ipv4, &Tcp)>().map(|w| {
                            let (e, i, t) = w.look_mut();
                            (from_ref(&*e), from_ref(&*i), from_ref(&*t))
                        });
                    assert_eq!(imm.is_some(), mutp.is_some(), "LookMut disagrees on hit");
                    if let (Some(i), Some(m)) = (imm, mutp) {
                        assert_eq!(i, m, "LookMut picked different (Eth, Ipv4, Tcp) slots");
                    }
                }
            });
    }

    #[test]
    fn look_mut_vlan_v4_tcp_agrees_with_look() {
        use std::ptr::from_ref;
        let zero = header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {});
        let one = header_chain()
            .eth(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {});
        let two = header_chain()
            .eth(|_| {})
            .vlan(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {});
        bolero::check!()
            .with_generator((zero, one, two))
            .for_each(|(a, b, c)| {
                for src in [a, b, c] {
                    let mut headers = src.clone();
                    let imm: Option<(*const Eth, *const Vlan, *const Ipv4, *const Tcp)> =
                        headers.as_window::<(&Eth, &Vlan, &Ipv4, &Tcp)>().map(|w| {
                            let (eth, vlan, ip, tcp) = w.look();
                            (from_ref(eth), from_ref(vlan), from_ref(ip), from_ref(tcp))
                        });
                    let mutp: Option<(*const Eth, *const Vlan, *const Ipv4, *const Tcp)> = headers
                        .as_window_mut::<(&Eth, &Vlan, &Ipv4, &Tcp)>()
                        .map(|w| {
                            let (eth, vlan, ip, tcp) = w.look_mut();
                            (
                                from_ref(&*eth),
                                from_ref(&*vlan),
                                from_ref(&*ip),
                                from_ref(&*tcp),
                            )
                        });
                    assert_eq!(imm.is_some(), mutp.is_some());
                    if let (Some(i), Some(m)) = (imm, mutp) {
                        assert_eq!(
                            i, m,
                            "LookMut picked different (Eth, Vlan, Ipv4, Tcp) slots"
                        );
                    }
                }
            });
    }

    #[test]
    fn look_mut_v6_hbh_tcp_agrees_with_look() {
        use std::ptr::from_ref;
        // Exercises the ext-gap-strict path on the mutable side as well.
        let exactly_hbh = header_chain()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .tcp(|_| {});
        let hbh_plus_do = header_chain()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .dest_opts(|_| {})
            .tcp(|_| {});
        let no_ext = header_chain().eth(|_| {}).ipv6(|_| {}).tcp(|_| {});
        bolero::check!()
            .with_generator((exactly_hbh, hbh_plus_do, no_ext))
            .for_each(|(a, b, c)| {
                for src in [a, b, c] {
                    let mut headers = src.clone();
                    let imm: Option<(*const Eth, *const Ipv6, *const HopByHop, *const Tcp)> =
                        headers
                            .as_window::<(&Eth, &Ipv6, &HopByHop, &Tcp)>()
                            .map(|w| {
                                let (eth, ip, hbh, tcp) = w.look();
                                (from_ref(eth), from_ref(ip), from_ref(hbh), from_ref(tcp))
                            });
                    let mutp: Option<(*const Eth, *const Ipv6, *const HopByHop, *const Tcp)> =
                        headers
                            .as_window_mut::<(&Eth, &Ipv6, &HopByHop, &Tcp)>()
                            .map(|w| {
                                let (eth, ip, hbh, tcp) = w.look_mut();
                                (
                                    from_ref(&*eth),
                                    from_ref(&*ip),
                                    from_ref(&*hbh),
                                    from_ref(&*tcp),
                                )
                            });
                    assert_eq!(imm.is_some(), mutp.is_some());
                    if let (Some(i), Some(m)) = (imm, mutp) {
                        assert_eq!(
                            i, m,
                            "LookMut picked different (Eth, Ipv6, HopByHop, Tcp) slots"
                        );
                    }
                }
            });
    }

    // Mutation through look_mut must actually take effect on the backing
    // Headers.  Uses look afterwards to observe the change.
    #[test]
    fn look_mut_mutation_propagates_to_headers() {
        use crate::vlan::Vid;
        let vid_initial = Vid::try_from(100u16).unwrap();
        let vid_updated = Vid::try_from(4000u16).unwrap();
        let mut h = HeaderStack::new()
            .eth(|_| {})
            .vlan(|v| {
                v.set_vid(vid_initial);
            })
            .ipv4(|_| {})
            .tcp(|_| {})
            .build_headers()
            .unwrap();

        {
            let w = h
                .as_window_mut::<(&Eth, &Vlan, &Ipv4, &Tcp)>()
                .expect("shape matches");
            let (_eth, v, _ip, _tcp) = w.look_mut();
            v.set_vid(vid_updated);
        }

        let w = h
            .as_window::<(&Eth, &Vlan, &Ipv4, &Tcp)>()
            .expect("shape matches");
        let (_eth, v, _ip, _tcp) = w.look();
        assert_eq!(v.vid(), vid_updated);
    }
}
