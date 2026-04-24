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
//! re-validating at each access site.
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
//! * External callers see only [`Window`] and [`Look`].  They cannot
//!   implement [`WindowStep`] or call it directly, so they cannot
//!   forge a `Window<T>` that sidesteps `matches`.
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

use super::pat::ExtGapCheck;
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
/// Extract typed references via [`Look::look`].
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
}
