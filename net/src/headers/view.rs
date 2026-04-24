// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type-carried structural proofs over [`Headers`].
//!
//! A [`HeadersView<T>`] is a [`Headers`] whose layer structure has been
//! validated against the tuple type `T`.  The validation reuses the
//! same [`Within<T>`] adjacency graph and [`ExtGapCheck`] machinery as
//! [`Matcher`](super::pat::Matcher), so a `HeadersView` enforces the exact
//! same "no silently skipped layers" semantics:
//!
//! * VLAN tags that are not mentioned in the shape cause `as_view`
//!   to return `None`.  A `HeadersView<(&Eth, &Ipv4, &Tcp)>` on a
//!   VLAN-tagged packet is a miss; the caller must write a shape
//!   that includes `&Vlan` to accept such a packet.
//! * IPv6 extension headers are skipped silently when the shape
//!   crosses directly from an IP layer to a transport layer, but
//!   matching becomes strict once the shape enters the extension
//!   region, with [`ExtGapCheck`] enforcing the same contract used
//!   by [`Matcher`](super::pat::Matcher).
//!
//! Downstream code that receives a `&HeadersView<T>` can extract typed
//! references to the matched layers via the [`Look`] trait without
//! re-validating at each access site.
//!
//! # Safety boundary
//!
//! Zero-cost extraction is achieved by informing the optimizer, via
//! `Option::unwrap_unchecked`, that the `HeadersView` type invariant rules
//! out the `None` arms of each [`ViewStep::step`] call.  The
//! `unsafe` required for this is fully contained:
//!
//! * [`Headers::as_view`] / [`Headers::as_view_mut`] are the only
//!   ways to obtain a `&HeadersView<T>` / `&mut HeadersView<T>`, and they run
//!   the [`sealed::Sealed::matches`] check -- which threads the same
//!   cursors and gap checks as [`ViewStep::step`] would -- before
//!   the `#[repr(transparent)]` reference cast.
//! * [`ViewStep`] is crate-private.  Its `step` method is a safe
//!   `Option`-returning function; [`Look::look`] simply invokes it
//!   and unwraps unchecked, relying on the `HeadersView<T>` newtype
//!   invariant.
//! * External callers see only [`HeadersView`] and [`Look`].  They cannot
//!   implement [`ViewStep`] or call it directly, so they cannot
//!   forge a `HeadersView<T>` that sidesteps `matches`.
//! * `HeadersView<T>` has private fields and no owning constructor;
//!   callers can only ever hold it behind a reference borrowed from a
//!   [`Headers`].  Do not add `Clone`, `Copy`, or any API that
//!   produces an owned `HeadersView<T>` without revisiting this contract
//!   -- cloning through `&HeadersView<T>` would manufacture an owned
//!   shape-proven value that bypasses the borrow and outlives its
//!   source.
//!
//! This matches the "safe abstraction built from local unsafe
//! scaffolding" pattern in `development/code/unsafe-code.md`.

#![allow(private_bounds)] // `Shape: sealed::Sealed` is the seal; external impls are the point we seal against.
#![allow(unsafe_code, clippy::inline_always)] // scaffolding for safe HeadersView abstraction; see module docs

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
// HeadersView<T>
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
/// Obtain via [`Headers::as_view`] or [`Headers::as_view_mut`].
/// Extract typed references via [`Look::look`].
#[repr(transparent)]
pub struct HeadersView<T>(Headers, PhantomData<T>);

// ===========================================================================
// Shape
// ===========================================================================

/// Declared, checkable shapes for [`HeadersView<T>`].
///
/// Any tuple whose layers chain through the [`Within<T>`] adjacency
/// graph and the [`ViewStep<Pos>`] trait is a [`Shape`].  External
/// crates cannot add new shapes (they cannot implement `ViewStep`),
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
// Headers::as_view / as_view_mut
// ===========================================================================

impl Headers {
    /// Borrow `self` as a [`HeadersView<T>`] if its structure matches `T`.
    ///
    /// Returns `None` if the shape doesn't match; does not move out
    /// of `self`.  This is the sole path to a `&HeadersView<T>` -- there
    /// is no owning constructor.
    #[inline]
    #[must_use]
    pub fn as_view<T>(&self) -> Option<&HeadersView<T>>
    where
        T: Shape,
    {
        if <T as sealed::Sealed>::matches(self) {
            // SAFETY: `matches` returned true, so the HeadersView<T> shape
            // invariant holds for this Headers.  HeadersView<T> is
            // #[repr(transparent)] over Headers, so a &Headers and
            // &HeadersView<T> have identical representations.
            let x = std::ptr::from_ref(self).cast::<HeadersView<T>>();
            Some(unsafe { x.as_ref_unchecked() })
        } else {
            None
        }
    }

    /// Mutable borrow of `self` as a `&mut HeadersView<T>` if its structure
    /// matches `T`.  Same invariant and cast as [`Self::as_view`].
    #[inline]
    #[must_use]
    pub fn as_view_mut<T>(&mut self) -> Option<&mut HeadersView<T>>
    where
        T: Shape,
    {
        if <T as sealed::Sealed>::matches(self) {
            // SAFETY: same as as_view, with exclusive borrow preserved.
            // (see notes at top of file)
            let x = std::ptr::from_mut(self).cast::<HeadersView<T>>();
            Some(unsafe { x.as_mut_unchecked() })
        } else {
            None
        }
    }
}

// ===========================================================================
// Look
// ===========================================================================

/// Extract typed references to the layers a [`HeadersView<T>`] holds.
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
    /// step; the `HeadersView` type invariant guarantees success so the
    /// `None` branches are pruned by the optimizer.
    fn look<'a>(&'a self) -> Self::Refs<'a>
    where
        Self: 'a;
}

// ===========================================================================
// ViewStep: per-layer extraction with cursor threading + gap checks
// ===========================================================================
//
// Each ViewStep<Pos> impl mirrors the corresponding Matcher method
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
/// relying on the `HeadersView` invariant.
pub(crate) trait ViewStep<Pos>: Sized {
    /// Run this layer's extraction and gap check against the current
    /// cursor state.  Returns `None` on any mismatch.
    fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&Self, u8, u8)>;
}

// ---- Entry: Eth -----------------------------------------------------------

impl ViewStep<()> for Eth {
    #[inline(always)]
    fn step(h: &Headers, vc: u8, ec: u8) -> Option<(&Eth, u8, u8)> {
        h.eth().map(|e| (e, vc, ec))
    }
}

// ---- VLAN: advance vc, still in-phase -------------------------------------

impl<Pos> ViewStep<Pos> for Vlan
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
        impl<Pos> ViewStep<Pos> for $T
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
impl<Pos> ViewStep<Pos> for Net
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
        impl<Pos> ViewStep<Pos> for $T
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
        impl<Pos> ViewStep<Pos> for $T
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
impl<Pos> ViewStep<Pos> for Transport
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

impl<Pos> ViewStep<Pos> for Vxlan
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
// arity range by adding a new `impl_view_arity_N!` arm below.

macro_rules! impl_view_arity_1 {
    ($A:ident) => {
        impl<'x, $A> Shape for (&'x $A,) where $A: ViewStep<()> {}

        impl<'x, $A> sealed::Sealed for (&'x $A,)
        where
            $A: ViewStep<()>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                $A::step(h, 0, 0).is_some()
            }
        }

        impl<'x, $A> Look<(&'x $A,)> for HeadersView<(&'x $A,)>
        where
            $A: ViewStep<()>,
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
                // SAFETY: HeadersView<(&A,)> invariant: matches(h) was true.
                // (see notes at top of file)
                unsafe {
                    let (a, _, _) = $A::step(h, 0, 0).unwrap_unchecked();
                    (a,)
                }
            }
        }
    };
}

macro_rules! impl_view_arity_2 {
    ($A:ident, $B:ident) => {
        impl<'x, $A, $B> Shape for (&'x $A, &'x $B)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
        {
        }

        impl<'x, $A, $B> sealed::Sealed for (&'x $A, &'x $B)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
        {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                let Some((_, vc, ec)) = $A::step(h, 0, 0) else {
                    return false;
                };
                $B::step(h, vc, ec).is_some()
            }
        }

        impl<'x, $A, $B> Look<(&'x $A, &'x $B)> for HeadersView<(&'x $A, &'x $B)>
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
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
                // SAFETY: HeadersView invariant: matches(h) was true.
                // (see notes at top of file)
                unsafe {
                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                    let (b, _, _) = $B::step(h, vc, ec).unwrap_unchecked();
                    (a, b)
                }
            }
        }
    };
}

macro_rules! impl_view_arity_3 {
    ($A:ident, $B:ident, $C:ident) => {
        impl<'x, $A, $B, $C> Shape for (&'x $A, &'x $B, &'x $C)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
        {
        }

        impl<'x, $A, $B, $C> sealed::Sealed for (&'x $A, &'x $B, &'x $C)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
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

        impl<'x, $A, $B, $C> Look<(&'x $A, &'x $B, &'x $C)>
            for HeadersView<(&'x $A, &'x $B, &'x $C)>
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
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
                // SAFETY: HeadersView invariant: matches(h) was true.
                // (see notes at top of file)
                unsafe {
                    let (a, vc, ec) = $A::step(h, 0, 0).unwrap_unchecked();
                    let (b, vc, ec) = $B::step(h, vc, ec).unwrap_unchecked();
                    let (c, _, _) = $C::step(h, vc, ec).unwrap_unchecked();
                    (a, b, c)
                }
            }
        }
    };
}

macro_rules! impl_view_arity_4 {
    ($A:ident, $B:ident, $C:ident, $D:ident) => {
        impl<'x, $A, $B, $C, $D> Shape for (&'x $A, &'x $B, &'x $C, &'x $D)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
        {
        }

        impl<'x, $A, $B, $C, $D> sealed::Sealed for (&'x $A, &'x $B, &'x $C, &'x $D)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
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
            for HeadersView<(&'x $A, &'x $B, &'x $C, &'x $D)>
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
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
                // SAFETY: HeadersView invariant: matches(h) was true.
                // (see notes at top of file)
                unsafe {
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

macro_rules! impl_view_arity_5 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident) => {
        impl<'x, $A, $B, $C, $D, $E> Shape for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
        {
        }

        impl<'x, $A, $B, $C, $D, $E> sealed::Sealed for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
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
            for HeadersView<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E)>
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
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
                // SAFETY: HeadersView invariant: matches(h) was true.
                // (see notes at top of file)
                unsafe {
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

macro_rules! impl_view_arity_6 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F> Shape for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
        {
        }

        impl<'x, $A, $B, $C, $D, $E, $F> sealed::Sealed
            for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
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
            for HeadersView<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F)>
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
            Self: 'x,
        {
            type Refs<'a>
                = (&'a $A, &'a $B, &'a $C, &'a $D, &'a $E, &'a $F)
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                let h = &self.0;
                // SAFETY: HeadersView invariant: matches(h) was true.
                // (see notes at top of file)
                unsafe {
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

macro_rules! impl_view_arity_7 {
    ($A:ident, $B:ident, $C:ident, $D:ident, $E:ident, $F:ident, $G:ident) => {
        impl<'x, $A, $B, $C, $D, $E, $F, $G> Shape
            for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
            $G: ViewStep<$F>,
        {
        }

        impl<'x, $A, $B, $C, $D, $E, $F, $G> sealed::Sealed
            for (&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
            $G: ViewStep<$F>,
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
            for HeadersView<(&'x $A, &'x $B, &'x $C, &'x $D, &'x $E, &'x $F, &'x $G)>
        where
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
            $G: ViewStep<$F>,
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
                // SAFETY: HeadersView invariant: matches(h) was true.
                // (see notes at top of file)
                unsafe {
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

macro_rules! impl_view_arity_8 {
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
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
            $G: ViewStep<$F>,
            $H: ViewStep<$G>,
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
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
            $G: ViewStep<$F>,
            $H: ViewStep<$G>,
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
            for HeadersView<(
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
            $A: ViewStep<()>,
            $B: ViewStep<$A>,
            $C: ViewStep<$B>,
            $D: ViewStep<$C>,
            $E: ViewStep<$D>,
            $F: ViewStep<$E>,
            $G: ViewStep<$F>,
            $H: ViewStep<$G>,
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
                // SAFETY: HeadersView invariant: matches(h) was true.
                // (see notes at top of file)
                unsafe {
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

impl_view_arity_1!(A);
impl_view_arity_2!(A, B);
impl_view_arity_3!(A, B, C);
impl_view_arity_4!(A, B, C, D);
impl_view_arity_5!(A, B, C, D, E);
impl_view_arity_6!(A, B, C, D, E, F);
impl_view_arity_7!(A, B, C, D, E, F, G);
impl_view_arity_8!(A, B, C, D, E, F, G, H);

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
        assert!(h.as_view::<(&Eth, &Ipv4, &Tcp)>().is_some());
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
        assert!(h.as_view::<(&Eth, &Ipv4, &Udp)>().is_some());
        assert!(h.as_view::<(&Eth, &Ipv4, &Tcp)>().is_none());
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
        assert!(h.as_view::<(&Eth,)>().is_some());
    }

    // ---- VLAN gap-check semantics (mirror pat.rs) --------------------------

    // Invariant: HeadersView<(&Eth, &Ipv4, &Tcp)> must REJECT a packet with
    // a VLAN tag between Eth and Ipv4.  If this returns Some, the
    // HeadersView has drifted from pat.rs semantics.
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
            h.as_view::<(&Eth, &Ipv4, &Tcp)>().is_none(),
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
        assert!(h.as_view::<(&Eth, &Vlan, &Ipv4, &Tcp)>().is_some());
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
            h.as_view::<(&Eth, &Vlan, &Ipv4, &Tcp)>().is_none(),
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
            .as_view::<(&Eth, &Vlan, &Vlan, &Ipv4, &Tcp)>()
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
        assert!(h.as_view::<(&Eth, &Ipv6, &Tcp)>().is_some());
        // Explicitly matching the extension also works.
        assert!(h.as_view::<(&Eth, &Ipv6, &HopByHop, &Tcp)>().is_some());
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
            h.as_view::<(&Eth, &Ipv6, &HopByHop, &Tcp)>().is_none(),
            "entered extension region but DestOpts unconsumed: must miss"
        );
        // Entered and complete.
        assert!(
            h.as_view::<(&Eth, &Ipv6, &HopByHop, &DestOpts, &Tcp)>()
                .is_some()
        );
        // Skipped from Ipv6 position: allowed.
        assert!(h.as_view::<(&Eth, &Ipv6, &Tcp)>().is_some());
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
            .as_view::<(&Eth, &Ipv6, &HopByHop, &DestOpts, &Tcp)>()
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
        assert!(h.as_view::<(&Eth, &Ipv6, &Tcp)>().is_some());
        assert!(h.as_view::<(&Eth, &Ipv4, &Tcp)>().is_none());
    }
}
