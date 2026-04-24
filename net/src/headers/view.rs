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
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::tcp::Tcp;
use crate::udp::Udp;

use super::pat::ExtGapCheck;
use super::{Headers, Net, Transport, Within};

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

// ===========================================================================
// Per-arity Shape / Sealed / Look impls
// ===========================================================================
//
// One arm per arity for clarity of generated code; each arm emits the
// three impls (`Shape`, `sealed::Sealed`, `Look`) plus the cursor-
// threaded `matches` and `look` bodies.  Follow-up commits extend
// the arity range as shapes requiring arities > 3 come online.

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

impl_view_arity_1!(A);
impl_view_arity_2!(A, B);
impl_view_arity_3!(A, B, C);

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
}
