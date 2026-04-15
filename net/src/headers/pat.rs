// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(private_bounds)]

//! Protocol-aware pattern matching for [`Headers`].
//!
//! The [`Matcher`] builder lets you express which layers a packet must (or may)
//! contain, and in what order.  Layer ordering is checked **at compile time**
//! via the same [`Within`] bounds used by the header-stack builder.  Skipped
//! intermediate layers (e.g. an unexpected VLAN between Ethernet and IPv4)
//! cause the match to fail at **runtime** rather than being silently ignored.
//!
//! # Optional methods: absent vs wrong variant
//!
//! Methods like `.opt_vlan()`, `.opt_ipv4()`, `.opt_tcp()` mean "this layer
//! may be **absent**."  They append `Option<&T>` to the tuple:
//!
//! - **Field is `None`** (genuinely absent): appends `None`, match continues.
//! - **Field is `Some` with the correct variant**: appends `Some(&T)`.
//! - **Field is `Some` with a different variant** (e.g. `.opt_tcp()` on a UDP
//!   packet): the match **fails** (returns `None`).  A wrong variant is not
//!   the same as absence -- it means the packet has a different protocol at
//!   this layer, which is a structural mismatch.
//!
//! # Quick example
//!
//! ```ignore
//! fn process(h: &Headers) {
//!     // Matches Eth / IPv4 / TCP with nothing in between.
//!     // A VLAN between Eth and IPv4 -> None (miss).
//!     match h.pat().eth().ipv4().tcp().done() {
//!         Some((eth, ipv4, tcp)) => { /* fast path */ }
//!         None => { /* miss */ }
//!     }
//!
//!     // Matches Eth / 0-or-1 VLAN / IPv4 / TCP.
//!     match h.pat().eth().opt_vlan().ipv4().tcp().done() {
//!         Some((eth, vlan, ipv4, tcp)) => { /* vlan: Option<&Vlan> */ }
//!         None => { /* miss */ }
//!     }
//! }
//! ```

use super::{
    EmbeddedHeaders, EmbeddedStart, EmbeddedTransport, Headers, Net, NetExt, Transport, Within,
};
use crate::eth::Eth;
use crate::icmp4::{Icmp4, TruncatedIcmp4};
use crate::icmp6::{Icmp6, TruncatedIcmp6};
use crate::ip_auth::{Ipv4Auth, Ipv6Auth};
use crate::ipv4::Ipv4;
use crate::ipv6::{DestOpts, Fragment, HopByHop, Ipv6, Routing};
use crate::tcp::{Tcp, TruncatedTcp};
use crate::udp::{TruncatedUdp, Udp, UdpEncap};
use crate::vlan::Vlan;
use crate::vxlan::Vxlan;

// ---------------------------------------------------------------------------
// TupleAppend -- grow a tuple by one element
// ---------------------------------------------------------------------------

/// Append a value to a tuple, producing a tuple one element wider.
///
/// Implementations are provided for tuples up to 16 elements.  Matcher
/// chains that accumulate more than 16 fields will hit a trait bound
/// error.  In practice this is rarely reached because embedded headers
/// use a nested sub-tuple rather than flattening into the outer tuple.
pub trait TupleAppend<T> {
    /// The resulting tuple type after appending `T`.
    type Output;
    /// Append `item` to `self`.
    fn append(self, item: T) -> Self::Output;
}

macro_rules! impl_tuple_append {
    () => {
        impl<T> TupleAppend<T> for () {
            type Output = (T,);
            #[inline]
            fn append(self, item: T) -> (T,) { (item,) }
        }
    };
    ($($name:ident),+) => {
        impl<$($name,)+ T> TupleAppend<T> for ($($name,)+) {
            type Output = ($($name,)+ T,);
            #[inline]
            #[allow(non_snake_case)]
            fn append(self, item: T) -> ($($name,)+ T,) {
                let ($($name,)+) = self;
                ($($name,)+ item,)
            }
        }
    };
}

impl_tuple_append!();
impl_tuple_append!(A);
impl_tuple_append!(A, B);
impl_tuple_append!(A, B, C);
impl_tuple_append!(A, B, C, D);
impl_tuple_append!(A, B, C, D, E);
impl_tuple_append!(A, B, C, D, E, F);
impl_tuple_append!(A, B, C, D, E, F, G);
impl_tuple_append!(A, B, C, D, E, F, G, H);
impl_tuple_append!(A, B, C, D, E, F, G, H, I);
impl_tuple_append!(A, B, C, D, E, F, G, H, I, J);
impl_tuple_append!(A, B, C, D, E, F, G, H, I, J, K);
impl_tuple_append!(A, B, C, D, E, F, G, H, I, J, K, L);
impl_tuple_append!(A, B, C, D, E, F, G, H, I, J, K, L, M);
impl_tuple_append!(A, B, C, D, E, F, G, H, I, J, K, L, M, N);
impl_tuple_append!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O);
impl_tuple_append!(A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P);

// ---------------------------------------------------------------------------
// Extension gap-check policy
// ---------------------------------------------------------------------------
//
// When transitioning from the network layer to the transport layer, the
// matcher needs to decide whether unconsumed IPv6 extension headers cause
// a miss.
//
// - If the user never mentioned any extension header in the chain
//   (Pos is an IP type or Net), extensions are silently skipped.  This is
//   the common case -- most packet processing doesn't inspect extensions.
//
// - If the user explicitly entered the extension region (Pos is an
//   extension header type), all remaining extensions must be consumed or
//   the match fails.  This preserves the "no silently skipped layers"
//   guarantee for users who opt into extension matching.
//
// VLANs are always strict -- they affect routing (VRF selection), so
// skipping them silently would be a bug.

mod sealed {
    pub trait Sealed {}
    impl Sealed for crate::ipv4::Ipv4 {}
    impl Sealed for crate::ipv6::Ipv6 {}
    impl Sealed for super::Net {}
    impl Sealed for crate::ipv6::HopByHop {}
    impl Sealed for crate::ipv6::DestOpts {}
    impl Sealed for crate::ipv6::Routing {}
    impl Sealed for crate::ipv6::Fragment {}
    impl Sealed for crate::ip_auth::Ipv4Auth {}
    impl Sealed for crate::ip_auth::Ipv6Auth {}
}

/// Determines whether the transport-layer gap check enforces that all
/// network extension headers have been consumed.
///
/// - IP-layer types return `true` unconditionally (extensions skipped).
/// - Extension header types return `true` only when all extensions have
///   been consumed (`net_ext.len() == ext_cursor`).
///
/// This is a sealed implementation detail -- all impls are provided by
/// this module and users never need to reference this trait directly.
#[doc(hidden)]
pub trait ExtGapCheck: sealed::Sealed {
    /// Returns `true` if the transport gap check should pass.
    fn ext_gap_ok(headers: &Headers, ext_cursor: u8) -> bool;

    /// Same check but using the pre-split [`Fields`] of [`MatcherMut`].
    fn ext_gap_ok_mut(fields: &Fields<'_>) -> bool;

    /// Same check but for [`EmbeddedHeaders`] (immutable matcher).
    fn ext_gap_ok_embedded(embedded: &EmbeddedHeaders, ext_cursor: u8) -> bool;

    /// Same check but for [`EmbeddedFields`] (mutable matcher).
    fn ext_gap_ok_mut_embedded(fields: &EmbeddedFields<'_>) -> bool;
}

// IP-layer positions: skip extensions silently.
macro_rules! impl_skip_ext {
    ($($T:ty),*) => {$(
        impl ExtGapCheck for $T {
            fn ext_gap_ok(_: &Headers, _: u8) -> bool { true }
            fn ext_gap_ok_mut(_: &Fields<'_>) -> bool { true }
            fn ext_gap_ok_embedded(_: &EmbeddedHeaders, _: u8) -> bool { true }
            fn ext_gap_ok_mut_embedded(_: &EmbeddedFields<'_>) -> bool { true }
        }
    )*};
}
impl_skip_ext!(Ipv4, Ipv6, Net);

// Extension header positions: unconsumed extensions cause a miss.
macro_rules! impl_strict_ext {
    ($($T:ty),*) => {$(
        impl ExtGapCheck for $T {
            fn ext_gap_ok(h: &Headers, ec: u8) -> bool {
                h.net_ext().len() == ec as usize
            }
            fn ext_gap_ok_mut(f: &Fields<'_>) -> bool {
                f.ext_consumed()
            }
            fn ext_gap_ok_embedded(e: &EmbeddedHeaders, ec: u8) -> bool {
                e.net_ext.len() == ec as usize
            }
            fn ext_gap_ok_mut_embedded(f: &EmbeddedFields<'_>) -> bool {
                f.ext_consumed()
            }
        }
    )*};
}
impl_strict_ext!(HopByHop, DestOpts, Routing, Fragment, Ipv4Auth, Ipv6Auth);

// ---------------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------------

/// A protocol-aware pattern matcher over [`Headers`].
///
/// `Pos` is the type-level "current layer" -- each chain method requires the
/// next layer to satisfy [`Within<Pos>`], reusing the same adjacency graph as
/// the header-stack builder.
///
/// `Acc` is the tuple of references accumulated so far.
///
/// Runtime cursors track progress into the `vlan` and `net_ext` [`ArrayVec`]
/// fields so that skipped intermediate layers are detected.
#[must_use = "a Matcher does nothing until .done() is called"]
pub struct Matcher<'a, Pos, Acc> {
    headers: &'a Headers,
    acc: Option<Acc>,
    vlan_cursor: u8,
    ext_cursor: u8,
    _pos: core::marker::PhantomData<Pos>,
}

impl Headers {
    /// Begin a discriminating pattern match on this header stack.
    ///
    /// Chain `.eth()`, `.ipv4()`, `.tcp()`, etc. to specify the expected
    /// layer sequence, then call [`.done()`](Matcher::done) to get the result.
    pub fn pat(&self) -> Matcher<'_, (), ()> {
        Matcher {
            headers: self,
            acc: Some(()),
            vlan_cursor: 0,
            ext_cursor: 0,
            _pos: core::marker::PhantomData,
        }
    }
}

impl<Pos, Acc> Matcher<'_, Pos, Acc> {
    /// Finalize the match.
    ///
    /// Returns `Some(tuple)` if every required layer was present and no
    /// intermediate layers were skipped.  Returns `None` otherwise.
    #[must_use]
    pub fn done(self) -> Option<Acc> {
        self.acc
    }

    /// Apply a predicate to the accumulated match so far.
    ///
    /// If the predicate returns `false`, the entire match becomes `None`.
    /// Does not advance the position or any cursors.
    ///
    /// ```ignore
    /// h.pat().eth().ipv4().icmp4()
    ///     .when(|(.., icmp)| icmp.is_error_message())
    ///     .embedded().ipv4().tcp().done()
    /// ```
    pub fn when(self, pred: impl FnOnce(&Acc) -> bool) -> Self {
        Self {
            acc: self.acc.filter(|a| pred(a)),
            ..self
        }
    }

    /// Peek at the accumulated match for debugging or tracing.
    ///
    /// The closure is only called if the match is still alive (not `None`).
    /// Does not affect the match result.
    pub fn inspect(self, f: impl FnOnce(&Acc)) -> Self {
        Self {
            acc: self.acc.inspect(|a| f(a)),
            ..self
        }
    }

    /// Run a closure if the match has already failed.
    ///
    /// Useful for logging or tracing why a pattern did not match.
    /// Does not affect the match result.
    pub fn otherwise(self, f: impl FnOnce()) -> Self {
        if self.acc.is_none() {
            f();
        }
        self
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc> {
    #[inline]
    fn step<T: 'a, NewAcc>(
        self,
        extract: impl FnOnce(&'a Headers) -> Option<&'a T>,
        vlan_cursor: u8,
        ext_cursor: u8,
    ) -> Matcher<'a, T, NewAcc>
    where
        Acc: TupleAppend<&'a T, Output = NewAcc>,
    {
        Matcher {
            headers: self.headers,
            acc: self
                .acc
                .and_then(|a| extract(self.headers).map(|v| a.append(v))),
            vlan_cursor,
            ext_cursor,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Eth -- entry layer, no gap check
// ---------------------------------------------------------------------------

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Eth: Within<Pos>,
    Acc: TupleAppend<&'a Eth>,
{
    /// Require an Ethernet header at this position.
    pub fn eth(self) -> Matcher<'a, Eth, <Acc as TupleAppend<&'a Eth>>::Output> {
        let vc = self.vlan_cursor;
        let ec = self.ext_cursor;
        self.step(|h| h.eth(), vc, ec)
    }
}

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Eth: Within<Pos>,
    Acc: TupleAppend<Option<&'a Eth>>,
{
    /// Optionally match an Ethernet header at this position.
    pub fn opt_eth(self) -> Matcher<'a, Eth, <Acc as TupleAppend<Option<&'a Eth>>>::Output> {
        let vc = self.vlan_cursor;
        let ec = self.ext_cursor;
        Matcher {
            headers: self.headers,
            acc: self.acc.map(|a| a.append(self.headers.eth())),
            vlan_cursor: vc,
            ext_cursor: ec,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Vlan -- ArrayVec cursor, no preceding gap check
// ---------------------------------------------------------------------------

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Vlan: Within<Pos>,
    Acc: TupleAppend<&'a Vlan>,
{
    /// Require a VLAN header at the current cursor position.
    ///
    /// Each call to `.vlan()` or `.opt_vlan()` advances the VLAN cursor by
    /// one, so chaining `.vlan().vlan()` requires exactly two VLAN tags.
    pub fn vlan(self) -> Matcher<'a, Vlan, <Acc as TupleAppend<&'a Vlan>>::Output> {
        let cursor = self.vlan_cursor as usize;
        let next_vc = self.vlan_cursor + 1;
        let ec = self.ext_cursor;
        self.step(|h| h.vlan().get(cursor), next_vc, ec)
    }
}

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Vlan: Within<Pos>,
    Acc: TupleAppend<Option<&'a Vlan>>,
{
    /// Optionally match a VLAN header at the current cursor position.
    ///
    /// If no VLAN is present at this position, `None` is appended to the
    /// tuple and the cursor is **not** advanced.
    pub fn opt_vlan(self) -> Matcher<'a, Vlan, <Acc as TupleAppend<Option<&'a Vlan>>>::Output> {
        let cursor = self.vlan_cursor as usize;
        let found = self.headers.vlan().get(cursor);
        let next_vc = if found.is_some() {
            self.vlan_cursor + 1
        } else {
            self.vlan_cursor
        };
        Matcher {
            headers: self.headers,
            acc: self.acc.map(|a| a.append(found)),
            vlan_cursor: next_vc,
            ext_cursor: self.ext_cursor,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// Net layer (Ipv4 / Ipv6) -- gap check: all VLANs consumed
// ---------------------------------------------------------------------------

/// Generate required + optional matcher methods for a network-layer header
/// that lives inside `Option<Net>`.
///
/// Gap check: `vlan.len() == vlan_cursor` (no unconsumed VLAN tags).
macro_rules! matcher_net {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Acc: TupleAppend<&'a $T>,
        {
            #[doc = concat!("Require ", stringify!($T), " at this position.")]
            ///
            /// Fails if there are unconsumed VLAN tags between the previous
            /// layer and this one.
            pub fn $name(self) -> Matcher<'a, $T, <Acc as TupleAppend<&'a $T>>::Output> {
                let vc = self.vlan_cursor;
                self.step(
                    |h| {
                        if h.vlan().len() != vc as usize {
                            return None;
                        }
                        match h.net() {
                            Some($variant(v)) => Some(v),
                            _ => None,
                        }
                    },
                    vc,
                    0,
                )
            }
        }

        impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Acc: TupleAppend<Option<&'a $T>>,
        {
            #[doc = concat!("Optionally match ", stringify!($T), " at this position.")]
            ///
            /// Fails (full miss) if there are unconsumed VLAN tags or if
            /// a different network variant is present (wrong variant is a
            /// miss, not "absent").  Only `net == None` counts as absent.
            pub fn $opt_name(
                self,
            ) -> Matcher<'a, $T, <Acc as TupleAppend<Option<&'a $T>>>::Output> {
                let vc = self.vlan_cursor;
                Matcher {
                    headers: self.headers,
                    acc: self.acc.and_then(|a| {
                        if self.headers.vlan().len() != vc as usize {
                            return None;
                        }
                        match self.headers.net() {
                            Some($variant(v)) => Some(a.append(Some(v))),
                            None => Some(a.append(None)),
                            Some(_) => None, // wrong variant = miss
                        }
                    }),
                    vlan_cursor: vc,
                    ext_cursor: 0,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

matcher_net!(ipv4 / opt_ipv4 -> Ipv4, Net::Ipv4);
matcher_net!(ipv6 / opt_ipv6 -> Ipv6, Net::Ipv6);

// -- Net enum (return &Net for caller to branch on variant) --

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Net: Within<Pos>,
    Acc: TupleAppend<&'a Net>,
{
    /// Require a network-layer header, returning the [`Net`] enum.
    ///
    /// Use this when you want to branch on IPv4 vs IPv6 yourself
    /// rather than committing to a specific variant in the chain.
    pub fn net(self) -> Matcher<'a, Net, <Acc as TupleAppend<&'a Net>>::Output> {
        let vc = self.vlan_cursor;
        self.step(
            |h| {
                if h.vlan().len() != vc as usize {
                    return None;
                }
                h.net()
            },
            vc,
            0,
        )
    }
}

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Net: Within<Pos>,
    Acc: TupleAppend<Option<&'a Net>>,
{
    /// Optionally match a network-layer header, returning the [`Net`] enum.
    pub fn opt_net(self) -> Matcher<'a, Net, <Acc as TupleAppend<Option<&'a Net>>>::Output> {
        let vc = self.vlan_cursor;
        Matcher {
            headers: self.headers,
            acc: self.acc.and_then(|a| {
                if self.headers.vlan().len() != vc as usize {
                    return None;
                }
                Some(a.append(self.headers.net()))
            }),
            vlan_cursor: vc,
            ext_cursor: 0,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// NetExt layer -- ArrayVec cursor with variant matching
// ---------------------------------------------------------------------------

/// Generate required + optional matcher methods for a network-extension header
/// that lives inside `ArrayVec<NetExt, _>`.
///
/// The cursor into `net_ext` advances when a matching entry is found.
macro_rules! matcher_ext {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Acc: TupleAppend<&'a $T>,
        {
            #[doc = concat!("Require ", stringify!($T), " at the current extension cursor.")]
            pub fn $name(self) -> Matcher<'a, $T, <Acc as TupleAppend<&'a $T>>::Output> {
                let cursor = self.ext_cursor as usize;
                let vc = self.vlan_cursor;
                let next_ec = self.ext_cursor.saturating_add(1);
                self.step(
                    |h| match h.net_ext().get(cursor) {
                        Some($variant(v)) => Some(v),
                        _ => None,
                    },
                    vc,
                    next_ec,
                )
            }
        }

        impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Acc: TupleAppend<Option<&'a $T>>,
        {
            #[doc = concat!("Optionally match ", stringify!($T), " at the current extension cursor.")]
            pub fn $opt_name(
                self,
            ) -> Matcher<'a, $T, <Acc as TupleAppend<Option<&'a $T>>>::Output> {
                let cursor = self.ext_cursor as usize;
                let found = match self.headers.net_ext().get(cursor) {
                    Some($variant(v)) => Some(v),
                    _ => None,
                };
                let next_ec = if found.is_some() {
                    self.ext_cursor.saturating_add(1)
                } else {
                    self.ext_cursor
                };
                Matcher {
                    headers: self.headers,
                    acc: self.acc.map(|a| a.append(found)),
                    vlan_cursor: self.vlan_cursor,
                    ext_cursor: next_ec,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

matcher_ext!(hop_by_hop / opt_hop_by_hop -> HopByHop, NetExt::HopByHop);
matcher_ext!(dest_opts  / opt_dest_opts  -> DestOpts, NetExt::DestOpts);
matcher_ext!(routing    / opt_routing    -> Routing,  NetExt::Routing);
matcher_ext!(fragment   / opt_fragment   -> Fragment, NetExt::Fragment);
matcher_ext!(ipv4_auth  / opt_ipv4_auth  -> Ipv4Auth, NetExt::Ipv4Auth);
matcher_ext!(ipv6_auth  / opt_ipv6_auth  -> Ipv6Auth, NetExt::Ipv6Auth);

// ---------------------------------------------------------------------------
// Transport layer -- extension gap check depends on Pos via ExtGapCheck
// ---------------------------------------------------------------------------

/// Generate required + optional matcher methods for a transport-layer header.
///
/// Uses [`ExtGapCheck`] to determine whether unconsumed extension headers
/// cause a miss (strict, when Pos is an extension type) or are silently
/// skipped (when Pos is an IP type).
macro_rules! matcher_transport {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
            Acc: TupleAppend<&'a $T>,
        {
            #[doc = concat!("Require ", stringify!($T), " at this position.")]
            pub fn $name(self) -> Matcher<'a, $T, <Acc as TupleAppend<&'a $T>>::Output> {
                let vc = self.vlan_cursor;
                let ec = self.ext_cursor;
                self.step(
                    |h| {
                        if !Pos::ext_gap_ok(h, ec) {
                            return None;
                        }
                        match h.transport() {
                            Some($variant(v)) => Some(v),
                            _ => None,
                        }
                    },
                    vc,
                    ec,
                )
            }
        }

        impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
            Acc: TupleAppend<Option<&'a $T>>,
        {
            #[doc = concat!("Optionally match ", stringify!($T), " at this position.")]
            pub fn $opt_name(
                self,
            ) -> Matcher<'a, $T, <Acc as TupleAppend<Option<&'a $T>>>::Output> {
                let vc = self.vlan_cursor;
                let ec = self.ext_cursor;
                Matcher {
                    headers: self.headers,
                    acc: self.acc.and_then(|a| {
                        if !Pos::ext_gap_ok(self.headers, ec) {
                            return None;
                        }
                        match self.headers.transport() {
                            Some($variant(v)) => Some(a.append(Some(v))),
                            None => Some(a.append(None)),
                            Some(_) => None, // wrong variant = miss
                        }
                    }),
                    vlan_cursor: vc,
                    ext_cursor: ec,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

matcher_transport!(tcp   / opt_tcp   -> Tcp,   Transport::Tcp);
matcher_transport!(udp   / opt_udp   -> Udp,   Transport::Udp);
matcher_transport!(icmp4 / opt_icmp4 -> Icmp4, Transport::Icmp4);
matcher_transport!(icmp6 / opt_icmp6 -> Icmp6, Transport::Icmp6);

// -- Transport enum --

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Transport: Within<Pos>,
    Pos: ExtGapCheck,
    Acc: TupleAppend<&'a Transport>,
{
    /// Require a transport-layer header, returning the [`Transport`] enum.
    pub fn transport(self) -> Matcher<'a, Transport, <Acc as TupleAppend<&'a Transport>>::Output> {
        let vc = self.vlan_cursor;
        let ec = self.ext_cursor;
        self.step(
            |h| {
                if !Pos::ext_gap_ok(h, ec) {
                    return None;
                }
                h.transport()
            },
            vc,
            ec,
        )
    }
}

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Transport: Within<Pos>,
    Pos: ExtGapCheck,
    Acc: TupleAppend<Option<&'a Transport>>,
{
    /// Optionally match a transport-layer header, returning the [`Transport`] enum.
    pub fn opt_transport(
        self,
    ) -> Matcher<'a, Transport, <Acc as TupleAppend<Option<&'a Transport>>>::Output> {
        let vc = self.vlan_cursor;
        let ec = self.ext_cursor;
        Matcher {
            headers: self.headers,
            acc: self.acc.and_then(|a| {
                if !Pos::ext_gap_ok(self.headers, ec) {
                    return None;
                }
                Some(a.append(self.headers.transport()))
            }),
            vlan_cursor: vc,
            ext_cursor: ec,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// UDP encapsulation (Vxlan) -- no gap check, directly after transport
// ---------------------------------------------------------------------------

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Vxlan: Within<Pos>,
    Acc: TupleAppend<&'a Vxlan>,
{
    /// Require a VXLAN header at this position.
    pub fn vxlan(self) -> Matcher<'a, Vxlan, <Acc as TupleAppend<&'a Vxlan>>::Output> {
        let vc = self.vlan_cursor;
        let ec = self.ext_cursor;
        self.step(
            |h| match h.udp_encap() {
                Some(UdpEncap::Vxlan(v)) => Some(v),
                _ => None,
            },
            vc,
            ec,
        )
    }
}

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    Vxlan: Within<Pos>,
    Acc: TupleAppend<Option<&'a Vxlan>>,
{
    /// Optionally match a VXLAN header at this position.
    pub fn opt_vxlan(self) -> Matcher<'a, Vxlan, <Acc as TupleAppend<Option<&'a Vxlan>>>::Output> {
        let vc = self.vlan_cursor;
        let ec = self.ext_cursor;
        Matcher {
            headers: self.headers,
            acc: self.acc.and_then(|a| match self.headers.udp_encap() {
                Some(UdpEncap::Vxlan(v)) => Some(a.append(Some(v))),
                None => Some(a.append(None)),
                #[allow(unreachable_patterns)] // future-proofing for new UdpEncap variants
                Some(_) => None,
            }),
            vlan_cursor: vc,
            ext_cursor: ec,
            _pos: core::marker::PhantomData,
        }
    }
}

// ===========================================================================
// MatcherMut -- mutable pattern matching
// ===========================================================================
//
// All header types yield `&mut` references.  Option-backed fields use the
// same `.take()` pattern as before.  ArrayVec-backed fields (vlan, net_ext)
// use `Option<&'a mut [T]>` with `split_first_mut` to peel off elements
// one at a time while keeping the remainder accessible for gap checks.

/// Pre-split mutable references into [`Headers`] fields (implementation detail).
///
/// Option-backed fields are wrapped in `Option` so that chain methods
/// can [`.take()`](Option::take) them.  Slice-backed fields (`vlan`, `net_ext`)
/// use `Option<&mut [T]>` so they can be taken and split via
/// [`split_first_mut`](`slice::split_first_mut`).
#[doc(hidden)]
pub struct Fields<'a> {
    eth: Option<&'a mut Option<Eth>>,
    vlan: Option<&'a mut [Vlan]>,
    net: Option<&'a mut Option<Net>>,
    net_ext: Option<&'a mut [NetExt]>,
    transport: Option<&'a mut Option<Transport>>,
    udp_encap: Option<&'a mut Option<UdpEncap>>,
    embedded: Option<&'a mut Option<EmbeddedHeaders>>,
}

impl Fields<'_> {
    /// True when all VLAN tags have been consumed (or none existed).
    fn vlan_consumed(&self) -> bool {
        self.vlan.as_ref().is_none_or(|s| s.is_empty())
    }

    /// True when all network extension headers have been consumed.
    fn ext_consumed(&self) -> bool {
        self.net_ext.as_ref().is_none_or(|s| s.is_empty())
    }
}

/// Mutable protocol-aware pattern matcher over [`Headers`].
///
/// Works like [`Matcher`] but yields `&mut` references for all header
/// types.  Internally, `Option`-backed fields are extracted via
/// [`.take()`](Option::take) and `ArrayVec`-backed fields are peeled
/// off via [`split_first_mut`](slice::split_first_mut).
#[must_use = "a MatcherMut does nothing until .done() is called"]
pub struct MatcherMut<'a, Pos, Acc> {
    fields: Fields<'a>,
    acc: Option<Acc>,
    _pos: core::marker::PhantomData<Pos>,
}

impl Headers {
    /// Begin a mutable discriminating pattern match on this header stack.
    ///
    /// Like [`pat()`](Headers::pat), but yields `&mut` references for all
    /// matched headers.
    pub fn pat_mut(&mut self) -> MatcherMut<'_, (), ()> {
        MatcherMut {
            fields: Fields {
                eth: Some(&mut self.eth),
                vlan: Some(self.vlan.as_mut_slice()),
                net: Some(&mut self.net),
                net_ext: Some(self.net_ext.as_mut_slice()),
                transport: Some(&mut self.transport),
                udp_encap: Some(&mut self.udp_encap),
                embedded: Some(&mut self.embedded_ip),
            },
            acc: Some(()),
            _pos: core::marker::PhantomData,
        }
    }
}

impl<Pos, Acc> MatcherMut<'_, Pos, Acc> {
    /// Finalize the match.
    ///
    /// Returns `Some(tuple)` if every required layer was present and no
    /// intermediate layers were skipped.  Returns `None` otherwise.
    #[must_use]
    pub fn done(self) -> Option<Acc> {
        self.acc
    }

    /// Apply a predicate to the accumulated match so far.
    ///
    /// If the predicate returns `false`, the entire match becomes `None`.
    /// The predicate receives `&Acc` (shared reference), so `&mut` fields
    /// in the accumulator are accessible as `&T` via auto-deref.
    pub fn when(self, pred: impl FnOnce(&Acc) -> bool) -> Self {
        Self {
            acc: self.acc.filter(|a| pred(a)),
            ..self
        }
    }

    /// Peek at the accumulated match for debugging or tracing.
    pub fn inspect(self, f: impl FnOnce(&Acc)) -> Self {
        Self {
            acc: self.acc.inspect(|a| f(a)),
            ..self
        }
    }

    /// Run a closure if the match has already failed.
    pub fn otherwise(self, f: impl FnOnce()) -> Self {
        if self.acc.is_none() {
            f();
        }
        self
    }
}

// ---------------------------------------------------------------------------
// MatcherMut: Eth -- mutable, Option-backed, no gap check
// ---------------------------------------------------------------------------

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Eth: Within<Pos>,
    Acc: TupleAppend<&'a mut Eth>,
{
    /// Require an Ethernet header (mutable).
    pub fn eth(mut self) -> MatcherMut<'a, Eth, <Acc as TupleAppend<&'a mut Eth>>::Output> {
        let found = self.fields.eth.take().and_then(|opt| opt.as_mut());
        MatcherMut {
            acc: self.acc.and_then(|a| found.map(|v| a.append(v))),
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Eth: Within<Pos>,
    Acc: TupleAppend<Option<&'a mut Eth>>,
{
    /// Optionally match an Ethernet header (mutable).
    pub fn opt_eth(
        mut self,
    ) -> MatcherMut<'a, Eth, <Acc as TupleAppend<Option<&'a mut Eth>>>::Output> {
        let found = self.fields.eth.take().and_then(|opt| opt.as_mut());
        MatcherMut {
            acc: self.acc.map(|a| a.append(found)),
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// MatcherMut: Vlan -- mutable via split_first_mut
// ---------------------------------------------------------------------------

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Vlan: Within<Pos>,
    Acc: TupleAppend<&'a mut Vlan>,
{
    /// Require a VLAN header (mutable).
    pub fn vlan(mut self) -> MatcherMut<'a, Vlan, <Acc as TupleAppend<&'a mut Vlan>>::Output> {
        let slice = self.fields.vlan.take();
        let (found, rest) = match slice.and_then(|s| s.split_first_mut()) {
            Some((first, rest)) => (Some(first), Some(rest)),
            None => (None, None),
        };
        self.fields.vlan = rest;
        MatcherMut {
            acc: self.acc.and_then(|a| found.map(|v| a.append(v))),
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Vlan: Within<Pos>,
    Acc: TupleAppend<Option<&'a mut Vlan>>,
{
    /// Optionally match a VLAN header (mutable).
    ///
    /// If no VLAN is present at this position, `None` is appended and the
    /// slice is **not** consumed.
    pub fn opt_vlan(
        mut self,
    ) -> MatcherMut<'a, Vlan, <Acc as TupleAppend<Option<&'a mut Vlan>>>::Output> {
        let slice = self.fields.vlan.take();
        let has_element = matches!(slice.as_deref(), Some([_, ..]));
        let (found, rest) = if has_element {
            match slice.and_then(|s| s.split_first_mut()) {
                Some((first, rest)) => (Some(first), Some(rest)),
                None => unreachable!(),
            }
        } else {
            (None, slice) // put original back (empty or None)
        };
        self.fields.vlan = rest;
        MatcherMut {
            acc: self.acc.map(|a| a.append(found)),
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// MatcherMut: Net layer (Ipv4 / Ipv6) -- mutable, vlan gap check
// ---------------------------------------------------------------------------

macro_rules! matcher_mut_net {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Acc: TupleAppend<&'a mut $T>,
        {
            #[doc = concat!("Require ", stringify!($T), " (mutable).")]
            pub fn $name(mut self) -> MatcherMut<'a, $T, <Acc as TupleAppend<&'a mut $T>>::Output> {
                let gap_ok = self.fields.vlan_consumed();
                let found = self.fields.net.take().and_then(|opt| {
                    if !gap_ok {
                        return None;
                    }
                    match opt.as_mut() {
                        Some($variant(v)) => Some(v),
                        _ => None,
                    }
                });
                MatcherMut {
                    acc: self.acc.and_then(|a| found.map(|v| a.append(v))),
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Acc: TupleAppend<Option<&'a mut $T>>,
        {
            #[doc = concat!("Optionally match ", stringify!($T), " (mutable).")]
            pub fn $opt_name(
                mut self,
            ) -> MatcherMut<'a, $T, <Acc as TupleAppend<Option<&'a mut $T>>>::Output> {
                let gap_ok = self.fields.vlan_consumed();
                let net_field = self.fields.net.take();
                let acc = if !gap_ok {
                    None
                } else {
                    match net_field.and_then(|opt| opt.as_mut()) {
                        Some($variant(v)) => self.acc.map(|a| a.append(Some(v))),
                        None => self.acc.map(|a| a.append(None)),
                        Some(_) => None, // wrong variant = miss
                    }
                };
                MatcherMut {
                    acc,
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

matcher_mut_net!(ipv4 / opt_ipv4 -> Ipv4, Net::Ipv4);
matcher_mut_net!(ipv6 / opt_ipv6 -> Ipv6, Net::Ipv6);

// -- MatcherMut: Net enum (mutable) --

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Net: Within<Pos>,
    Acc: TupleAppend<&'a mut Net>,
{
    /// Require a network-layer header, returning a mutable [`Net`] enum.
    pub fn net(mut self) -> MatcherMut<'a, Net, <Acc as TupleAppend<&'a mut Net>>::Output> {
        let gap_ok = self.fields.vlan_consumed();
        let found = self.fields.net.take().and_then(|opt| {
            if !gap_ok {
                return None;
            }
            opt.as_mut()
        });
        MatcherMut {
            acc: self.acc.and_then(|a| found.map(|v| a.append(v))),
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Net: Within<Pos>,
    Acc: TupleAppend<Option<&'a mut Net>>,
{
    /// Optionally match a network-layer header, returning a mutable [`Net`] enum.
    pub fn opt_net(
        mut self,
    ) -> MatcherMut<'a, Net, <Acc as TupleAppend<Option<&'a mut Net>>>::Output> {
        let gap_ok = self.fields.vlan_consumed();
        let found = if gap_ok {
            self.fields.net.take().and_then(|opt| opt.as_mut())
        } else {
            let _ = self.fields.net.take();
            None
        };
        MatcherMut {
            acc: if gap_ok {
                self.acc.map(|a| a.append(found))
            } else {
                None
            },
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// MatcherMut: NetExt -- mutable via split_first_mut + variant match
// ---------------------------------------------------------------------------

macro_rules! matcher_mut_ext {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Acc: TupleAppend<&'a mut $T>,
        {
            #[doc = concat!("Require ", stringify!($T), " (mutable).")]
            pub fn $name(mut self) -> MatcherMut<'a, $T, <Acc as TupleAppend<&'a mut $T>>::Output> {
                let slice = self.fields.net_ext.take();
                let (found, rest) = match slice.and_then(|s| s.split_first_mut()) {
                    Some(($variant(v), rest)) => (Some(v), Some(rest)),
                    Some((_, _)) => (None, None), // wrong variant
                    None => (None, None),
                };
                self.fields.net_ext = rest;
                MatcherMut {
                    acc: self.acc.and_then(|a| found.map(|v| a.append(v))),
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Acc: TupleAppend<Option<&'a mut $T>>,
        {
            #[doc = concat!("Optionally match ", stringify!($T), " (mutable).")]
            pub fn $opt_name(
                mut self,
            ) -> MatcherMut<'a, $T, <Acc as TupleAppend<Option<&'a mut $T>>>::Output> {
                let slice = self.fields.net_ext.take();
                // Peek at the first element to decide whether to consume.
                let is_match = matches!(slice.as_deref(), Some([$variant(_), ..]));
                let (found, rest) = if is_match {
                    match slice.and_then(|s| s.split_first_mut()) {
                        Some(($variant(v), rest)) => (Some(v), Some(rest)),
                        _ => unreachable!(),
                    }
                } else {
                    (None, slice) // put original back unchanged
                };
                self.fields.net_ext = rest;
                MatcherMut {
                    acc: self.acc.map(|a| a.append(found)),
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

matcher_mut_ext!(hop_by_hop / opt_hop_by_hop -> HopByHop, NetExt::HopByHop);
matcher_mut_ext!(dest_opts  / opt_dest_opts  -> DestOpts, NetExt::DestOpts);
matcher_mut_ext!(routing    / opt_routing    -> Routing,  NetExt::Routing);
matcher_mut_ext!(fragment   / opt_fragment   -> Fragment, NetExt::Fragment);
matcher_mut_ext!(ipv4_auth  / opt_ipv4_auth  -> Ipv4Auth, NetExt::Ipv4Auth);
matcher_mut_ext!(ipv6_auth  / opt_ipv6_auth  -> Ipv6Auth, NetExt::Ipv6Auth);

// ---------------------------------------------------------------------------
// MatcherMut: Transport -- ext gap check via ExtGapCheck
// ---------------------------------------------------------------------------

macro_rules! matcher_mut_transport {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
            Acc: TupleAppend<&'a mut $T>,
        {
            #[doc = concat!("Require ", stringify!($T), " (mutable).")]
            pub fn $name(mut self) -> MatcherMut<'a, $T, <Acc as TupleAppend<&'a mut $T>>::Output> {
                let gap_ok = Pos::ext_gap_ok_mut(&self.fields);
                let found = self.fields.transport.take().and_then(|opt| {
                    if !gap_ok {
                        return None;
                    }
                    match opt.as_mut() {
                        Some($variant(v)) => Some(v),
                        _ => None,
                    }
                });
                MatcherMut {
                    acc: self.acc.and_then(|a| found.map(|v| a.append(v))),
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
            Acc: TupleAppend<Option<&'a mut $T>>,
        {
            #[doc = concat!("Optionally match ", stringify!($T), " (mutable).")]
            pub fn $opt_name(
                mut self,
            ) -> MatcherMut<'a, $T, <Acc as TupleAppend<Option<&'a mut $T>>>::Output> {
                let gap_ok = Pos::ext_gap_ok_mut(&self.fields);
                let transport_field = self.fields.transport.take();
                let acc = if !gap_ok {
                    None
                } else {
                    match transport_field.and_then(|opt| opt.as_mut()) {
                        Some($variant(v)) => self.acc.map(|a| a.append(Some(v))),
                        None => self.acc.map(|a| a.append(None)),
                        Some(_) => None,
                    }
                };
                MatcherMut {
                    acc,
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

matcher_mut_transport!(tcp   / opt_tcp   -> Tcp,   Transport::Tcp);
matcher_mut_transport!(udp   / opt_udp   -> Udp,   Transport::Udp);
matcher_mut_transport!(icmp4 / opt_icmp4 -> Icmp4, Transport::Icmp4);
matcher_mut_transport!(icmp6 / opt_icmp6 -> Icmp6, Transport::Icmp6);

// -- MatcherMut: Transport enum --

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Transport: Within<Pos>,
    Pos: ExtGapCheck,
    Acc: TupleAppend<&'a mut Transport>,
{
    /// Require a transport-layer header, returning a mutable [`Transport`] enum.
    pub fn transport(
        mut self,
    ) -> MatcherMut<'a, Transport, <Acc as TupleAppend<&'a mut Transport>>::Output> {
        let gap_ok = Pos::ext_gap_ok_mut(&self.fields);
        let found = self.fields.transport.take().and_then(|opt| {
            if !gap_ok {
                return None;
            }
            opt.as_mut()
        });
        MatcherMut {
            acc: self.acc.and_then(|a| found.map(|v| a.append(v))),
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Transport: Within<Pos>,
    Pos: ExtGapCheck,
    Acc: TupleAppend<Option<&'a mut Transport>>,
{
    /// Optionally match a transport-layer header, returning a mutable [`Transport`] enum.
    pub fn opt_transport(
        mut self,
    ) -> MatcherMut<'a, Transport, <Acc as TupleAppend<Option<&'a mut Transport>>>::Output> {
        let gap_ok = Pos::ext_gap_ok_mut(&self.fields);
        let found = if gap_ok {
            self.fields.transport.take().and_then(|opt| opt.as_mut())
        } else {
            let _ = self.fields.transport.take();
            None
        };
        MatcherMut {
            acc: if gap_ok {
                self.acc.map(|a| a.append(found))
            } else {
                None
            },
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

// ---------------------------------------------------------------------------
// MatcherMut: Vxlan -- mutable, Option-backed, no gap check
// ---------------------------------------------------------------------------

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Vxlan: Within<Pos>,
    Acc: TupleAppend<&'a mut Vxlan>,
{
    /// Require a VXLAN header (mutable).
    pub fn vxlan(mut self) -> MatcherMut<'a, Vxlan, <Acc as TupleAppend<&'a mut Vxlan>>::Output> {
        let found = self
            .fields
            .udp_encap
            .take()
            .and_then(|opt| match opt.as_mut() {
                Some(UdpEncap::Vxlan(v)) => Some(v),
                _ => None,
            });
        MatcherMut {
            acc: self.acc.and_then(|a| found.map(|v| a.append(v))),
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    Vxlan: Within<Pos>,
    Acc: TupleAppend<Option<&'a mut Vxlan>>,
{
    /// Optionally match a VXLAN header (mutable).
    pub fn opt_vxlan(
        mut self,
    ) -> MatcherMut<'a, Vxlan, <Acc as TupleAppend<Option<&'a mut Vxlan>>>::Output> {
        let encap_field = self.fields.udp_encap.take();
        let acc = match encap_field.and_then(|opt| opt.as_mut()) {
            Some(UdpEncap::Vxlan(v)) => self.acc.map(|a| a.append(Some(v))),
            None => self.acc.map(|a| a.append(None)),
            #[allow(unreachable_patterns)]
            Some(_) => None,
        };
        MatcherMut {
            acc,
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

// ===========================================================================
// EmbeddedMatcher -- pattern matching inside ICMP error payloads
// ===========================================================================
//
// After `.icmp4()` or `.icmp6()`, calling `.embedded()` transitions into
// an EmbeddedMatcher that operates on the inner headers.  The inner
// accumulator is finalized as a nested tuple when `.done()` is called.
//
// EmbeddedHeaders has: net (Option<Net>), net_ext (ArrayVec<NetExt, 3>),
// transport (Option<EmbeddedTransport>).  No eth, no vlan.

/// Immutable pattern matcher for embedded (inner) ICMP error headers.
#[must_use = "an EmbeddedMatcher does nothing until .done() is called"]
pub struct EmbeddedMatcher<'a, Pos, OuterAcc, InnerAcc> {
    embedded: Option<&'a EmbeddedHeaders>,
    outer_acc: Option<OuterAcc>,
    inner_acc: Option<InnerAcc>,
    ext_cursor: u8,
    _pos: core::marker::PhantomData<Pos>,
}

impl<Pos, OuterAcc, InnerAcc> EmbeddedMatcher<'_, Pos, OuterAcc, InnerAcc>
where
    OuterAcc: TupleAppend<InnerAcc>,
{
    /// Finalize both outer and inner matches.
    ///
    /// The inner accumulator is appended as a nested tuple to the outer one.
    #[must_use]
    pub fn done(self) -> Option<<OuterAcc as TupleAppend<InnerAcc>>::Output> {
        let outer = self.outer_acc?;
        let inner = self.inner_acc?;
        Some(outer.append(inner))
    }
}

impl<Pos, OuterAcc, InnerAcc> EmbeddedMatcher<'_, Pos, OuterAcc, InnerAcc> {
    /// Apply a predicate to the inner accumulator.
    pub fn when(self, pred: impl FnOnce(&InnerAcc) -> bool) -> Self {
        Self {
            inner_acc: self.inner_acc.filter(|a| pred(a)),
            ..self
        }
    }

    /// Peek at the inner accumulator for debugging or tracing.
    pub fn inspect(self, f: impl FnOnce(&InnerAcc)) -> Self {
        Self {
            inner_acc: self.inner_acc.inspect(|a| f(a)),
            ..self
        }
    }

    /// Run a closure if the inner match has already failed.
    pub fn otherwise(self, f: impl FnOnce()) -> Self {
        if self.inner_acc.is_none() {
            f();
        }
        self
    }
}

// -- .embedded() on immutable Matcher --

impl<'a, Pos, Acc> Matcher<'a, Pos, Acc>
where
    EmbeddedHeaders: Within<Pos>,
{
    /// Transition into the embedded (inner) ICMP error headers.
    ///
    /// Returns an [`EmbeddedMatcher`] whose chain methods accumulate into
    /// a nested sub-tuple.
    ///
    /// This is available after any ICMP position (not just error subtypes).
    /// The builder restricts `.embedded()` to error subtypes because it
    /// needs the subtype to *construct* a valid packet.  The matcher is
    /// reading a *parsed* packet where `embedded_ip` is either present or
    /// not -- if the ICMP message is not an error (e.g. echo request),
    /// `embedded_ip` will be `None` and the match simply fails.
    pub fn embedded(self) -> EmbeddedMatcher<'a, EmbeddedStart, Acc, ()> {
        let embedded = self.headers.embedded_ip();
        EmbeddedMatcher {
            outer_acc: if embedded.is_some() { self.acc } else { None },
            embedded,
            inner_acc: Some(()),
            ext_cursor: 0,
            _pos: core::marker::PhantomData,
        }
    }
}

// -- Net layer methods on EmbeddedMatcher --

macro_rules! embedded_net {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, OA, IA> EmbeddedMatcher<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            IA: TupleAppend<&'a $T>,
        {
            #[doc = concat!("Require inner ", stringify!($T), ".")]
            pub fn $name(self) -> EmbeddedMatcher<'a, $T, OA, <IA as TupleAppend<&'a $T>>::Output> {
                let found = self.embedded.and_then(|e| match &e.net {
                    Some($variant(v)) => Some(v),
                    _ => None,
                });
                EmbeddedMatcher {
                    embedded: self.embedded,
                    outer_acc: self.outer_acc,
                    inner_acc: self.inner_acc.and_then(|a| found.map(|v| a.append(v))),
                    ext_cursor: 0,
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, OA, IA> EmbeddedMatcher<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            IA: TupleAppend<Option<&'a $T>>,
        {
            #[doc = concat!("Optionally match inner ", stringify!($T), ".")]
            pub fn $opt_name(
                self,
            ) -> EmbeddedMatcher<'a, $T, OA, <IA as TupleAppend<Option<&'a $T>>>::Output> {
                let inner_acc = match self.embedded.map(|e| &e.net) {
                    Some(Some($variant(v))) => self.inner_acc.map(|a| a.append(Some(v))),
                    Some(None) | None => self.inner_acc.map(|a| a.append(None)),
                    Some(Some(_)) => None, // wrong variant = miss
                };
                EmbeddedMatcher {
                    embedded: self.embedded,
                    outer_acc: self.outer_acc,
                    inner_acc,
                    ext_cursor: 0,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

embedded_net!(ipv4 / opt_ipv4 -> Ipv4, Net::Ipv4);
embedded_net!(ipv6 / opt_ipv6 -> Ipv6, Net::Ipv6);

// -- Net enum on EmbeddedMatcher --

impl<'a, Pos, OA, IA> EmbeddedMatcher<'a, Pos, OA, IA>
where
    Net: Within<Pos>,
    IA: TupleAppend<&'a Net>,
{
    /// Require an inner network header, returning the [`Net`] enum.
    pub fn net(self) -> EmbeddedMatcher<'a, Net, OA, <IA as TupleAppend<&'a Net>>::Output> {
        let found = self.embedded.and_then(|e| e.net.as_ref());
        EmbeddedMatcher {
            embedded: self.embedded,
            outer_acc: self.outer_acc,
            inner_acc: self.inner_acc.and_then(|a| found.map(|v| a.append(v))),
            ext_cursor: 0,
            _pos: core::marker::PhantomData,
        }
    }
}

// -- Extension methods on EmbeddedMatcher --

macro_rules! embedded_ext {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, OA, IA> EmbeddedMatcher<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            IA: TupleAppend<&'a $T>,
        {
            #[doc = concat!("Require inner ", stringify!($T), ".")]
            pub fn $name(self) -> EmbeddedMatcher<'a, $T, OA, <IA as TupleAppend<&'a $T>>::Output> {
                let cursor = self.ext_cursor as usize;
                let found = self.embedded.and_then(|e| match e.net_ext.get(cursor) {
                    Some($variant(v)) => Some(v),
                    _ => None,
                });
                EmbeddedMatcher {
                    embedded: self.embedded,
                    outer_acc: self.outer_acc,
                    inner_acc: self.inner_acc.and_then(|a| found.map(|v| a.append(v))),
                    ext_cursor: self.ext_cursor.saturating_add(1),
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, OA, IA> EmbeddedMatcher<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            IA: TupleAppend<Option<&'a $T>>,
        {
            #[doc = concat!("Optionally match inner ", stringify!($T), ".")]
            pub fn $opt_name(
                self,
            ) -> EmbeddedMatcher<'a, $T, OA, <IA as TupleAppend<Option<&'a $T>>>::Output> {
                let cursor = self.ext_cursor as usize;
                let found = self.embedded.and_then(|e| match e.net_ext.get(cursor) {
                    Some($variant(v)) => Some(v),
                    _ => None,
                });
                let next_ec = if found.is_some() {
                    self.ext_cursor.saturating_add(1)
                } else {
                    self.ext_cursor
                };
                EmbeddedMatcher {
                    embedded: self.embedded,
                    outer_acc: self.outer_acc,
                    inner_acc: self.inner_acc.map(|a| a.append(found)),
                    ext_cursor: next_ec,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

embedded_ext!(hop_by_hop / opt_hop_by_hop -> HopByHop, NetExt::HopByHop);
embedded_ext!(dest_opts  / opt_dest_opts  -> DestOpts, NetExt::DestOpts);
embedded_ext!(routing    / opt_routing    -> Routing,  NetExt::Routing);
embedded_ext!(fragment   / opt_fragment   -> Fragment, NetExt::Fragment);
embedded_ext!(ipv4_auth  / opt_ipv4_auth  -> Ipv4Auth, NetExt::Ipv4Auth);
embedded_ext!(ipv6_auth  / opt_ipv6_auth  -> Ipv6Auth, NetExt::Ipv6Auth);

// -- Transport methods on EmbeddedMatcher (EmbeddedTransport variants) --

macro_rules! embedded_transport {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, OA, IA> EmbeddedMatcher<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
            IA: TupleAppend<&'a $T>,
        {
            #[doc = concat!("Require inner ", stringify!($T), ".")]
            pub fn $name(self) -> EmbeddedMatcher<'a, $T, OA, <IA as TupleAppend<&'a $T>>::Output> {
                let ec = self.ext_cursor;
                let found = self.embedded.and_then(|e| {
                    if !Pos::ext_gap_ok_embedded(e, ec) {
                        return None;
                    }
                    match &e.transport {
                        Some($variant(v)) => Some(v),
                        _ => None,
                    }
                });
                EmbeddedMatcher {
                    embedded: self.embedded,
                    outer_acc: self.outer_acc,
                    inner_acc: self.inner_acc.and_then(|a| found.map(|v| a.append(v))),
                    ext_cursor: ec,
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, OA, IA> EmbeddedMatcher<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
            IA: TupleAppend<Option<&'a $T>>,
        {
            #[doc = concat!("Optionally match inner ", stringify!($T), ".")]
            pub fn $opt_name(
                self,
            ) -> EmbeddedMatcher<'a, $T, OA, <IA as TupleAppend<Option<&'a $T>>>::Output> {
                let ec = self.ext_cursor;
                let gap_ok = self
                    .embedded
                    .map_or(false, |e| Pos::ext_gap_ok_embedded(e, ec));
                let found = if gap_ok {
                    self.embedded.and_then(|e| match &e.transport {
                        Some($variant(v)) => Some(Some(v)),
                        None => Some(None),
                        Some(_) => None,
                    })
                } else {
                    None
                };
                EmbeddedMatcher {
                    embedded: self.embedded,
                    outer_acc: self.outer_acc,
                    inner_acc: if gap_ok {
                        match found {
                            Some(v) => self.inner_acc.map(|a| a.append(v)),
                            None => None, // wrong variant or gap fail
                        }
                    } else {
                        None
                    },
                    ext_cursor: ec,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

embedded_transport!(tcp   / opt_tcp   -> TruncatedTcp,   EmbeddedTransport::Tcp);
embedded_transport!(udp   / opt_udp   -> TruncatedUdp,   EmbeddedTransport::Udp);
embedded_transport!(icmp4 / opt_icmp4 -> TruncatedIcmp4, EmbeddedTransport::Icmp4);
embedded_transport!(icmp6 / opt_icmp6 -> TruncatedIcmp6, EmbeddedTransport::Icmp6);

// -- .embedded() on MatcherMut --

// ===========================================================================
// EmbeddedMatcherMut -- mutable embedded ICMP payload matching
// ===========================================================================

/// Pre-split mutable references into [`EmbeddedHeaders`] fields (implementation detail).
#[doc(hidden)]
pub struct EmbeddedFields<'a> {
    net: Option<&'a mut Option<Net>>,
    net_ext: Option<&'a mut [NetExt]>,
    transport: Option<&'a mut Option<EmbeddedTransport>>,
}

impl EmbeddedFields<'_> {
    fn ext_consumed(&self) -> bool {
        self.net_ext.as_ref().is_none_or(|s| s.is_empty())
    }
}

/// Mutable pattern matcher for embedded (inner) ICMP error headers.
#[must_use = "an EmbeddedMatcherMut does nothing until .done() is called"]
pub struct EmbeddedMatcherMut<'a, Pos, OuterAcc, InnerAcc> {
    fields: EmbeddedFields<'a>,
    outer_acc: Option<OuterAcc>,
    inner_acc: Option<InnerAcc>,
    _pos: core::marker::PhantomData<Pos>,
}

impl<Pos, OuterAcc, InnerAcc> EmbeddedMatcherMut<'_, Pos, OuterAcc, InnerAcc>
where
    OuterAcc: TupleAppend<InnerAcc>,
{
    /// Finalize both outer and inner matches.
    #[must_use]
    pub fn done(self) -> Option<<OuterAcc as TupleAppend<InnerAcc>>::Output> {
        let outer = self.outer_acc?;
        let inner = self.inner_acc?;
        Some(outer.append(inner))
    }
}

impl<Pos, OuterAcc, InnerAcc> EmbeddedMatcherMut<'_, Pos, OuterAcc, InnerAcc> {
    /// Apply a predicate to the inner accumulator.
    pub fn when(self, pred: impl FnOnce(&InnerAcc) -> bool) -> Self {
        Self {
            inner_acc: self.inner_acc.filter(|a| pred(a)),
            ..self
        }
    }

    /// Peek at the inner accumulator for debugging or tracing.
    pub fn inspect(self, f: impl FnOnce(&InnerAcc)) -> Self {
        Self {
            inner_acc: self.inner_acc.inspect(|a| f(a)),
            ..self
        }
    }

    /// Run a closure if the inner match has already failed.
    pub fn otherwise(self, f: impl FnOnce()) -> Self {
        if self.inner_acc.is_none() {
            f();
        }
        self
    }
}

// -- .embedded() on MatcherMut --

impl<'a, Pos, Acc> MatcherMut<'a, Pos, Acc>
where
    EmbeddedHeaders: Within<Pos>,
{
    /// Transition into the embedded (inner) ICMP error headers (mutable).
    ///
    /// This is available after any ICMP position (not just error subtypes).
    /// The builder restricts `.embedded()` to error subtypes because it
    /// needs the subtype to *construct* a valid packet.  The matcher is
    /// reading a *parsed* packet where `embedded_ip` is either present or
    /// not -- if the ICMP message is not an error (e.g. echo request),
    /// `embedded_ip` will be `None` and the match simply fails.
    pub fn embedded(mut self) -> EmbeddedMatcherMut<'a, EmbeddedStart, Acc, ()> {
        let embedded = self.fields.embedded.take().and_then(|opt| opt.as_mut());
        match embedded {
            Some(e) => EmbeddedMatcherMut {
                outer_acc: self.acc,
                fields: EmbeddedFields {
                    net: Some(&mut e.net),
                    net_ext: Some(e.net_ext.as_mut_slice()),
                    transport: Some(&mut e.transport),
                },
                inner_acc: Some(()),
                _pos: core::marker::PhantomData,
            },
            None => EmbeddedMatcherMut {
                outer_acc: None,
                fields: EmbeddedFields {
                    net: None,
                    net_ext: None,
                    transport: None,
                },
                inner_acc: Some(()),
                _pos: core::marker::PhantomData,
            },
        }
    }
}

// -- Net on EmbeddedMatcherMut --

macro_rules! embedded_mut_net {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, OA, IA> EmbeddedMatcherMut<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            IA: TupleAppend<&'a mut $T>,
        {
            #[doc = concat!("Require inner ", stringify!($T), " (mutable).")]
            pub fn $name(
                mut self,
            ) -> EmbeddedMatcherMut<'a, $T, OA, <IA as TupleAppend<&'a mut $T>>::Output> {
                let found = self.fields.net.take().and_then(|opt| match opt.as_mut() {
                    Some($variant(v)) => Some(v),
                    _ => None,
                });
                EmbeddedMatcherMut {
                    inner_acc: self.inner_acc.and_then(|a| found.map(|v| a.append(v))),
                    outer_acc: self.outer_acc,
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, OA, IA> EmbeddedMatcherMut<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            IA: TupleAppend<Option<&'a mut $T>>,
        {
            #[doc = concat!("Optionally match inner ", stringify!($T), " (mutable).")]
            pub fn $opt_name(
                mut self,
            ) -> EmbeddedMatcherMut<'a, $T, OA, <IA as TupleAppend<Option<&'a mut $T>>>::Output>
            {
                let net_field = self.fields.net.take();
                let inner_acc = match net_field.and_then(|opt| opt.as_mut()) {
                    Some($variant(v)) => self.inner_acc.map(|a| a.append(Some(v))),
                    None => self.inner_acc.map(|a| a.append(None)),
                    Some(_) => None,
                };
                EmbeddedMatcherMut {
                    inner_acc,
                    outer_acc: self.outer_acc,
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

embedded_mut_net!(ipv4 / opt_ipv4 -> Ipv4, Net::Ipv4);
embedded_mut_net!(ipv6 / opt_ipv6 -> Ipv6, Net::Ipv6);

// -- Net enum on EmbeddedMatcherMut --

impl<'a, Pos, OA, IA> EmbeddedMatcherMut<'a, Pos, OA, IA>
where
    Net: Within<Pos>,
    IA: TupleAppend<&'a mut Net>,
{
    /// Require an inner network header (mutable [`Net`] enum).
    pub fn net(
        mut self,
    ) -> EmbeddedMatcherMut<'a, Net, OA, <IA as TupleAppend<&'a mut Net>>::Output> {
        let found = self.fields.net.take().and_then(|opt| opt.as_mut());
        EmbeddedMatcherMut {
            inner_acc: self.inner_acc.and_then(|a| found.map(|v| a.append(v))),
            outer_acc: self.outer_acc,
            fields: self.fields,
            _pos: core::marker::PhantomData,
        }
    }
}

// -- Ext on EmbeddedMatcherMut (uses split_first_mut) --

macro_rules! embedded_mut_ext {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, OA, IA> EmbeddedMatcherMut<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            IA: TupleAppend<&'a mut $T>,
        {
            #[doc = concat!("Require inner ", stringify!($T), " (mutable).")]
            pub fn $name(
                mut self,
            ) -> EmbeddedMatcherMut<'a, $T, OA, <IA as TupleAppend<&'a mut $T>>::Output> {
                let slice = self.fields.net_ext.take();
                let (found, rest) = match slice.and_then(|s| s.split_first_mut()) {
                    Some(($variant(v), rest)) => (Some(v), Some(rest)),
                    Some((_, _)) => (None, None),
                    None => (None, None),
                };
                self.fields.net_ext = rest;
                EmbeddedMatcherMut {
                    inner_acc: self.inner_acc.and_then(|a| found.map(|v| a.append(v))),
                    outer_acc: self.outer_acc,
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, OA, IA> EmbeddedMatcherMut<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            IA: TupleAppend<Option<&'a mut $T>>,
        {
            #[doc = concat!("Optionally match inner ", stringify!($T), " (mutable).")]
            pub fn $opt_name(
                mut self,
            ) -> EmbeddedMatcherMut<'a, $T, OA, <IA as TupleAppend<Option<&'a mut $T>>>::Output>
            {
                let slice = self.fields.net_ext.take();
                let is_match = matches!(slice.as_deref(), Some([$variant(_), ..]));
                let (found, rest) = if is_match {
                    match slice.and_then(|s| s.split_first_mut()) {
                        Some(($variant(v), rest)) => (Some(v), Some(rest)),
                        _ => unreachable!(),
                    }
                } else {
                    (None, slice)
                };
                self.fields.net_ext = rest;
                EmbeddedMatcherMut {
                    inner_acc: self.inner_acc.map(|a| a.append(found)),
                    outer_acc: self.outer_acc,
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

embedded_mut_ext!(hop_by_hop  / opt_hop_by_hop -> HopByHop, NetExt::HopByHop);
embedded_mut_ext!(dest_opts   / opt_dest_opts  -> DestOpts, NetExt::DestOpts);
embedded_mut_ext!(routing     / opt_routing    -> Routing,  NetExt::Routing);
embedded_mut_ext!(fragment    / opt_fragment   -> Fragment, NetExt::Fragment);
embedded_mut_ext!(ipv4_auth   / opt_ipv4_auth  -> Ipv4Auth, NetExt::Ipv4Auth);
embedded_mut_ext!(ipv6_auth   / opt_ipv6_auth  -> Ipv6Auth, NetExt::Ipv6Auth);

// -- Transport on EmbeddedMatcherMut --

macro_rules! embedded_mut_transport {
    ($name:ident / $opt_name:ident -> $T:ty, $variant:path) => {
        impl<'a, Pos, OA, IA> EmbeddedMatcherMut<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
            IA: TupleAppend<&'a mut $T>,
        {
            #[doc = concat!("Require inner ", stringify!($T), " (mutable).")]
            pub fn $name(
                mut self,
            ) -> EmbeddedMatcherMut<'a, $T, OA, <IA as TupleAppend<&'a mut $T>>::Output> {
                let gap_ok = Pos::ext_gap_ok_mut_embedded(&self.fields);
                let found = self.fields.transport.take().and_then(|opt| {
                    if !gap_ok {
                        return None;
                    }
                    match opt.as_mut() {
                        Some($variant(v)) => Some(v),
                        _ => None,
                    }
                });
                EmbeddedMatcherMut {
                    inner_acc: self.inner_acc.and_then(|a| found.map(|v| a.append(v))),
                    outer_acc: self.outer_acc,
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }

        impl<'a, Pos, OA, IA> EmbeddedMatcherMut<'a, Pos, OA, IA>
        where
            $T: Within<Pos>,
            Pos: ExtGapCheck,
            IA: TupleAppend<Option<&'a mut $T>>,
        {
            #[doc = concat!("Optionally match inner ", stringify!($T), " (mutable).")]
            pub fn $opt_name(
                mut self,
            ) -> EmbeddedMatcherMut<'a, $T, OA, <IA as TupleAppend<Option<&'a mut $T>>>::Output>
            {
                let gap_ok = Pos::ext_gap_ok_mut_embedded(&self.fields);
                let transport_field = self.fields.transport.take();
                let inner_acc = if !gap_ok {
                    None
                } else {
                    match transport_field.and_then(|opt| opt.as_mut()) {
                        Some($variant(v)) => self.inner_acc.map(|a| a.append(Some(v))),
                        None => self.inner_acc.map(|a| a.append(None)),
                        Some(_) => None,
                    }
                };
                EmbeddedMatcherMut {
                    inner_acc,
                    outer_acc: self.outer_acc,
                    fields: self.fields,
                    _pos: core::marker::PhantomData,
                }
            }
        }
    };
}

embedded_mut_transport!(tcp   / opt_tcp   -> TruncatedTcp,   EmbeddedTransport::Tcp);
embedded_mut_transport!(udp   / opt_udp   -> TruncatedUdp,   EmbeddedTransport::Udp);
embedded_mut_transport!(icmp4 / opt_icmp4 -> TruncatedIcmp4, EmbeddedTransport::Icmp4);
embedded_mut_transport!(icmp6 / opt_icmp6 -> TruncatedIcmp6, EmbeddedTransport::Icmp6);

#[cfg(test)]
mod tests {
    use crate::eth::Eth;
    use crate::eth::mac::{DestinationMac, Mac};
    use crate::headers::builder::header_chain;
    use crate::headers::{Headers, Net, Transport};
    use crate::ipv4::Ipv4;
    use crate::tcp::Tcp;
    use crate::udp::UdpPort;
    use crate::vlan::{Vid, Vlan};
    use crate::vxlan::Vni;

    #[test]
    fn eth_ipv4_tcp_matches() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .for_each(|h| {
                assert!(h.pat().eth().ipv4().tcp().done().is_some());
            });
    }

    #[test]
    fn vlan_causes_miss_when_not_in_pattern() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                assert!(
                    h.pat().eth().ipv4().tcp().done().is_none(),
                    "should miss: VLAN between Eth and Ipv4"
                );
            });
    }

    #[test]
    fn vlan_in_pattern_matches() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                assert!(h.pat().eth().vlan().ipv4().tcp().done().is_some());
            });
    }

    #[test]
    fn opt_vlan_matches_with_and_without() {
        fn check_pat(h: &Headers) -> Option<(&Eth, Option<&Vlan>, &Ipv4, &Tcp)> {
            h.pat().eth().opt_vlan().ipv4().tcp().done()
        }
        let with_vlan = header_chain()
            .eth(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {})
            .tcp(|_| {});
        let without_vlan = header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {});
        bolero::check!()
            .with_generator((with_vlan, without_vlan))
            .for_each(|(with, without)| {
                let Some((_, Some(_), _, _)) = check_pat(with) else {
                    panic!("did not match expected shape");
                };
                let Some((_, None, _, _)) = check_pat(without) else {
                    panic!("without VLAN: should match with vlan=None");
                };
            });
    }

    #[test]
    fn two_vlans_require_two_in_pattern() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {}),
            )
            .for_each(|h| {
                // One VLAN in pattern -- miss (second VLAN unconsumed)
                let result = h.pat().eth().vlan().ipv4().done();
                assert!(result.is_none(), "should miss: second VLAN not consumed");

                // Two VLANs in pattern -- match
                let result = h.pat().eth().vlan().vlan().ipv4().done();
                assert!(result.is_some());
            });
    }

    #[test]
    fn opt_vlan_opt_vlan_covers_zero_one_two() {
        let zero_gen = header_chain().eth(|_| {}).ipv4(|_| {});
        let one_gen = header_chain().eth(|_| {}).vlan(|_| {}).ipv4(|_| {});
        let two_gen = header_chain()
            .eth(|_| {})
            .vlan(|_| {})
            .vlan(|_| {})
            .ipv4(|_| {});
        bolero::check!()
            .with_generator((zero_gen, one_gen, two_gen))
            .for_each(|(zero, one, two)| {
                let r = zero.pat().eth().opt_vlan().opt_vlan().ipv4().done();
                let Some((_, None, None, _)) = r else {
                    panic!("zero vlans: wrong shape");
                };
                let r = one.pat().eth().opt_vlan().opt_vlan().ipv4().done();
                let Some((_, Some(_), None, _)) = r else {
                    panic!("one vlan: wrong shape");
                };
                let r = two.pat().eth().opt_vlan().opt_vlan().ipv4().done();
                let Some((_, Some(_), Some(_), _)) = r else {
                    panic!("two vlans: wrong shape");
                };
            });
    }

    #[test]
    fn ipv6_extensions_skipped_by_default() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .hop_by_hop(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                // From IP position, extensions are silently skipped.
                assert!(h.pat().eth().ipv6().tcp().done().is_some());
                // Explicitly matching an extension still works.
                assert!(h.pat().eth().ipv6().hop_by_hop().tcp().done().is_some());
            });
    }

    #[test]
    fn ipv6_extensions_strict_when_entered() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .hop_by_hop(|_| {})
                    .dest_opts(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                // Entered but incomplete -- miss
                assert!(h.pat().eth().ipv6().hop_by_hop().tcp().done().is_none());
                // Entered and complete -- match
                assert!(
                    h.pat()
                        .eth()
                        .ipv6()
                        .hop_by_hop()
                        .dest_opts()
                        .tcp()
                        .done()
                        .is_some()
                );
                // Skipping from IP position -- match
                assert!(h.pat().eth().ipv6().tcp().done().is_some());
            });
    }

    #[test]
    fn ipv4_auth_skipped_by_default_strict_when_entered() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .ipv4_auth(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                // From IPv4 position, AH is silently skipped.
                assert!(h.pat().eth().ipv4().tcp().done().is_some());
                // Explicitly matching AH works.
                assert!(h.pat().eth().ipv4().ipv4_auth().tcp().done().is_some());
            });
    }

    #[test]
    fn opt_extension_header() {
        let with_ext = header_chain()
            .eth(|_| {})
            .ipv6(|_| {})
            .hop_by_hop(|_| {})
            .tcp(|_| {});
        let without_ext = header_chain().eth(|_| {}).ipv6(|_| {}).tcp(|_| {});
        bolero::check!()
            .with_generator((with_ext, without_ext))
            .for_each(|(with, without)| {
                let r = with.pat().eth().ipv6().opt_hop_by_hop().tcp().done();
                let Some((_, _, Some(_), _)) = r else {
                    panic!("with ext: should have HopByHop");
                };
                let r = without.pat().eth().ipv6().opt_hop_by_hop().tcp().done();
                let Some((_, _, None, _)) = r else {
                    panic!("without ext: should not have HopByHop");
                };
            });
    }

    #[test]
    fn eth_ipv4_udp_vxlan() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .udp(|_| {})
                    .vxlan(|_| {}),
            )
            .for_each(|h| {
                assert!(h.pat().eth().ipv4().udp().vxlan().done().is_some());
            });
    }

    #[test]
    fn wrong_transport_misses() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).udp(|_| {}))
            .for_each(|h| {
                assert!(h.pat().eth().ipv4().tcp().done().is_none());
                assert!(h.pat().eth().ipv4().icmp4().done().is_none());
            });
    }

    #[test]
    fn wrong_net_misses() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv6(|_| {}).tcp(|_| {}))
            .for_each(|h| {
                assert!(h.pat().eth().ipv4().tcp().done().is_none());
            });
    }

    #[test]
    fn opt_tcp_at_tail() {
        let with_tcp = header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {});
        let with_udp = header_chain().eth(|_| {}).ipv4(|_| {}).udp(|_| {});
        bolero::check!()
            .with_generator((with_tcp, with_udp))
            .for_each(|(tcp_pkt, udp_pkt)| {
                // TCP present -> opt_tcp returns Some
                let Some((_, _, Some(_))) = tcp_pkt.pat().eth().ipv4().opt_tcp().done() else {
                    panic!("tcp should be present");
                };
                // Wrong transport variant -> miss (not "absent")
                assert!(
                    udp_pkt.pat().eth().ipv4().opt_tcp().done().is_none(),
                    "wrong transport variant should miss, not return None"
                );
            });
    }

    // -----------------------------------------------------------------------
    // MatcherMut tests
    // -----------------------------------------------------------------------

    #[test]
    fn pat_mut_eth_ipv4_tcp() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .cloned()
            .for_each(|mut h| {
                assert!(h.pat_mut().eth().ipv4().tcp().done().is_some());
            });
    }

    #[test]
    fn pat_mut_can_mutate() {
        use crate::tcp::TcpPort;
        use std::num::NonZero;

        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .cloned()
            .for_each(|mut h| {
                if let Some((_eth, _ipv4, tcp)) = h.pat_mut().eth().ipv4().tcp().done() {
                    tcp.set_source(TcpPort::new(NonZero::new(2000).unwrap()));
                }
                assert_eq!(
                    h.pat().eth().ipv4().tcp().done().unwrap().2.source(),
                    TcpPort::new(NonZero::new(2000).unwrap())
                );
            });
    }

    #[test]
    fn pat_mut_vlan_causes_miss() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {}),
            )
            .cloned()
            .for_each(|mut h| {
                assert!(h.pat_mut().eth().ipv4().tcp().done().is_none());
            });
    }

    #[test]
    fn pat_mut_opt_vlan() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {}),
            )
            .cloned()
            .for_each(|mut h| {
                let r = h.pat_mut().eth().opt_vlan().ipv4().tcp().done();
                let Some((_, Some(_), _, _)) = r else {
                    panic!("should match with VLAN present");
                };
            });
    }

    #[test]
    fn pat_mut_ipv6_ext() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .hop_by_hop(|_| {})
                    .tcp(|_| {}),
            )
            .cloned()
            .for_each(|mut h| {
                assert!(h.pat_mut().eth().ipv6().hop_by_hop().tcp().done().is_some());
            });
    }

    #[test]
    fn pat_mut_wrong_variant_misses() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).udp(|_| {}))
            .cloned()
            .for_each(|mut h| {
                assert!(h.pat_mut().eth().ipv4().tcp().done().is_none());
            });
    }

    #[test]
    fn pat_mut_fuzz() {
        let generator = || {
            crate::headers::builder::header_chain()
                .eth(|_| {})
                .ipv4(|_| {})
                .tcp(|_| {})
        };
        bolero::check!()
            .with_generator((generator(), generator()))
            .cloned()
            .for_each(|(mut h, _)| {
                assert!(h.pat_mut().eth().ipv4().tcp().done().is_some());
            });
    }

    // -----------------------------------------------------------------------
    // Enum-level (.net() / .transport()) tests
    // -----------------------------------------------------------------------

    #[test]
    fn net_enum_matches_ipv4() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .for_each(|h| {
                let Some((_, Net::Ipv4(_), Transport::Tcp(_))) =
                    h.pat().eth().net().transport().done()
                else {
                    panic!("should match Ipv4/Tcp");
                };
            });
    }

    #[test]
    fn net_enum_matches_ipv6() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv6(|_| {}).udp(|_| {}))
            .for_each(|h| {
                let Some((_, Net::Ipv6(_), Transport::Udp(_))) =
                    h.pat().eth().net().transport().done()
                else {
                    panic!("should match Ipv6/Udp");
                };
            });
    }

    #[test]
    fn net_enum_gap_check_still_works() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                assert!(h.pat().eth().net().done().is_none());
                assert!(h.pat().eth().vlan().net().done().is_some());
            });
    }

    #[test]
    fn transport_enum_skips_extensions_by_default() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .hop_by_hop(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                assert!(h.pat().eth().ipv6().transport().done().is_some());
                assert!(
                    h.pat()
                        .eth()
                        .ipv6()
                        .hop_by_hop()
                        .transport()
                        .done()
                        .is_some()
                );
            });
    }

    #[test]
    fn net_then_tcp_works() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .for_each(|h| {
                assert!(h.pat().eth().net().tcp().done().is_some());
            });
    }

    #[test]
    fn pat_mut_net_transport() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .cloned()
            .for_each(|mut h| {
                let Some((_, Net::Ipv4(_), _)) = h.pat_mut().eth().net().transport().done() else {
                    panic!("should match");
                };
            });
    }

    #[test]
    fn double_vlan_gap_detection_and_mutation() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|v| {
                        v.set_vid(Vid::new(18).unwrap());
                    })
                    .vlan(|v| {
                        v.set_vid(Vid::new(7).unwrap());
                    })
                    .ipv4(|_| {})
                    .udp(|_| {})
                    .vxlan(|_| {}),
            )
            .cloned()
            .for_each(|mut h| {
                // No VLAN in pattern -> miss
                assert!(h.pat().eth().net().transport().done().is_none());
                // One VLAN in pattern -> miss (second unconsumed)
                assert!(h.pat().eth().vlan().net().transport().done().is_none());
                // Both VLANs -> match, and mutation works
                let Some((eth, svlan, cvlan, _ip, udp, vxlan)) =
                    h.pat_mut().eth().vlan().vlan().ipv4().udp().vxlan().done()
                else {
                    panic!("should match double-vlan shape");
                };
                eth.set_destination(DestinationMac::new(Mac([0x02, 1, 2, 3, 4, 5])).unwrap());
                assert_eq!(svlan.vid(), Vid::new(18).unwrap());
                cvlan.set_vid(Vid::new(128).unwrap());
                udp.set_source(UdpPort::new_checked(18).unwrap());
                vxlan.set_vni(Vni::new_checked(12).unwrap());
            });
    }

    // -----------------------------------------------------------------------
    // Embedded matcher tests
    // -----------------------------------------------------------------------

    #[test]
    fn embedded_ipv4_tcp() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .icmp4(|_| {})
                    .dest_unreachable(|_| {})
                    .embed_ipv4(|_| {})
                    .embed_tcp(|_| {}),
            )
            .for_each(|h| {
                assert!(
                    h.pat()
                        .eth()
                        .ipv4()
                        .icmp4()
                        .embedded()
                        .ipv4()
                        .tcp()
                        .done()
                        .is_some()
                );
            });
    }

    #[test]
    fn embedded_ipv4_opt_tcp() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .icmp4(|_| {})
                    .dest_unreachable(|_| {})
                    .embed_ipv4(|_| {})
                    .embed_tcp(|_| {}),
            )
            .for_each(|h| {
                let Some((_, _, _, (_, Some(_)))) = h
                    .pat()
                    .eth()
                    .ipv4()
                    .icmp4()
                    .embedded()
                    .ipv4()
                    .opt_tcp()
                    .done()
                else {
                    panic!("tcp should be present in embedded");
                };
            });
    }

    #[test]
    fn embedded_wrong_transport_misses() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .icmp4(|_| {})
                    .dest_unreachable(|_| {})
                    .embed_ipv4(|_| {})
                    .embed_udp(|_| {}),
            )
            .for_each(|h| {
                assert!(
                    h.pat()
                        .eth()
                        .ipv4()
                        .icmp4()
                        .embedded()
                        .ipv4()
                        .tcp()
                        .done()
                        .is_none(),
                    "should miss: embedded has UDP, not TCP"
                );
            });
    }

    #[test]
    fn embedded_mut_nat_rewrite() {
        use std::net::Ipv4Addr;

        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .icmp4(|_| {})
                    .dest_unreachable(|_| {})
                    .embed_ipv4(|_| {})
                    .embed_tcp(|_| {}),
            )
            .cloned()
            .for_each(|mut h| {
                if let Some((_eth, _outer_ip, _icmp, (inner_ip, inner_tcp))) = h
                    .pat_mut()
                    .eth()
                    .ipv4()
                    .icmp4()
                    .embedded()
                    .ipv4()
                    .tcp()
                    .done()
                {
                    inner_ip.set_destination(Ipv4Addr::new(192, 168, 1, 100));
                    inner_tcp.set_source(crate::tcp::TcpPort::new_checked(2000).unwrap());
                } else {
                    panic!("should match");
                }

                let (_, _, _, (ip, tcp)) = h
                    .pat()
                    .eth()
                    .ipv4()
                    .icmp4()
                    .embedded()
                    .ipv4()
                    .tcp()
                    .done()
                    .unwrap();
                assert_eq!(ip.destination(), Ipv4Addr::new(192, 168, 1, 100));
                assert_eq!(
                    tcp.source(),
                    crate::tcp::TcpPort::new_checked(2000).unwrap()
                );
            });
    }

    // -----------------------------------------------------------------------
    // Bolero fuzz tests
    // -----------------------------------------------------------------------

    /// Eth/IPv4/TCP always matches when built that way.
    #[test]
    fn fuzz_eth_ipv4_tcp_always_matches() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .for_each(|h| {
                assert!(h.pat().eth().ipv4().tcp().done().is_some());
                assert!(h.pat().eth().net().transport().done().is_some());
            });
    }

    /// Eth/IPv6/UDP always matches when built that way.
    #[test]
    fn fuzz_eth_ipv6_udp_always_matches() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv6(|_| {}).udp(|_| {}))
            .for_each(|h| {
                assert!(h.pat().eth().ipv6().udp().done().is_some());
                assert!(h.pat().eth().net().transport().done().is_some());
            });
    }

    /// Wrong transport variant never matches.
    #[test]
    fn fuzz_wrong_transport_never_matches() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).udp(|_| {}))
            .for_each(|h| {
                assert!(h.pat().eth().ipv4().tcp().done().is_none());
                assert!(h.pat().eth().ipv4().icmp4().done().is_none());
            });
    }

    /// Wrong net variant never matches.
    #[test]
    fn fuzz_wrong_net_never_matches() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv6(|_| {}).tcp(|_| {}))
            .for_each(|h| {
                assert!(h.pat().eth().ipv4().tcp().done().is_none());
            });
    }

    /// VLAN gap detection: Eth/Vlan/IPv4/TCP misses Eth/IPv4/TCP pattern.
    #[test]
    fn fuzz_vlan_gap_detected() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                // Skipping the VLAN must miss
                assert!(h.pat().eth().ipv4().tcp().done().is_none());
                // Including the VLAN must match
                assert!(h.pat().eth().vlan().ipv4().tcp().done().is_some());
                // Optional VLAN must match
                assert!(h.pat().eth().opt_vlan().ipv4().tcp().done().is_some());
            });
    }

    /// Without VLAN, `opt_vlan` still matches (with None).
    #[test]
    fn fuzz_opt_vlan_without_vlan() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .for_each(|h| {
                let result = h.pat().eth().opt_vlan().ipv4().tcp().done();
                assert!(result.is_some());
                let (_, vlan, _, _) = result.unwrap();
                assert!(vlan.is_none());
            });
    }

    /// IPv6 extensions are skipped from IP position.
    #[test]
    fn fuzz_ipv6_ext_skipped_by_default() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .hop_by_hop(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                // Direct to TCP from IPv6 -- extensions skipped
                assert!(h.pat().eth().ipv6().tcp().done().is_some());
                // Explicit HopByHop then TCP -- strict, works
                assert!(h.pat().eth().ipv6().hop_by_hop().tcp().done().is_some());
            });
    }

    /// IPv6 extensions are strict when entered.
    #[test]
    fn fuzz_ipv6_ext_strict_when_entered() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv6(|_| {})
                    .hop_by_hop(|_| {})
                    .dest_opts(|_| {})
                    .tcp(|_| {}),
            )
            .for_each(|h| {
                // Skipping from IP -- works
                assert!(h.pat().eth().ipv6().tcp().done().is_some());
                // Entered but incomplete -- misses
                assert!(h.pat().eth().ipv6().hop_by_hop().tcp().done().is_none());
                // Entered and complete -- works
                assert!(
                    h.pat()
                        .eth()
                        .ipv6()
                        .hop_by_hop()
                        .dest_opts()
                        .tcp()
                        .done()
                        .is_some()
                );
            });
    }

    /// Mutable matcher always matches the same shapes as immutable.
    #[test]
    fn fuzz_dis_mut_matches_same_as_dis() {
        bolero::check!()
            .with_generator(header_chain().eth(|_| {}).ipv4(|_| {}).tcp(|_| {}))
            .cloned()
            .for_each(|mut h| {
                assert!(h.pat_mut().eth().ipv4().tcp().done().is_some());
            });
    }

    /// Mutable matcher with VLAN gap detection.
    #[test]
    fn fuzz_dis_mut_vlan_gap() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .vlan(|_| {})
                    .ipv4(|_| {})
                    .tcp(|_| {}),
            )
            .cloned()
            .for_each(|mut h| {
                assert!(h.pat_mut().eth().ipv4().tcp().done().is_none());
                assert!(h.pat_mut().eth().vlan().ipv4().tcp().done().is_some());
            });
    }

    /// Eth/IPv4/UDP/VXLAN always matches.
    #[test]
    fn fuzz_vxlan_always_matches() {
        bolero::check!()
            .with_generator(
                header_chain()
                    .eth(|_| {})
                    .ipv4(|_| {})
                    .udp(|_| {})
                    .vxlan(|_| {}),
            )
            .for_each(|h| {
                assert!(h.pat().eth().ipv4().udp().vxlan().done().is_some());
            });
    }

    // -----------------------------------------------------------------------
    // Adversarial tests: structurally broken Headers
    // -----------------------------------------------------------------------
    //
    // These use HeadersBuilder to construct states that the parser would
    // never produce but that can exist mid-pipeline (e.g. during NAT64
    // conversion where IPv4 has been rewritten to IPv6 but ICMP4 hasn't
    // been converted yet).

    use crate::headers::HeadersBuilder;

    /// Transport present but no net header.
    #[test]
    fn adversarial_transport_without_net() {
        let h = HeadersBuilder::default()
            .eth(Some(crate::headers::builder::Blank::blank()))
            .transport(Some(
                Transport::Tcp(crate::headers::builder::Blank::blank()),
            ))
            .build()
            .unwrap();

        // Should miss: no IP layer to match
        assert!(h.pat().eth().ipv4().tcp().done().is_none());
        assert!(h.pat().eth().ipv6().tcp().done().is_none());
        // net() also misses
        assert!(h.pat().eth().net().done().is_none());
    }

    /// Mismatched IP version and ICMP version (e.g. mid-NAT64).
    #[test]
    fn adversarial_ipv4_with_icmp6() {
        let h = HeadersBuilder::default()
            .eth(Some(crate::headers::builder::Blank::blank()))
            .net(Some(Net::Ipv4(crate::headers::builder::Blank::blank())))
            .transport(Some(Transport::Icmp6(
                crate::headers::builder::Blank::blank(),
            )))
            .build()
            .unwrap();

        // ipv4().icmp6() won't compile (Icmp6: !Within<Ipv4>), which is
        // correct. But ipv4().transport() should match -- it gives back
        // the Transport enum for the caller to discover the mismatch.
        let result = h.pat().eth().ipv4().transport().done();
        assert!(result.is_some());
        let (_, _, t) = result.unwrap();
        assert!(matches!(t, Transport::Icmp6(_)));

        // ipv4().tcp() misses (wrong transport variant, correct behavior)
        assert!(h.pat().eth().ipv4().tcp().done().is_none());
    }

    /// Embedded headers present but transport is TCP (not ICMP).
    #[test]
    fn adversarial_embedded_without_icmp() {
        let h = HeadersBuilder::default()
            .eth(Some(crate::headers::builder::Blank::blank()))
            .net(Some(Net::Ipv4(crate::headers::builder::Blank::blank())))
            .transport(Some(
                Transport::Tcp(crate::headers::builder::Blank::blank()),
            ))
            .embedded_ip(Some(crate::headers::EmbeddedHeaders::default()))
            .build()
            .unwrap();

        // .embedded() requires Within<Icmp4> or Within<Icmp6>, so
        // .tcp().embedded() won't compile -- you can only enter embedded
        // from an ICMP position. Since this packet has TCP transport,
        // the embedded headers are unreachable through the matcher chain.
        let result = h.pat().eth().ipv4().transport().done();
        assert!(result.is_some());
    }

    /// VLANs present but no net header.
    #[test]
    fn adversarial_vlans_without_net() {
        let h = HeadersBuilder::default()
            .eth(Some(crate::headers::builder::Blank::blank()))
            .vlan({
                let mut v = arrayvec::ArrayVec::new();
                v.push(crate::headers::builder::Blank::blank());
                v
            })
            .build()
            .unwrap();

        // opt_vlan matches (VLAN is present)
        let result = h.pat().eth().opt_vlan().ipv4().done();
        // But ipv4 misses (no net header)
        assert!(result.is_none());

        // vlan matches, then net misses
        let result = h.pat().eth().vlan().net().done();
        assert!(result.is_none());
    }

    /// Empty headers -- everything is None/default.
    #[test]
    fn adversarial_empty_headers() {
        let h = HeadersBuilder::default().build().unwrap();

        assert!(h.pat().eth().done().is_none());
        // opt_eth on empty headers: eth is absent
        let result = h.pat().opt_eth().done();
        assert!(result.is_some());
        let (None,) = result.unwrap() else {
            panic!("eth should be absent");
        };
    }
}
