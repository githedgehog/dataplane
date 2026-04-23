// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Type-carried structural proofs over [`Headers`].
//!
//! A [`Window<T>`] is a [`Headers`] that has been validated at construction
//! to conform to a specific shape `T`.  Downstream code that receives a
//! `Window<T>` can extract typed references to the matched layers via the
//! [`Look`] trait without re-validating at each access site.
//!
//! # Safety boundary
//!
//! Zero-cost extraction is achieved by informing the optimizer, via
//! `unreachable_unchecked`, that the `Window` type invariant rules out
//! the failure arms of layer-access match expressions.  The `unsafe`
//! required for this is fully contained:
//!
//! * [`Window::new`] is the only way to construct a `Window<T>`, and it
//!   validates the shape using [`ExtractUnchecked::try_extract`] for each
//!   layer in `T`.
//! * [`ExtractUnchecked`] is crate-private.  Its `extract_unchecked`
//!   method is `unsafe fn` and carries a presence-proof obligation which
//!   is discharged, once, by the `Window<T>` newtype invariant.
//! * External callers see only [`Window`] and [`Look`].  They cannot
//!   implement [`ExtractUnchecked`] or call it directly.
//!
//! This matches the "safe abstraction built from local unsafe
//! scaffolding" pattern in `development/code/unsafe-code.md`.

#![allow(unsafe_code)] // scaffolding for safe Window abstraction; see module docs

use core::marker::PhantomData;

use crate::eth::Eth;
use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
use crate::tcp::Tcp;
use crate::udp::Udp;

use super::{Headers, Net, Transport};

/// A [`Headers`] whose structural shape has been validated at construction
/// to match the tuple type parameter `T`.
///
/// `T` is a reference-tuple marker (e.g. `(&Eth,)`,
/// `(&Eth, &Ipv4, &Tcp)`).  Its presence at the type level asserts that
/// the underlying [`Headers`] actually contains those layers in that
/// order.
///
/// Construct via [`Window::new`].  Extract typed references via
/// [`Look::look`].
#[repr(transparent)]
pub struct Window<T>(Headers, PhantomData<T>);

impl<T> Window<T> {
    /// Unwrap the `Window` back into the underlying [`Headers`].
    pub fn into_headers(self) -> Headers {
        self.0
    }
}

/// Declared, checkable shapes for [`Window<T>`].
///
/// Sealed: only shapes the crate declares via `define_window!` are
/// [`Shape`]s.  External crates use [`Shape`] as a bound on generic
/// code but cannot add new shapes; the shape catalog is owned here.
pub trait Shape: sealed::Sealed {}

mod sealed {
    use super::Headers;

    pub trait Sealed {
        /// Check that `h`'s structure matches this shape.
        fn matches(h: &Headers) -> bool;
    }
}

/// Type-level "Self is a prefix of `Wide`."
///
/// If `ShapePrefix<Wide>` is implemented for `Narrow`, then any
/// `Headers` that satisfies `Wide` also satisfies `Narrow`, and by
/// extension `&Window<Wide>` can be viewed as `&Window<Narrow>` for
/// free (see the [`AsRef`] blanket impl below).
///
/// The lattice is generated alongside the shape catalog: each
/// [`define_window!`] invocation emits the reflexive impl, and
/// strict-prefix impls between declared shapes are emitted via
/// [`define_shape_prefix!`].
///
/// Sealed via [`Shape`]: callers can use `ShapePrefix` as a bound but
/// cannot introduce new lattice elements.
pub trait ShapePrefix<Wide>: Shape
where
    Wide: Shape,
{
}

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
        // `Narrow: ShapePrefix<Wide>` plus the existing `Wide` proof on
        // `self` means `Headers` inside `self` also satisfies
        // `Narrow`; reinterpreting the reference is sound.
        unsafe { &*(self as *const Window<Wide> as *const Window<Narrow>) }
    }
}

impl Headers {
    /// Borrow `self` as a [`Window<T>`] if its structure matches `T`.
    ///
    /// Non-consuming companion to [`Window::new`].  Returns `None` if
    /// the shape doesn't match; does not move out of `self`.
    #[inline]
    pub fn as_window<T>(&self) -> Option<&Window<T>>
    where
        T: Shape,
    {
        if <T as sealed::Sealed>::matches(self) {
            // SAFETY: `matches` returned true, so the Window<T> shape
            // invariant holds for this Headers.  Window<T> is
            // #[repr(transparent)] over Headers, so a &Headers and
            // &Window<T> have identical representations.
            Some(unsafe { &*(self as *const Headers as *const Window<T>) })
        } else {
            None
        }
    }

    /// Mutable borrow of `self` as a `&mut Window<T>` if its structure
    /// matches `T`.  Same invariant and cast as [`Self::as_window`].
    #[inline]
    pub fn as_window_mut<T>(&mut self) -> Option<&mut Window<T>>
    where
        T: Shape,
    {
        if <T as sealed::Sealed>::matches(self) {
            // SAFETY: same as as_window, with exclusive borrow preserved.
            Some(unsafe { &mut *(self as *mut Headers as *mut Window<T>) })
        } else {
            None
        }
    }
}

/// Extract typed references to the layers a [`Window<T>`] holds.
///
/// Implemented for each valid shape tuple `T`.  `Refs<'a>` is the tuple
/// of references returned by [`Self::look`].
pub trait Look<T> {
    /// The tuple of typed references produced by [`Self::look`].
    type Refs<'a>
    where
        Self: 'a;

    /// Extract typed references to the matched layers.
    ///
    /// Compiles to pure field-offset computations; the `Window` type
    /// invariant guarantees presence so no runtime check is needed.
    fn look<'a>(&'a self) -> Self::Refs<'a>
    where
        Self: 'a;
}

/// Crate-private: maps a layer type to its location in [`Headers`].
///
/// Consumers never see this trait.  It exists as internal scaffolding
/// for the [`Look`] impls generated by [`define_window!`].
pub(crate) trait ExtractUnchecked: Sized {
    /// Safely attempt to extract a reference to `Self` from `h`.  Used
    /// by [`Window::new`] to validate the shape at construction.
    fn try_extract(h: &Headers) -> Option<&Self>;

    /// Extract a reference to `Self` from `h`, assuming presence.
    ///
    /// # Safety
    ///
    /// The caller must hold a proof that `Self` is structurally present
    /// in `h`.  The `Window<T>` newtype invariant (established by
    /// [`Window::new`]) is such a proof for any `Self` whose reference
    /// appears in `T`.  Calling this without such a proof is undefined
    /// behavior.
    #[inline(always)]
    unsafe fn extract_unchecked(h: &Headers) -> &Self {
        match Self::try_extract(h) {
            Some(x) => x,
            None => unsafe { core::hint::unreachable_unchecked() },
        }
    }
}

impl ExtractUnchecked for Eth {
    #[inline(always)]
    fn try_extract(h: &Headers) -> Option<&Eth> {
        h.eth()
    }
}

impl ExtractUnchecked for Ipv4 {
    #[inline(always)]
    fn try_extract(h: &Headers) -> Option<&Ipv4> {
        match h.net() {
            Some(Net::Ipv4(ip)) => Some(ip),
            _ => None,
        }
    }
}

impl ExtractUnchecked for Ipv6 {
    #[inline(always)]
    fn try_extract(h: &Headers) -> Option<&Ipv6> {
        match h.net() {
            Some(Net::Ipv6(ip)) => Some(ip),
            _ => None,
        }
    }
}

impl ExtractUnchecked for Tcp {
    #[inline(always)]
    fn try_extract(h: &Headers) -> Option<&Tcp> {
        match h.transport() {
            Some(Transport::Tcp(t)) => Some(t),
            _ => None,
        }
    }
}

impl ExtractUnchecked for Udp {
    #[inline(always)]
    fn try_extract(h: &Headers) -> Option<&Udp> {
        match h.transport() {
            Some(Transport::Udp(u)) => Some(u),
            _ => None,
        }
    }
}

/// Expand a shape (list of layer types) into:
/// - an `impl<'x> Window<(&'x T1, &'x T2, ...)>` with a `new` that
///   validates the shape,
/// - an `impl<'x> Look<(&'x T1, ...)> for Window<...>` whose `look`
///   is zero-cost under the `Window` invariant.
///
/// Crate-private.  External crates compose pre-defined shapes rather
/// than declare new ones.  Adding a shape is a one-line change here.
macro_rules! define_window {
    ($($ty:ty),+ $(,)?) => {
        impl<'x> Window<($(&'x $ty,)+)>
        where
            Self: 'x,
        {
            /// Validate the shape and construct a `Window` on success,
            /// returning the original [`Headers`] on failure.
            pub fn new(headers: Headers) -> Result<Self, Headers> {
                let ok = true
                    $( && <$ty as ExtractUnchecked>::try_extract(&headers).is_some() )+;
                if ok {
                    Ok(Window(headers, PhantomData))
                } else {
                    Err(headers)
                }
            }
        }

        impl<'x> Look<($(&'x $ty,)+)> for Window<($(&'x $ty,)+)>
        where
            Self: 'x,
        {
            type Refs<'a>
                = ($(&'a $ty,)+)
            where
                Self: 'a;

            #[inline(always)]
            fn look<'a>(&'a self) -> Self::Refs<'a>
            where
                Self: 'a,
            {
                unsafe {
                    (
                        $( <$ty as ExtractUnchecked>::extract_unchecked(&self.0), )+
                    )
                }
            }
        }

        impl<'x> Shape for ($(&'x $ty,)+) {}

        impl<'x> sealed::Sealed for ($(&'x $ty,)+) {
            #[inline(always)]
            fn matches(h: &Headers) -> bool {
                true $( && <$ty as ExtractUnchecked>::try_extract(h).is_some() )+
            }
        }

        // Reflexive: every shape is a prefix of itself.
        impl<'x> ShapePrefix<($(&'x $ty,)+)> for ($(&'x $ty,)+) {}
    };
}

/// Declare `Narrow` as a strict prefix of `Wide`.  Both sides must be
/// tuples of `&`-layer-types (the same form `define_window!` consumes).
///
/// Emits `impl ShapePrefix<Wide> for Narrow`.  Reflexive impls are
/// emitted by `define_window!`; this helper is for the strict-prefix
/// pairs.
macro_rules! define_shape_prefix {
    (($($narrow:ty),+ $(,)?) => ($($wide:ty),+ $(,)?)) => {
        impl<'x> ShapePrefix<($(&'x $wide,)+)> for ($(&'x $narrow,)+) {}
    };
}

define_window!(Eth);
define_window!(Eth, Ipv4);
define_window!(Eth, Ipv6);
define_window!(Eth, Ipv4, Tcp);
define_window!(Eth, Ipv4, Udp);
define_window!(Eth, Ipv6, Tcp);
define_window!(Eth, Ipv6, Udp);

// Strict-prefix impls.  Every declared super-shape names its proper
// prefixes so a `&Window<Wide>` can be viewed as `&Window<Narrow>`.
// Reflexive cases are in the macro above.

// Single-layer narrow.
define_shape_prefix!((Eth) => (Eth, Ipv4));
define_shape_prefix!((Eth) => (Eth, Ipv6));
define_shape_prefix!((Eth) => (Eth, Ipv4, Tcp));
define_shape_prefix!((Eth) => (Eth, Ipv4, Udp));
define_shape_prefix!((Eth) => (Eth, Ipv6, Tcp));
define_shape_prefix!((Eth) => (Eth, Ipv6, Udp));

// Two-layer narrow (Eth + net).
define_shape_prefix!((Eth, Ipv4) => (Eth, Ipv4, Tcp));
define_shape_prefix!((Eth, Ipv4) => (Eth, Ipv4, Udp));
define_shape_prefix!((Eth, Ipv6) => (Eth, Ipv6, Tcp));
define_shape_prefix!((Eth, Ipv6) => (Eth, Ipv6, Udp));
