// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Loom backend: poison-as-panic wrapper around `loom::sync` plus a
//! local `Arc<T>` / `Weak<T>` shim.
//!
//! `loom::sync::{Mutex, RwLock}` return `LockResult<Guard>` because they
//! mirror `std::sync`'s shape. This workspace treats poison as a fatal
//! invariant violation; the wrapper below strips `LockResult` and
//! panics, presenting the same naked-guard surface as the default
//! production backend.
//!
//! `OnceLock` is taken from `std::sync` (loom doesn't ship one). Same
//! for `LockResult` / `TryLockResult` / `TryLockError` / `PoisonError`
//! / `Once` / `OnceState` / `BarrierWaitResult` -- loom does not ship
//! these, but loom's own `Mutex::lock` returns `std::sync::LockResult`
//! so re-exporting the std types here matches the wrapped surface
//! exactly.
//!
//! ## Arc / Weak
//!
//! Loom 0.7 ships `Arc<T>` but no `Weak<T>` and no `Arc::downgrade`.
//! The wrapper at the bottom of this file adds both. The `Weak<T>`
//! shim holds a *strong* clone of the inner `loom::sync::Arc<T>` until
//! the `Weak` itself drops. Consequences:
//!
//!   * `Weak::upgrade` after a successful `Arc::downgrade` always
//!     returns `Some` -- the upgrade-fails-after-last-strong-drop race
//!     real `Weak` exposes is not modelled.
//!   * `Arc::strong_count` reflects live `Arc`s **and** live `Weak`s.
//!   * `Arc::weak_count` panics: the shim has no separate weak count
//!     to report, and returning `0` silently would make assertions
//!     pass for the wrong reason on every backend. See the per-method
//!     SAFETY note for the rationale.
//!   * Last `Arc` drop will not free the value if any `Weak` is still
//!     live; the value is freed when the last `Arc`-or-`Weak` drops.
//!
//! Code that uses `Weak<T>` purely to break ownership cycles (the
//! workspace's only use case) compiles and runs under loom unchanged.
//! Tests that specifically want to model-check the strong/weak race
//! must either avoid the facade's `Weak` or extend this shim.

// Wrapping below panics on poison. clippy::panic is denied at the
// crate root; allow it locally for the cold poisoned() helper.
#![allow(clippy::panic)]

use core::borrow::Borrow;
use core::fmt;
use core::ops::{Deref, DerefMut};
use loom::sync as inner;

pub use loom::sync::{Barrier, Condvar, WaitTimeoutResult, atomic, mpsc};
pub use std::sync::{
    BarrierWaitResult, LockResult, Once, OnceLock, OnceState, PoisonError, TryLockError,
    TryLockResult,
};

#[inline(never)]
#[cold]
fn poisoned() -> ! {
    panic!(
        "concurrency::sync lock was poisoned: a previous holder panicked while \
         holding the lock; propagating the failure"
    );
}

// =============================== Mutex ====================================

pub struct Mutex<T: ?Sized>(inner::Mutex<T>);

#[must_use = "if unused the Mutex will immediately unlock"]
pub struct MutexGuard<'a, T: ?Sized + 'a>(inner::MutexGuard<'a, T>);

impl<T> Mutex<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self(inner::Mutex::new(value))
    }

    #[inline]
    pub fn into_inner(self) -> T {
        match self.0.into_inner() {
            Ok(v) => v,
            Err(_) => poisoned(),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    #[inline]
    pub fn lock(&self) -> MutexGuard<'_, T> {
        match self.0.lock() {
            Ok(g) => MutexGuard(g),
            Err(_) => poisoned(),
        }
    }

    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        match self.0.try_lock() {
            Ok(g) => Some(MutexGuard(g)),
            Err(TryLockError::Poisoned(_)) => poisoned(),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        match self.0.get_mut() {
            Ok(v) => v,
            Err(_) => poisoned(),
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mutex").finish_non_exhaustive()
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> From<T> for Mutex<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized + fmt::Display> fmt::Display for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

// =============================== RwLock ===================================

/// Reader-writer lock with a `parking_lot`-shaped surface.
///
/// `T: Sized` because `loom::sync::RwLock` does not implement `Deref`
/// on its guards for `?Sized` payloads; the facade adopts the lowest
/// common denominator so call sites compile identically across all
/// backends.
pub struct RwLock<T>(inner::RwLock<T>);

#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockReadGuard<'a, T: 'a>(inner::RwLockReadGuard<'a, T>);

#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockWriteGuard<'a, T: 'a>(inner::RwLockWriteGuard<'a, T>);

/// Upgradable-read guard for [`RwLock`].
///
/// Implemented as an exclusive write guard; loom has no native
/// upgradable read.
#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockUpgradableReadGuard<'a, T: 'a>(inner::RwLockWriteGuard<'a, T>);

impl<T> RwLock<T> {
    #[inline]
    pub fn new(value: T) -> Self {
        Self(inner::RwLock::new(value))
    }

    #[inline]
    pub fn into_inner(self) -> T {
        match self.0.into_inner() {
            Ok(v) => v,
            Err(_) => poisoned(),
        }
    }

    #[inline]
    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        match self.0.read() {
            Ok(g) => RwLockReadGuard(g),
            Err(_) => poisoned(),
        }
    }

    #[inline]
    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        match self.0.write() {
            Ok(g) => RwLockWriteGuard(g),
            Err(_) => poisoned(),
        }
    }

    #[inline]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        match self.0.try_read() {
            Ok(g) => Some(RwLockReadGuard(g)),
            Err(TryLockError::Poisoned(_)) => poisoned(),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    #[inline]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        match self.0.try_write() {
            Ok(g) => Some(RwLockWriteGuard(g)),
            Err(TryLockError::Poisoned(_)) => poisoned(),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// Acquire an upgradable read guard.
    ///
    /// Loom has no native upgradable-read; this is an exclusive
    /// `write()`. Sound but loses the many-readers-plus-one-upgradable
    /// schedule that `parking_lot` permits.
    #[inline]
    pub fn upgradable_read(&self) -> RwLockUpgradableReadGuard<'_, T> {
        match self.0.write() {
            Ok(g) => RwLockUpgradableReadGuard(g),
            Err(_) => poisoned(),
        }
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        match self.0.get_mut() {
            Ok(v) => v,
            Err(_) => poisoned(),
        }
    }
}

impl<'a, T: 'a> RwLockUpgradableReadGuard<'a, T> {
    #[inline]
    pub fn upgrade(s: Self) -> RwLockWriteGuard<'a, T> {
        RwLockWriteGuard(s.0)
    }

    /// # Errors
    ///
    /// Never returns `Err`; the `Result` shape matches `parking_lot`.
    #[inline]
    pub fn try_upgrade(s: Self) -> Result<RwLockWriteGuard<'a, T>, Self> {
        Ok(RwLockWriteGuard(s.0))
    }
}

impl<T: fmt::Debug> fmt::Debug for RwLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RwLock").finish_non_exhaustive()
    }
}

impl<T: Default> Default for RwLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> From<T> for RwLock<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

macro_rules! impl_rwlock_guard_traits {
    ($guard:ident, $mutability:ident) => {
        impl<T> Deref for $guard<'_, T> {
            type Target = T;
            #[inline]
            fn deref(&self) -> &T {
                &*self.0
            }
        }

        impl<T: fmt::Debug> fmt::Debug for $guard<'_, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&**self, f)
            }
        }

        impl<T: fmt::Display> fmt::Display for $guard<'_, T> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&**self, f)
            }
        }

        impl_rwlock_guard_traits!(@mut $guard, $mutability);
    };
    (@mut $guard:ident, mut) => {
        impl<T> DerefMut for $guard<'_, T> {
            #[inline]
            fn deref_mut(&mut self) -> &mut T {
                &mut *self.0
            }
        }
    };
    (@mut $guard:ident, immut) => {};
}

impl_rwlock_guard_traits!(RwLockReadGuard, immut);
impl_rwlock_guard_traits!(RwLockWriteGuard, mut);
impl_rwlock_guard_traits!(RwLockUpgradableReadGuard, immut);

// ============================== Arc / Weak ================================

/// `Arc` wrapper used under the loom backend.
///
/// Thin wrapper around `loom::sync::Arc<T>` that adds the associated
/// `Arc::downgrade` function (loom does not provide one) and otherwise
/// forwards every method to the wrapped type.
#[derive(Debug)]
#[repr(transparent)]
pub struct Arc<T: ?Sized>(inner::Arc<T>);

impl<T> Arc<T> {
    pub fn new(value: T) -> Self {
        Self(inner::Arc::new(value))
    }

    /// Construct an `Arc<MaybeUninit<T>>`. See `std::sync::Arc::new_uninit`.
    ///
    /// Loom 0.7 does not provide `new_uninit` directly; build it on
    /// top of `Arc::new(MaybeUninit::uninit())`. Same behavior as std:
    /// the returned `Arc` points at uninitialized memory and must be
    /// written into before [`Arc::assume_init`] is called.
    #[must_use]
    pub fn new_uninit() -> Arc<core::mem::MaybeUninit<T>> {
        Arc(inner::Arc::new(core::mem::MaybeUninit::uninit()))
    }

    /// # Errors
    ///
    /// Returns `Err(self)` if there is more than one strong reference.
    pub fn try_unwrap(this: Self) -> Result<T, Self> {
        inner::Arc::try_unwrap(this.0).map_err(Self)
    }
}

impl<T> Arc<core::mem::MaybeUninit<T>> {
    /// # Safety
    ///
    /// Caller must guarantee the inner `MaybeUninit<T>` has been
    /// initialized. See `std::sync::Arc::assume_init`.
    #[must_use]
    #[allow(unsafe_code)]
    pub unsafe fn assume_init(self) -> Arc<T> {
        // SAFETY: per the function's contract, the inner value is
        // initialized. `MaybeUninit<T>` and `T` have the same layout,
        // so a raw-pointer-cast through `into_raw`/`from_raw` is sound.
        unsafe {
            let raw = inner::Arc::into_raw(self.0).cast::<T>();
            Arc(inner::Arc::from_raw(raw))
        }
    }
}

impl<T: ?Sized> Arc<T> {
    #[must_use]
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        inner::Arc::ptr_eq(&this.0, &other.0)
    }

    /// See `std::sync::Arc::strong_count`. Note: under this loom shim
    /// the count includes live `Weak`s as well as live `Arc`s.
    #[must_use]
    pub fn strong_count(this: &Self) -> usize {
        inner::Arc::strong_count(&this.0)
    }

    /// See `std::sync::Arc::weak_count`. **Not implemented under the
    /// loom shim.** The shim's `Weak<T>` holds a *strong* clone of
    /// the inner `loom::sync::Arc<T>`, so there is no separate weak
    /// count to report -- and silently returning `0` here would let
    /// assertions like `assert_eq!(Arc::weak_count(&a), 0)` pass for
    /// the wrong reason on every backend (true on loom because of
    /// the shim, true on std because the weaks have actually
    /// dropped). Panicking on the call surfaces the gap loudly so
    /// the test author can either cfg the assertion out of loom or
    /// rework the check to not depend on `weak_count`.
    ///
    /// # Panics
    ///
    /// Always panics under loom.
    #[must_use]
    #[allow(clippy::unused_self, clippy::needless_pass_by_value, clippy::panic)]
    pub fn weak_count(_this: &Self) -> usize {
        panic!(
            "Arc::weak_count is not implemented under loom: the shim's \
             `Weak<T>` is a strong clone, so there is no separate weak \
             count to report. Cfg the call out of loom or rework the \
             check."
        )
    }

    pub fn get_mut(this: &mut Self) -> Option<&mut T> {
        inner::Arc::get_mut(&mut this.0)
    }

    #[must_use]
    pub fn as_ptr(this: &Self) -> *const T {
        inner::Arc::as_ptr(&this.0)
    }

    /// Construct a `Weak<T>` from this `Arc<T>`. Loom's `Arc` has no
    /// downgrade of its own; see the module-level note on Weak
    /// semantics under loom.
    #[must_use]
    pub fn downgrade(this: &Self) -> Weak<T> {
        Weak {
            inner: Some(this.0.clone()),
        }
    }
}

impl<T: ?Sized> Clone for Arc<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: ?Sized> Deref for Arc<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> AsRef<T> for Arc<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: ?Sized> Borrow<T> for Arc<T> {
    fn borrow(&self) -> &T {
        &self.0
    }
}

// `std::sync::Arc<T>` forwards equality / ordering / hashing to the
// pointee. `parking_lot`'s re-export inherits the same. Without these
// impls on the loom shim, a workspace call site that puts an `Arc<T>`
// in a `HashMap` or `BTreeMap` compiles on every other backend and
// fails to compile under `--features loom`. Forward to the inner
// value so the shim has the same surface.
impl<T: ?Sized + PartialEq> PartialEq for Arc<T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<T: ?Sized + Eq> Eq for Arc<T> {}

impl<T: ?Sized + PartialOrd> PartialOrd for Arc<T> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        (**self).partial_cmp(&**other)
    }
}

impl<T: ?Sized + Ord> Ord for Arc<T> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (**self).cmp(&**other)
    }
}

impl<T: ?Sized + core::hash::Hash> core::hash::Hash for Arc<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        (**self).hash(state);
    }
}

impl<T: Default> Default for Arc<T> {
    fn default() -> Self {
        Self(inner::Arc::default())
    }
}

impl<T> From<T> for Arc<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: ?Sized + fmt::Display> fmt::Display for Arc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl<T: ?Sized> fmt::Pointer for Arc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&inner::Arc::as_ptr(&self.0), f)
    }
}

/// `Weak<T>` shim for the loom backend.
///
/// Loom 0.7 does not ship a `Weak` type. This stand-in holds a strong
/// `loom::sync::Arc<T>` clone internally; see the module-level note
/// for the semantic limitations that implies.
#[derive(Debug)]
pub struct Weak<T: ?Sized> {
    inner: Option<inner::Arc<T>>,
}

impl<T> Weak<T> {
    /// Construct a `Weak<T>` that always upgrades to `None`. Matches
    /// `std::sync::Weak::new`.
    #[must_use]
    pub fn new() -> Self {
        Self { inner: None }
    }
}

impl<T: ?Sized> Weak<T> {
    /// Try to obtain a strong `Arc<T>` from this `Weak<T>`.
    ///
    /// Returns `None` for a `Weak` that has never been associated with
    /// an `Arc` (i.e. `Weak::new()`); under this loom shim, otherwise
    /// always returns `Some` because the `Weak` keeps a strong clone
    /// alive.
    #[must_use]
    pub fn upgrade(&self) -> Option<Arc<T>> {
        self.inner.as_ref().map(|a| Arc(a.clone()))
    }
}

impl<T> Weak<T> {
    /// Consume the `Weak`, returning a raw pointer to the contained
    /// value.
    ///
    /// See `std::sync::Weak::into_raw`. **Divergence from std:** for an
    /// empty `Weak` (one created via `Weak::new()`), this returns a
    /// **null** pointer.  Real `std::sync::Weak` uses a non-null
    /// sentinel that callers can pattern-match on (e.g. to
    /// distinguish "empty Weak" from "Weak whose target lives at
    /// pointer X"). The workspace's existing `into_raw`/`from_raw`
    /// callers always round-trip through a non-empty `Weak`, so the
    /// difference does not matter in practice -- but a future caller
    /// that depends on the std sentinel will see different behaviour
    /// under loom.
    #[must_use]
    pub fn into_raw(self) -> *const T {
        match self.inner {
            Some(arc) => inner::Arc::into_raw(arc),
            None => core::ptr::null(),
        }
    }

    /// # Safety
    ///
    /// The pointer must have come from `Weak::into_raw` on a `Weak<U>`
    /// whose `U` has the same size and alignment as `T`. See
    /// `std::sync::Weak::from_raw` for the full contract.
    ///
    /// Note the empty-`Weak` divergence documented on [`Weak::into_raw`]:
    /// under this shim, a null pointer round-trips through `from_raw`
    /// to a fresh empty `Weak`, whereas real `std::sync::Weak::from_raw`
    /// expects the std non-null sentinel for the empty case. Code that
    /// uses the std sentinel as a "this Weak is empty" signal will
    /// behave differently under loom.
    #[allow(unsafe_code)]
    pub unsafe fn from_raw(ptr: *const T) -> Self {
        if ptr.is_null() {
            Self { inner: None }
        } else {
            // SAFETY: per the contract, `ptr` came from
            // `inner::Arc::into_raw` and the allocation is still live.
            Self {
                inner: Some(unsafe { inner::Arc::from_raw(ptr) }),
            }
        }
    }
}

impl<T: ?Sized> Clone for Weak<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T> Default for Weak<T> {
    fn default() -> Self {
        Self::new()
    }
}
