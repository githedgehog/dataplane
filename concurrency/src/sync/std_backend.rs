// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Default backend: poison-as-panic wrapper around `std::sync`.
//!
//! `std::sync::{Mutex, RwLock}` return `LockResult<Guard>` because they
//! poison on holder panic. This workspace treats poison as a fatal
//! invariant violation; the wrapper below strips `LockResult` and
//! panics, presenting a `parking_lot`-shaped naked-guard surface.
//!
//! One indirection on lock acquire/release (wrapper match + std poison
//! branch). Cold path only -- the fast path under contention is
//! unchanged.

// Wrapping below panics on poison. clippy::panic is denied at the
// crate root; allow it locally for the cold poisoned() helper.
#![allow(clippy::panic)]

use core::fmt;
use core::ops::{Deref, DerefMut};
use std::sync as inner;

pub use std::sync::{
    Arc, Barrier, BarrierWaitResult, Condvar, LockResult, Once, OnceLock, OnceState, PoisonError,
    TryLockError, TryLockResult, WaitTimeoutResult, Weak, atomic, mpsc,
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

/// Mutual exclusion primitive with a `parking_lot`-shaped surface.
///
/// Returns guards directly (no `LockResult`); poison is treated as a
/// fatal invariant violation and panics. See module docs for rationale.
pub struct Mutex<T: ?Sized>(inner::Mutex<T>);

/// RAII guard for [`Mutex`].
#[must_use = "if unused the Mutex will immediately unlock"]
pub struct MutexGuard<'a, T: ?Sized + 'a>(inner::MutexGuard<'a, T>);

impl<T> Mutex<T> {
    #[inline]
    pub const fn new(value: T) -> Self {
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
/// `T: Sized` for parity with future model-checker backends, which
/// adopt the lowest common denominator across their inner types.
pub struct RwLock<T>(inner::RwLock<T>);

/// Shared-reference guard for [`RwLock`].
#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockReadGuard<'a, T: 'a>(inner::RwLockReadGuard<'a, T>);

/// Exclusive-reference guard for [`RwLock`].
#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockWriteGuard<'a, T: 'a>(inner::RwLockWriteGuard<'a, T>);

/// Upgradable-read guard for [`RwLock`].
///
/// std `RwLock` has no native upgradable-read state machine; this is
/// an exclusive write guard with a `parking_lot`-shaped `upgrade()` API.
#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockUpgradableReadGuard<'a, T: 'a>(inner::RwLockWriteGuard<'a, T>);

impl<T> RwLock<T> {
    #[inline]
    pub const fn new(value: T) -> Self {
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
    /// std `RwLock` has no native upgradable-read; this is implemented
    /// as an exclusive `write()`. Subsequent backends (parking_lot)
    /// will replace this with a true upgradable read; meanwhile the
    /// surface is consistent across backends, sound in all cases, and
    /// merely loses the many-readers-plus-one-upgradable schedule that
    /// `parking_lot` permits.
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
    /// Upgrade to a write guard. Free here because we already hold the
    /// underlying write lock.
    #[inline]
    pub fn upgrade(s: Self) -> RwLockWriteGuard<'a, T> {
        RwLockWriteGuard(s.0)
    }

    /// Always succeeds under the std backend.
    ///
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
