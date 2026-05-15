// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Test-backend facade for `loom` and `shuttle`.
//!
//! Both crates expose `std::sync`-shaped primitives that return
//! `LockResult<Guard>`. This workspace treats a crashed thread as a crashed
//! process: poison means a previous lock-holder panicked, and the only
//! correct response is to propagate that failure to whoever tries to lock
//! next. The facade therefore panics on poison rather than silently
//! handing back the (possibly torn) inner value. Under loom and shuttle,
//! that panic is observed by the model-checker / scheduler and reported
//! as a test failure, which is exactly what we want.
//!
//! With poison off the table, `lock` / `read` / `write` return guards
//! directly -- no `LockResult`, no `.unwrap()` -- matching the
//! `parking_lot` surface presented by the default backend.
//!
//! ## Caveats
//!
//! * `new` is **not** `const fn`: `loom::sync::Mutex::new` is plain `fn`
//!   because each instance registers with the loom executor. `shuttle`'s
//!   `new` is `const fn`, but the facade has to expose the lowest common
//!   denominator. If you need `static FOO: Mutex<T> = Mutex::new(...)`, use
//!   the default (release) backend or wrap the static in `OnceLock` for
//!   loom/shuttle.
//! * `RwLock::upgradable_read` is implemented in terms of an exclusive
//!   write lock under loom/shuttle. This is conservatively correct (no
//!   interleaving allowed by parking_lot is forbidden here) but it loses
//!   the "many readers + one upgradable reader" schedule that parking_lot
//!   permits. If you specifically need to model-check that interleaving,
//!   either use a plain `RwLock<T>` with explicit `read` then `write`, or
//!   extend this facade with a richer state machine.

// The whole point of the helpers below is to panic when the underlying
// primitive returns a poisoned lock. clippy::panic is denied at the crate
// root to catch incidental panics; the calls here are intentional and
// scoped to a single cold function, so allow it locally.
#![allow(clippy::panic)]

#[cfg(concurrency = "loom")]
use loom::sync as inner;
#[cfg(concurrency = "shuttle")]
use shuttle::sync as inner;

#[cfg(concurrency = "loom")]
pub use loom::sync::{Arc, Barrier, Condvar, WaitTimeoutResult, atomic, mpsc};

#[cfg(concurrency = "shuttle")]
pub use shuttle::sync::{
    Arc, Barrier, BarrierWaitResult, Condvar, LockResult, Once, OnceState, PoisonError,
    TryLockError, TryLockResult, WaitTimeoutResult, Weak, atomic, mpsc,
};

use core::fmt;
use core::ops::{Deref, DerefMut};

// Loom returns `std::sync::TryLockResult` but doesn't re-export
// `TryLockError`; shuttle does. Pull it in directly for loom; for shuttle
// the public re-export below already brings it into scope.
#[cfg(concurrency = "loom")]
use std::sync::TryLockError;

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
/// Returns guards directly (no `LockResult`); poison is treated as a fatal
/// invariant violation and panics. See module docs for rationale.
pub struct Mutex<T: ?Sized>(inner::Mutex<T>);

/// RAII guard for [`Mutex`].
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
        &*self.0
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut *self.0
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
/// `T: Sized` because `loom::sync::RwLock` does not implement `Deref` on its
/// guards for `?Sized` payloads; the facade adopts the lowest common
/// denominator so call sites compile identically across all three backends.
pub struct RwLock<T>(inner::RwLock<T>);

/// Shared-reference guard for [`RwLock`].
#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockReadGuard<'a, T: 'a>(inner::RwLockReadGuard<'a, T>);

/// Exclusive-reference guard for [`RwLock`].
#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockWriteGuard<'a, T: 'a>(inner::RwLockWriteGuard<'a, T>);

/// Upgradable-read guard for [`RwLock`].
///
/// Under loom/shuttle this is implemented as an exclusive write guard; see
/// the module-level caveat.
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

    /// See module-level caveat: this takes an exclusive write internally.
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

    /// Always succeeds under loom/shuttle.
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
// Upgradable holds a write lock internally, but parking_lot's upgradable
// guard only exposes `Deref`, not `DerefMut`. Mirror that so call-site
// behavior matches across backends.
impl_rwlock_guard_traits!(RwLockUpgradableReadGuard, immut);
