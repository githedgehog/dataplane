// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shuttle backend: poison-as-panic wrapper around `shuttle::sync`.
//!
//! `shuttle::sync::{Mutex, RwLock}` return `LockResult<Guard>` because
//! they mirror `std::sync`'s shape. This workspace treats poison as a
//! fatal invariant violation; the wrapper below strips `LockResult`
//! and panics, presenting the same naked-guard surface as the default
//! production backend.
//!
//! `OnceLock` is taken from `std::sync` (shuttle doesn't ship one);
//! it's pure-std machinery so it doesn't need model-checker
//! integration.

// Wrapping below panics on poison. clippy::panic is denied at the
// crate root; allow it locally for the cold poisoned() helper.
#![allow(clippy::panic)]

use core::fmt;
use core::ops::{Deref, DerefMut};
use shuttle::sync as inner;

pub use shuttle::sync::{
    Arc, Barrier, BarrierWaitResult, Condvar, LockResult, Once, OnceState, PoisonError,
    TryLockError, TryLockResult, WaitTimeoutResult, Weak, atomic, mpsc,
};
pub use std::sync::OnceLock;

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

pub struct RwLock<T>(inner::RwLock<T>);

#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockReadGuard<'a, T: 'a>(inner::RwLockReadGuard<'a, T>);

#[must_use = "if unused the RwLock will immediately unlock"]
pub struct RwLockWriteGuard<'a, T: 'a>(inner::RwLockWriteGuard<'a, T>);

/// Upgradable-read guard for [`RwLock`].
///
/// Implemented as an exclusive write guard; shuttle has no native
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
    /// Shuttle has no native upgradable-read; this is an exclusive
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
