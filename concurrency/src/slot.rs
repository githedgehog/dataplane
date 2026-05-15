// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Single-slot atomic publication.
//!
//! In production these are `arc_swap::ArcSwap` / `ArcSwapOption` --
//! lock-free read fast path, which is what makes
//! [`Subscriber::snapshot`] cheap on the data-plane.
//!
//! When the `loom` or `shuttle` feature is enabled (via the
//! `concurrency` crate) they fall back to `Mutex<Arc<T>>` /
//! `Mutex<Option<Arc<T>>>` because neither model checker sees
//! `arc_swap`'s internals (hazard pointers + lower-level atomics).
//! The two implementations are observably equivalent for the QSBR
//! protocol -- atomic publish, atomic load -- which is all the model
//! checker needs to see.
//!
//! [`Subscriber::snapshot`]: crate::Subscriber::snapshot

// Strict provenance checks fail with arc-swap since it uses hazard pointers and does not (yet) use the new
// std features to expose provenance information in their mechanics.
// As a result, we can still check for provenance violations in this crate, but only with the Mutex based
// fallback implementation.
cfg_select! {
    any(feature = "loom", feature = "shuttle", feature = "_strict_provenance") => {
        use crate::sync::{Arc, Mutex};

        pub struct Slot<T>(Mutex<Arc<T>>);

        impl<T> Slot<T> {
            pub fn from_pointee(value: T) -> Self {
                Self(Mutex::new(Arc::new(value)))
            }

            #[must_use]
            pub fn new(value: Arc<T>) -> Self {
                Self(Mutex::new(value))
            }

            pub fn load_full(&self) -> Arc<T> {
                #[allow(clippy::expect_used)] // poisoned only in unrecoverable cases
                let guard = self.0.lock().expect("slot mutex poisoned");
                Arc::clone(&*guard)
            }

            pub fn swap(&self, new: Arc<T>) -> Arc<T> {
                #[allow(clippy::expect_used)]
                let mut guard = self.0.lock().expect("slot mutex poisoned");
                core::mem::replace(&mut *guard, new)
            }

            pub fn store(&self, new: Arc<T>) {
                #[allow(clippy::expect_used)]
                let mut guard = self.0.lock().expect("slot mutex poisoned");
                *guard = new;
            }
        }

        /// Single-slot atomic publication of an optional value.
        ///
        /// Fallback implementation backed by `Mutex<Option<Arc<T>>>`.
        pub struct SlotOption<T>(Mutex<Option<Arc<T>>>);

        impl<T> SlotOption<T> {
            #[must_use]
            pub fn empty() -> Self {
                Self(Mutex::new(None))
            }

            pub fn from_pointee<V: Into<Option<T>>>(value: V) -> Self {
                Self(Mutex::new(value.into().map(Arc::new)))
            }

            #[must_use]
            pub fn new(value: Option<Arc<T>>) -> Self {
                Self(Mutex::new(value))
            }

            pub fn load_full(&self) -> Option<Arc<T>> {
                #[allow(clippy::expect_used)]
                let guard = self.0.lock().expect("slot mutex poisoned");
                guard.as_ref().map(Arc::clone)
            }

            pub fn swap(&self, new: Option<Arc<T>>) -> Option<Arc<T>> {
                #[allow(clippy::expect_used)]
                let mut guard = self.0.lock().expect("slot mutex poisoned");
                core::mem::replace(&mut *guard, new)
            }

            pub fn store(&self, new: Option<Arc<T>>) {
                #[allow(clippy::expect_used)]
                let mut guard = self.0.lock().expect("slot mutex poisoned");
                *guard = new;
            }
        }

        impl<T> Default for SlotOption<T> {
            fn default() -> Self {
                Self::empty()
            }
        }
    }
    _ => {
        use crate::sync::Arc;
        use arc_swap::{ArcSwap, ArcSwapOption};

        #[repr(transparent)]
        pub struct Slot<T>(ArcSwap<T>);

        impl<T> Slot<T> {
            #[inline]
            pub fn from_pointee(value: T) -> Self {
                Self(ArcSwap::from_pointee(value))
            }

            #[inline]
            #[must_use]
            pub fn new(value: Arc<T>) -> Self {
                Self(ArcSwap::new(value))
            }

            #[inline]
            pub fn load_full(&self) -> Arc<T> {
                self.0.load_full()
            }

            #[inline]
            pub fn swap(&self, new: Arc<T>) -> Arc<T> {
                self.0.swap(new)
            }

            #[inline]
            pub fn store(&self, new: Arc<T>) {
                self.0.store(new);
            }
        }

        /// Single-slot atomic publication of an optional value.
        ///
        /// Wraps `arc_swap::ArcSwapOption` in production.
        #[repr(transparent)]
        pub struct SlotOption<T>(ArcSwapOption<T>);

        impl<T> SlotOption<T> {
            #[inline]
            #[must_use]
            pub fn empty() -> Self {
                Self(ArcSwapOption::new(None))
            }

            #[inline]
            pub fn from_pointee<V: Into<Option<T>>>(value: V) -> Self {
                Self(ArcSwapOption::from_pointee(value))
            }

            #[inline]
            #[must_use]
            pub fn new(value: Option<Arc<T>>) -> Self {
                Self(ArcSwapOption::new(value))
            }

            #[inline]
            pub fn load_full(&self) -> Option<Arc<T>> {
                self.0.load_full()
            }

            #[inline]
            pub fn swap(&self, new: Option<Arc<T>>) -> Option<Arc<T>> {
                self.0.swap(new)
            }

            #[inline]
            pub fn store(&self, new: Option<Arc<T>>) {
                self.0.store(new);
            }
        }

        impl<T> Default for SlotOption<T> {
            fn default() -> Self {
                Self::empty()
            }
        }
    }
}

use core::fmt;

impl<T> fmt::Debug for Slot<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slot").finish_non_exhaustive()
    }
}

impl<T> fmt::Debug for SlotOption<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlotOption").finish_non_exhaustive()
    }
}
