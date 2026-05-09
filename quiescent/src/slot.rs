// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Single-slot atomic publication.
//!
//! In production this is `arc_swap::ArcSwap` -- lock-free read fast path,
//! which is what makes [`Subscriber::snapshot`] cheap on the data-plane.
//!
//! When the `loom` or `shuttle` feature is enabled (via the
//! `concurrency` crate) it falls back to `Mutex<Arc<T>>` because neither
//! model checker sees `arc_swap`'s internals (hazard pointers + lower-
//! level atomics).  The two implementations are observably equivalent
//! for the QSBR protocol -- atomic publish, atomic load -- which is all
//! the model checker needs to see.
//!
//! [`Subscriber::snapshot`]: crate::Subscriber::snapshot

// Strict provenance checks fail with arc-swap since it uses hazard pointers and does not (yet) use the new
// std features to expose provenance information in their mechanics.
// As a result, we can still check for provenance violations in this crate, but only with the Mutex based
// fallback implementation.
cfg_select! {
    any(feature = "loom", feature = "shuttle", feature = "_strict_provenance") => {
        use concurrency::sync::{Arc, Mutex};

        pub(crate) struct Slot<T>(Mutex<Arc<T>>);

        impl<T> Slot<T> {
            pub(crate) fn from_pointee(value: T) -> Self {
                Self(Mutex::new(Arc::new(value)))
            }

            pub(crate) fn load_full(&self) -> Arc<T> {
                #[allow(clippy::expect_used)] // poisoned only in unrecoverable cases
                Arc::clone(&self.0.lock().expect("slot mutex poisoned"))
            }

            pub(crate) fn swap(&self, new: Arc<T>) -> Arc<T> {
                #[allow(clippy::expect_used)]
                let mut guard = self.0.lock().expect("slot mutex poisoned");
                core::mem::replace(&mut *guard, new)
            }
        }
    }
    _ => {
        use concurrency::sync::Arc;
        use arc_swap::ArcSwap;

        pub(crate) struct Slot<T>(ArcSwap<T>);

        impl<T> Slot<T> {
            #[inline]
            pub(crate) fn from_pointee(value: T) -> Self {
                Self(ArcSwap::from_pointee(value))
            }

            #[inline]
            pub(crate) fn load_full(&self) -> Arc<T> {
                self.0.load_full()
            }

            #[inline]
            pub(crate) fn swap(&self, new: Arc<T>) -> Arc<T> {
                self.0.swap(new)
            }
        }
    }
}
