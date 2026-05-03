//! Single-slot atomic publication.
//!
//! In production this is `arc_swap::ArcSwap` — lock-free read fast path,
//! which is what makes [`Reader::snapshot`] cheap on the data-plane.
//!
//! When the `loom` or `shuttle` feature is enabled (via the
//! `concurrency` crate) it falls back to `Mutex<Arc<T>>` because neither
//! model checker sees `arc_swap`'s internals (hazard pointers + lower-
//! level atomics).  The two implementations are observably equivalent
//! for the QSBR protocol — atomic publish, atomic load — which is all
//! the model checker needs to see.
//!
//! [`Reader::snapshot`]: crate::Reader::snapshot

use concurrency::sync::Arc;

#[cfg(not(any(feature = "loom", feature = "shuttle")))]
mod imp {
    use super::Arc;
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

#[cfg(any(feature = "loom", feature = "shuttle"))]
mod imp {
    use super::Arc;
    use concurrency::sync::Mutex;

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

pub(crate) use imp::Slot;
