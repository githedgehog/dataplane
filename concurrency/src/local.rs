// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Thread-affine ownership.
//!
//! [`Local<T>`] wraps a value so that the value itself cannot be moved to another thread, and
//! records which thread that is.
//!
//! # What this guarantees, exactly
//!
//! `Local<T>` is `!Send` and `!Sync`, so **the wrapped value cannot be moved to another thread,
//! and the wrapper cannot be shared with one**. That is the whole guarantee. In particular it is
//! *not* a guarantee that `T` is only ever *used* on one thread, because the accessors hand out
//! `&T` and `&mut T`, whose thread-transferability is decided by `T` rather than by the wrapper:
//!
//! | `T` | `&T` crosses threads? | `&mut T` crosses threads? |
//! |-----|-----------------------|---------------------------|
//! | `Send + Sync` | yes (`&T: Send` when `T: Sync`) | yes (`&mut T: Send` when `T: Send`) |
//! | `!Sync` | no | yes, if `T: Send` |
//!
//! So for a `Send + Sync` payload, a caller can take `as_mut()` and hand the resulting `&mut T` to
//! a scoped thread. `Local` prevents the *accidental* move of the whole value and records the
//! intent in the type, but it is not a proof of single-threaded use for such a `T`.
//!
//! **Where it is a proof:** when `T` is itself `!Sync`, `&T` cannot cross a thread boundary, so a
//! `T` whose useful methods all take `&self` is genuinely pinned. [`quiescent::Publisher`] is
//! exactly this shape -- it is `!Sync`, and `publish`/`reclaim` take `&self` -- which is the case
//! this type was built for.
//!
//! Closing the gap for `Send + Sync` payloads would need a negative bound (`impl<T: !Sync>`),
//! which Rust does not have. Rather than imply a guarantee it cannot deliver, this module states
//! the boundary and leaves it to the caller to pick a `T` that lands on the right side of it.
//!
//! # Why a [`ThreadId`] and not a domain-specific core id
//!
//! An earlier version of this stored DPDK's `LCoreId`. That was worse in three ways. It forced a
//! fallible constructor, because DPDK reports `LCORE_ID_ANY` for any thread that is not an EAL
//! thread and has not registered itself -- so the wrapper could not be built on an ordinary
//! thread at all. It did not survive model checking, since an lcore id means nothing under loom
//! or shuttle. And it was the *less* useful identifier: a backtrace, a panic message, or a
//! debugger reports Rust thread identity, so an lcore id has to be correlated through a mapping
//! nobody maintains.
//!
//! For registered threads the two are in bijection anyway, and the one DPDK constraint that named
//! the main lcore specifically -- `rte_eal_init` "is to be executed on the MAIN lcore only" --
//! needs no wrapper, because the thread that calls it *becomes* the main lcore. `rte_eal_cleanup`
//! states no thread requirement at all.
//!
//! [`quiescent::Publisher`]: crate::quiescent::Publisher

use core::fmt::{Debug, Formatter};
use core::marker::PhantomData;

use crate::thread::{self, ThreadId};

/// A value pinned to the thread that created it.
///
/// See the [module documentation](self) for the precise guarantee -- in particular, that this
/// pins *ownership* rather than *use*.
///
/// The wrapper records the [`ThreadId`] it was built on, so that a value can say which thread it
/// belongs to when something goes wrong. That identity is a diagnostic, not a check: since a
/// `Local<T>` can neither move to another thread nor be shared with one, the calling thread at
/// any access is *necessarily* the one that constructed it.
///
/// There is deliberately no way to unwrap a `Local<T>` back into a bare `T`: an un-pinning
/// operation would make the pin advisory, and no current caller needs one. Access the value with
/// [`AsRef`]/[`AsMut`], and let [`Drop`] handle teardown.
///
/// The guarantee, as a compile error -- the value cannot be moved to another thread:
///
/// ```compile_fail,E0277
/// # use dataplane_concurrency::local::Local;
/// let local = Local::new(0u64);
/// std::thread::scope(|s| {
///     s.spawn(move || { let _ = local.as_ref(); });
/// });
/// ```
///
/// Nor can the wrapper be shared with one:
///
/// ```compile_fail,E0277
/// # use dataplane_concurrency::local::Local;
/// let local = Local::new(0u64);
/// let borrowed = &local;
/// std::thread::scope(|s| {
///     s.spawn(move || { let _ = borrowed.as_ref(); });
/// });
/// ```
pub struct Local<T> {
    inner: T,
    /// The thread this value was pinned to. Diagnostics only -- see the type docs.
    owner: ThreadId,
    /// `*const ()` is neither `Send` nor `Sync`, which is what removes both from `Local<T>`.
    ///
    /// If you ever need `!Send` while *keeping* `Sync`, the marker is
    /// `PhantomData<std::sync::MutexGuard<'static, ()>>` -- `MutexGuard` is `!Send + Sync`. That
    /// is not what is wanted here: losing `Sync` on the wrapper only forces an explicit
    /// `as_ref()` before sharing the inner value, which is the right amount of friction.
    _pin: PhantomData<*const ()>,
}

impl<T> Local<T> {
    /// Pin `inner` to the calling thread.
    ///
    /// Infallible: every thread has a [`ThreadId`], so there is no "this thread has no identity"
    /// case to report.
    #[must_use]
    pub fn new(inner: T) -> Local<T> {
        Local {
            inner,
            owner: thread::current().id(),
            _pin: PhantomData,
        }
    }

    /// The thread this value is pinned to.
    ///
    /// Intended for diagnostics -- naming the owner of a resource in a log line or a stuck-worker
    /// report. It cannot be used to detect misuse, because misuse is already unrepresentable.
    #[must_use]
    pub fn owner(&self) -> ThreadId {
        self.owner
    }
}

impl<T> AsRef<T> for Local<T> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<T> AsMut<T> for Local<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: Debug> Debug for Local<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Local")
            .field("inner", &self.inner)
            .field("owner", &self.owner)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guarantee that does hold: the wrapped value cannot be moved to another thread.
    ///
    /// This is a compile-time property, so the test that matters is the `compile_fail` doctest on
    /// the negative side; here we only pin down that the positive case works and that the
    /// accessors round-trip.
    #[test]
    fn accessors_round_trip() {
        let mut local = Local::new(41u64);
        assert_eq!(*local.as_ref(), 41);
        *local.as_mut() += 1;
        assert_eq!(*local.as_ref(), 42);
    }

    #[test]
    fn debug_shows_inner_and_owner() {
        let local = Local::new(7u8);
        let rendered = format!("{local:?}");
        assert!(rendered.contains("inner: 7"), "got {rendered}");
        assert!(rendered.contains("owner:"), "got {rendered}");
    }

    #[test]
    fn owner_is_the_constructing_thread() {
        let local = Local::new(0u8);
        assert_eq!(local.owner(), thread::current().id());
    }

    /// A `Local` built on another thread records *that* thread, not this one.
    #[test]
    fn owner_distinguishes_threads() {
        let here = thread::current().id();
        // `Local` is `!Send`, so only the recorded id comes back across the join.
        let there = std::thread::spawn(|| Local::new(0u8).owner())
            .join()
            .expect("thread panicked");
        assert_ne!(here, there);
    }

    /// `Local<T>` is neither `Send` nor `Sync`, whatever `T` is.
    #[test]
    fn is_neither_send_nor_sync() {
        static_assertions::assert_not_impl_any!(Local<u64>: Send, Sync);
        // Even for a payload that is itself both.
        static_assertions::assert_impl_all!(u64: Send, Sync);
    }
}
