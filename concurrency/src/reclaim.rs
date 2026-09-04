// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Deferred release of resources that workers may still be touching.
//!
//! [`Reclaimer`] tracks a set of live resources and releases a retired one only once every worker
//! has passed a quiescent point since the retirement. It is a thin layer over
//! [`quiescent`](crate::quiescent), and inherits that module's central guarantee: **the
//! destructor runs on the owner's thread**, not on whichever worker happened to hold the last
//! reference.
//!
//! # What problem this solves
//!
//! Some resources cannot be released on their owner's schedule, because a worker may hold a
//! reference the owner cannot see -- a raw pointer on a worker's stack, an entry in a hardware
//! ring. A reference count answers "is anyone still holding a handle", which is not the same
//! question: the dangerous references are precisely the ones that are *not* handles. Quiescence
//! answers the right question, by establishing that every worker has been observed at a point
//! where it holds nothing.
//!
//! The corollary is a discipline, and it is the whole basis of the guarantee: **a worker must
//! hold no reference to a tracked resource at the moment it calls
//! [`at_safe_point`](Attendant::at_safe_point)**. Where that point goes is therefore a design
//! decision, not an implementation detail -- put it between units of work, after everything the
//! previous unit borrowed has been released.
//!
//! # How retirement works
//!
//! The live set *is* the published value. Retiring a resource publishes a set without it, which
//! leaves the previous set -- holding the last handle to the retired entry -- in the publisher's
//! retired list until every subscriber has advanced past it. Entries that are still live appear in
//! both sets, so only the removed one loses its last holder. No change to `quiescent` is needed
//! for any of this.
//!
//! # Shutdown
//!
//! [`drain_until`](Reclaimer::drain_until) retires everything and waits. It completes as soon as
//! the workers are gone, without any handshake: a [`Attendant`] removes itself from the domain when
//! dropped, so once every worker has exited there is nothing left to wait for. A worker that is
//! wedged and never drops its attendant is what the deadline is for -- and the right response is
//! to leak loudly rather than release memory a live worker may still be reading.

use core::cell::RefCell;
use std::time::Instant;

use crate::quiescent::{self, Publisher, Subscriber, SubscriberFactory};

/// Owns the live set and defers release until quiescence.
///
/// Single-threaded by construction: [`Publisher`] is `!Sync`, so a `Reclaimer` is too, and every
/// retirement, reclamation and destructor runs on the thread that created it. That is the point --
/// see the module documentation on drop affinity.
pub struct Reclaimer<T: Clone + Send + Sync + 'static> {
    publisher: Publisher<Vec<T>>,
    /// The owner's canonical copy of the live set, so a retirement can be computed without
    /// reading back the publication.
    live: RefCell<Vec<T>>,
}

/// Hands out [`Attendant`]s. `Copy + Send + Sync`, so it can be shared with every worker.
///
/// `Clone` is derived while `Copy` is written out: the derive would add a `T: Copy` bound, and the
/// resources tracked here are refcounted handles rather than `Copy` values. `T: Clone` is already
/// required, so the `Clone` half derives correctly -- unlike
/// [`SubscriberFactory`], whose bounds do not include `Clone` and which therefore has to write
/// both out by hand.
#[derive(Clone)]
pub struct Attendants<'r, T: Clone + Send + Sync + 'static> {
    inner: SubscriberFactory<'r, Vec<T>>,
}

impl<T: Clone + Send + Sync + 'static> Copy for Attendants<'_, T> {}

/// A worker's participation in the quiescence protocol.
///
/// One per worker, and per *logical* worker rather than per thread: an async task that can be
/// parked while holding a reference to a tracked resource is its own worker for this purpose, and
/// a per-thread attendant would let the thread report quiescence on behalf of a parked task that
/// is anything but.
pub struct Attendant<'r, T: Clone + Send + Sync + 'static> {
    inner: Subscriber<'r, Vec<T>>,
}

/// Returned by [`Reclaimer::drain_until`] when the deadline passed with resources still held.
///
/// `Display`/`Error` are written out rather than derived: `concurrency` is a foundational crate
/// and does not depend on `thiserror`, and one error type is not worth adding it for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StillHeld {
    /// How many retired publications were still pinned by some attendant.
    pub pending: usize,
}

impl core::fmt::Display for StillHeld {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{pending} retired resource set(s) still held at the deadline; leaking them",
            pending = self.pending
        )
    }
}

impl core::error::Error for StillHeld {}

impl<T: Clone + Send + Sync + 'static> Reclaimer<T> {
    /// Create a reclaimer with an empty live set, owned by the calling thread.
    #[must_use]
    pub fn new() -> Reclaimer<T> {
        Reclaimer {
            publisher: quiescent::channel(Vec::new()),
            live: RefCell::new(Vec::new()),
        }
    }

    /// Hand out a factory for worker [`Attendant`]s.
    #[must_use]
    pub fn attendants(&self) -> Attendants<'_, T> {
        Attendants {
            inner: self.publisher.factory(),
        }
    }

    /// Begin tracking `resource`.
    ///
    /// # Panics
    ///
    /// Panics if the live set is already borrowed, which the `!Sync` invariant makes unreachable.
    #[allow(clippy::expect_used)]
    pub fn register(&self, resource: T) {
        let mut live = self
            .live
            .try_borrow_mut()
            .expect("live set concurrently borrowed");
        live.push(resource);
        self.publisher.publish(live.clone());
    }

    /// Stop tracking every resource for which `keep` returns `false`, and defer their release.
    ///
    /// Returns the number retired. Nothing is released here; that happens in
    /// [`reclaim`](Self::reclaim) (which [`register`](Self::register) and this method also trigger
    /// opportunistically, via `publish`) once every attendant has passed a safe point.
    ///
    /// # Panics
    ///
    /// Panics if the live set is already borrowed, which the `!Sync` invariant makes unreachable.
    #[allow(clippy::expect_used)]
    pub fn retire_unless(&self, mut keep: impl FnMut(&T) -> bool) -> usize {
        let mut live = self
            .live
            .try_borrow_mut()
            .expect("live set concurrently borrowed");
        let before = live.len();
        live.retain(|entry| keep(entry));
        let retired = before - live.len();
        if retired > 0 {
            self.publisher.publish(live.clone());
        }
        retired
    }

    /// Release anything retired that no attendant can still be using.
    pub fn reclaim(&self) {
        self.publisher.reclaim();
    }

    /// How many retired publications are still pinned.
    ///
    /// Zero means everything retired so far has been released.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.publisher.pending_reclamation()
    }

    /// The number of resources still live.
    ///
    /// # Panics
    ///
    /// Panics if the live set is already borrowed, which the `!Sync` invariant makes unreachable.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn live(&self) -> usize {
        self.live
            .try_borrow()
            .expect("live set concurrently borrowed")
            .len()
    }

    /// Retire everything and wait until it has all been released, or `deadline` passes.
    ///
    /// # Errors
    ///
    /// Returns [`StillHeld`] if the deadline passes with resources still pinned by an attendant --
    /// a worker that never reached a safe point and never exited. The resources are then leaked
    /// deliberately: releasing memory a live worker may still be reading is the failure this whole
    /// module exists to prevent, so it is the wrong trade even under a stuck shutdown.
    pub fn drain_until(&self, deadline: Instant) -> Result<(), StillHeld> {
        self.retire_unless(|_| false);
        loop {
            self.reclaim();
            let pending = self.pending();
            if pending == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(StillHeld { pending });
            }
            // Attendants make progress on their own threads; yielding beats spinning on a core
            // they might want.
            crate::thread::yield_now();
        }
    }
}

impl<T: Clone + Send + Sync + 'static> Default for Reclaimer<T> {
    fn default() -> Reclaimer<T> {
        Reclaimer::new()
    }
}

impl<'r, T: Clone + Send + Sync + 'static> Attendants<'r, T> {
    /// Enrol one worker.
    #[must_use]
    pub fn attend(&self) -> Attendant<'r, T> {
        Attendant {
            inner: self.inner.subscriber(),
        }
    }
}

impl<T: Clone + Send + Sync + 'static> Attendant<'_, T> {
    /// Declare that this worker currently holds no reference to any tracked resource, and read the
    /// live set.
    ///
    /// This is the quiescent point. Everything in this module rests on the declaration being true
    /// -- see the module documentation.
    pub fn at_safe_point(&mut self) -> &[T] {
        self.inner.snapshot()
    }
}
