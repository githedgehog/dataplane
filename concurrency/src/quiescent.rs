// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../QUIESCENT.md")]
#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use core::cell::{Cell, RefCell};
use core::marker::PhantomData;
use core::num::NonZero;

use crate::slot::Slot;
use crate::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

struct Versioned<T> {
    /// Monotonic version stamp assigned by the Publisher.
    version: Version,
    inner: T,
}

struct Domain {
    /// Registry of per-Subscriber observation cells.  Mutex-guarded
    /// because `register` (any thread holding a `SubscriberFactory`)
    /// and the Publisher's reclaim scan (`min_observed`) both mutate
    /// the Vec.  The snapshot fast path never touches this; `register`
    /// is a once-per-Subscriber cost at spawn time.  `min_observed`
    /// shares the same lock and is called from `reclaim` (which
    /// `publish` invokes on every call), so this Mutex sits on the
    /// publish path -- keep its critical section tight.
    ///
    /// Each entry is the same `Arc<CachePaddedCounter>` the
    /// corresponding `Subscriber` holds via its `Epoch`.  When a
    /// `Subscriber` drops, the strong-count of its cell falls from 2
    /// (Subscriber + Domain) to 1 (Domain only); the next
    /// `min_observed` scan removes such entries.  We use
    /// `Arc::strong_count` rather than `Weak` because loom's
    /// `loom::sync` doesn't expose a `Weak`, and `strong_count`
    /// carries the same information with one fewer indirection.
    active: Mutex<Vec<Arc<CachePaddedCounter>>>,
}

impl Domain {
    /// Initial capacity for the active-Subscriber registry.  Sized to
    /// roughly the typical maximum lcore count for our deployments;
    /// over-sizing the Vec is cheap (one allocation of pointer-sized
    /// slots) and we avoid early reallocations during burst spawns.
    const SUBSCRIBER_GUESS: usize = 256;

    fn new() -> Self {
        Self {
            active: Mutex::new(Vec::with_capacity(Self::SUBSCRIBER_GUESS)),
        }
    }

    fn register(&self) -> Epoch {
        let epoch = Epoch::new();
        self.active.lock().push(Arc::clone(&epoch.cell));
        epoch
    }

    fn min_observed(&self) -> Option<Version> {
        let mut active = self.active.lock();
        let mut min = u64::MAX;
        let mut any_in_flight = false;
        active.retain(|cell| {
            if Arc::strong_count(cell) == 1 {
                // Only the Domain still holds this cell -- the corresponding
                // Subscriber is gone.  Drop the entry.
                //
                // Load-bearing Acquire fence: `Arc::strong_count` is a
                // Relaxed load in std, but the Subscriber's drop sequence
                // is `cached = None` (Release on `Versioned`'s strong
                // count) followed by `epoch` field drop (Release on this
                // cell's strong count).  Without a synchronization
                // edge, on weak-memory architectures the Publisher's
                // subsequent decrement of the same `Versioned` (in
                // `reclaim`) could be reordered before the Subscriber's
                // -- leaving the Subscriber's decrement as the last one,
                // and therefore running the destructor on the wrong
                // thread.  This Acquire fence pairs with the
                // Subscriber's `epoch` Release decrement: the Relaxed
                // `strong_count` load above sees the result of that
                // Release, and the fence lifts every later operation
                // on this thread to happen-after it.  In particular,
                // any subsequent `retired.clear()` decrement of the
                // matching `Versioned` is now ordered after the
                // Subscriber's prior `cached = None` decrement.
                crate::sync::atomic::fence(Ordering::Acquire);
                return false;
            }
            let observed = cell.load();
            if observed == 0 {
                // Cell == 0 means the Subscriber is either freshly
                // registered or in the middle of its first snapshot
                // (between `load_full` and `observe`).  In the latter
                // case the Subscriber may already be holding an
                // `Arc<Versioned>` via the local `latest` variable
                // that `min_observed` cannot see, so we cannot
                // conclude "no pin" -- that would let `reclaim` drop a
                // retired version the Subscriber is about to cache,
                // and the destructor would then run on the
                // Subscriber's thread when the cached Arc is finally
                // dropped.  Conservatively pin every retired version
                // until this Subscriber observes a real Version.  Once
                // a Subscriber has called `observe` once, its cell is
                // monotonically non-zero for the rest of its life
                // (Version is `NonZero<u64>`), so this is a one-shot
                // window per Subscriber rather than a permanent block.
                any_in_flight = true;
                return true;
            }
            if observed < min {
                min = observed;
            }
            true
        });
        if any_in_flight {
            // Pin everything from the lowest possible version onward;
            // the caller's `retain |x| x.version >= INITIAL` keeps all
            // retired entries.
            return Some(Version::INITIAL);
        }
        if min == u64::MAX {
            return None;
        }
        Some(Version(NonZero::new(min).unwrap_or_else(|| unreachable!())))
    }
}

#[repr(transparent)]
struct Epoch {
    cell: Arc<CachePaddedCounter>,
}

#[repr(align(64))] // cache padding to avoid false sharing if something else ends up in the same cache line
struct CachePaddedCounter(AtomicU64);

impl CachePaddedCounter {
    fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    #[inline]
    fn store(&self, val: u64) {
        self.0.store(val, Ordering::Release);
    }

    #[inline]
    fn load(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

impl Epoch {
    fn new() -> Self {
        Self {
            cell: Arc::new(CachePaddedCounter::new()),
        }
    }

    fn observe(&self, version: Version) {
        self.cell.store(version.get());
    }
}

/// Monotonic version stamp assigned to each publication.  Returned by
/// [`Publisher::publish`] and useful for tracking "has the world
/// advanced past this point?" without holding a snapshot ref.
///
/// Strictly increasing across the lifetime of a [`Publisher`].  The
/// initial publication carries the lowest non-zero version (`1`); each
/// subsequent `publish` returns a version one greater than the
/// previous one.
#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct Version(NonZero<u64>);

impl Version {
    const INITIAL: Self = Self(NonZero::<u64>::MIN);

    /// Extract the raw monotonic counter.  Useful for tracing, metrics,
    /// or comparing against externally-stored versions.
    #[inline]
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    #[inline]
    const fn next(self) -> Self {
        if let Some(nz) = self.0.checked_add(1) {
            Self(nz)
        } else {
            // LCOV_EXCL_START - reaching this path is itself the failure;
            // chasing coverage of it is absurd.  See the comment below.
            core::hint::cold_path();
            #[allow(clippy::panic)]
            {
                // This whole path is technically reachable, but only technically.
                // If you got config updates 1B times per second on average it would
                // still take 584 years to wrap around.  Even that requires us to receive
                // and process config updates faster than the line rate of an 800Gb/s NIC.
                // For hundreds of years.  With no reboot.
                //
                // The only realistic way to reach this point is via a bug in this code,
                // not via normal operation.
                panic!("Version wrapped!  This is a bug");
            }
            // LCOV_EXCL_STOP
        }
    }
}

/// Owns the publication slot and the QSBR domain.  Hands out
/// [`SubscriberFactory`] handles via [`Publisher::factory`]; both the
/// factory and any [`Subscriber`]s it spawns borrow from this Publisher
/// and therefore cannot outlive it.  This makes "the last `Versioned`
/// destructor runs on the Publisher's thread" a compile-time guarantee.
///
/// Methods that mutate Publisher state ([`publish`](Self::publish),
/// [`reclaim`](Self::reclaim)) take `&self` because handing out
/// `SubscriberFactory<'_, T>` borrows the Publisher shared.  Single-
/// thread use is enforced by the `RefCell`/`Cell` interior -- Publisher
/// is `!Sync`.  Send is preserved so the Publisher can be moved to its
/// owning thread once at startup.
pub struct Publisher<T: Send + Sync> {
    publication: Arc<Slot<Versioned<T>>>,
    domain: Arc<Domain>,
    retired: RefCell<Vec<Arc<Versioned<T>>>>,
    next_version: Cell<Version>,
}

/// Construct a fresh QSBR channel with `initial` as the version-1
/// publication.  Returns the [`Publisher`] alone; subscribers are
/// obtained via [`Publisher::factory`].
#[must_use]
pub fn channel<T: Send + Sync>(initial: T) -> Publisher<T> {
    let domain = Arc::new(Domain::new());
    let publication = Arc::new(Slot::from_pointee(Versioned {
        version: Version::INITIAL,
        inner: initial,
    }));
    Publisher {
        publication,
        domain,
        retired: RefCell::new(Vec::with_capacity(8)),
        next_version: Cell::new(Version::INITIAL.next()),
    }
}

impl<T: Send + Sync> Publisher<T> {
    /// Atomically publish `message` as a new version of the channel
    /// and run an opportunistic [`reclaim`](Self::reclaim) pass.
    ///
    /// # Panics
    ///
    /// Panics if the retired list is currently borrowed (this should be
    /// impossible unless unsafe code is involved).
    pub fn publish(&self, message: T) -> Version {
        let generation = self.next_version.get();
        self.next_version.set(generation.next());
        let new_arc = Arc::new(Versioned {
            version: generation,
            inner: message,
        });
        let prev_arc = self.publication.swap(new_arc);
        #[allow(clippy::expect_used)] // !Sync invariant means no concurrent borrow
        self.retired
            .try_borrow_mut()
            .expect("retired RefCell concurrently borrowed")
            .push(prev_arc);
        self.reclaim();
        generation
    }

    /// Reclaim any retired `Versioned`s whose version is below every
    /// live Subscriber's observed version.  Called automatically by
    /// [`publish`](Self::publish); exposed for callers who want to
    /// drive reclamation explicitly.
    ///
    /// # Panics
    ///
    /// Panics if the retired list is currently borrowed (this should be
    /// impossible unless unsafe code is involved).
    pub fn reclaim(&self) {
        #[allow(clippy::expect_used)] // !Sync invariant means no concurrent borrow
        let mut retired = self
            .retired
            .try_borrow_mut()
            .expect("retired RefCell concurrently borrowed");
        match self.domain.min_observed() {
            Some(version) => retired.retain(|x| x.version >= version),
            None => retired.clear(),
        }
    }

    /// Number of retired `Versioned`s still pending reclamation.
    /// Useful for diagnostics.
    #[must_use]
    pub fn pending_reclamation(&self) -> usize {
        self.retired.borrow().len()
    }

    /// Hand out a [`SubscriberFactory`] tied to this Publisher's
    /// lifetime.  The factory and any Subscribers it spawns cannot
    /// outlive the Publisher -- the borrow checker enforces this.
    #[must_use]
    pub fn factory(&self) -> SubscriberFactory<'_, T> {
        SubscriberFactory {
            publication: &self.publication,
            domain: &self.domain,
        }
    }
}

/// Spawns [`Subscriber`]s tied to a [`Publisher`].  Cheap to clone (a
/// pair of references); send clones into Subscriber threads inside a
/// `thread::scope`.
pub struct SubscriberFactory<'p, T: Send + Sync> {
    publication: &'p Arc<Slot<Versioned<T>>>,
    domain: &'p Arc<Domain>,
}

impl<T: Send + Sync> Clone for SubscriberFactory<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Send + Sync> Copy for SubscriberFactory<'_, T> {}

impl<'p, T: Send + Sync> SubscriberFactory<'p, T> {
    /// Construct a new [`Subscriber`] registered with the Publisher's
    /// QSBR domain.  Each Subscriber should live on a single thread.
    #[must_use]
    pub fn subscriber(&self) -> Subscriber<'p, T> {
        Subscriber {
            publication: self.publication,
            cached: None,
            epoch: self.domain.register(),
            _marker: PhantomData,
        }
    }
}

/// Per-thread snapshot handle.  Borrows from the [`Publisher`] via
/// `'p`; cannot outlive the Publisher.  `Send + !Sync`: ownership can
/// move to its destination thread once at setup, but the embedded
/// epoch is meaningful only for one thread's observations.
///
/// Field order is load-bearing: `cached` must drop **before** `epoch`.
/// See the [`Drop`] impl for the full reasoning.  Default field-drop
/// order (declared order) honours this; the explicit `Drop` impl is
/// belt-and-suspenders so the invariant survives someone reordering
/// the fields.
pub struct Subscriber<'p, T: Send + Sync> {
    publication: &'p Arc<Slot<Versioned<T>>>,
    cached: Option<Arc<Versioned<T>>>,
    epoch: Epoch,
    /// `&'p ()` carries the covariant Publisher-lifetime brand;
    /// `Cell<()>` makes the Subscriber `!Sync` (the embedded epoch is
    /// meaningful only for one thread's observations, and `cached` is
    /// a per-thread cache).  `PhantomData` of a tuple gives us both at
    /// zero cost.
    _marker: PhantomData<(&'p (), Cell<()>)>,
}

impl<T: Send + Sync> Subscriber<'_, T> {
    /// Refresh the per-thread cache from the latest publication and
    /// return a borrow of the underlying value.  The borrow is bounded
    /// by `&mut self`, so two snapshots from the same Subscriber
    /// cannot coexist -- one snapshot per Subscriber per batch.
    pub fn snapshot(&mut self) -> &T {
        let latest = self.publication.load_full();
        let needs_refresh = self
            .cached
            .as_ref()
            .is_none_or(|cached| cached.version < latest.version);
        if needs_refresh {
            let version = latest.version;
            // Cache update MUST happen before `observe` call!  Reordering
            // would let the Publisher's reclaim drop its retained clone
            // while we still hold the old `cached` Arc, so the
            // `Versioned` destructor would run on this (Subscriber)
            // thread instead of the Publisher's.
            self.cached = Some(latest);
            self.epoch.observe(version);
        }
        &self
            .cached
            .as_ref()
            .unwrap_or_else(|| unreachable!("cache populated"))
            .inner
    }
}

impl<T: Send + Sync> Drop for Subscriber<'_, T> {
    fn drop(&mut self) {
        // Load-bearing: cached must drop BEFORE epoch.  If epoch dies
        // first, the cell's strong-count falls to 1, the Publisher's
        // next `min_observed` scan prunes our entry -- but our
        // still-live `cached` Arc would be the last clone of
        // `Versioned<V>`, so its destructor would run on this
        // (Subscriber) thread, violating QSBR drop affinity.  Drop
        // cached first so the Publisher always holds the last clone.
        //
        // The field declaration order on `Subscriber` already places
        // `cached` before `epoch`, so default field-drop order honours
        // this.  The explicit `cached = None` here is belt-and-
        // suspenders: if anyone reorders the fields without thinking
        // about it, this Drop impl still gets it right.
        self.cached = None;
    }
}

// =====================================================================
// Auto-trait assertions: load-bearing properties of the public API.  A
// regression silently changing any of these would break QSBR safety;
// the build error here forces us to acknowledge the change.
// =====================================================================

// Publisher: Send (movable to its owning thread once at startup) but
// !Sync (single-thread invariant -- interior mutability via `RefCell`/
// `Cell` is unsafe to share).
static_assertions::assert_impl_all!(Publisher<()>: Send);
static_assertions::assert_not_impl_any!(Publisher<()>: Sync);

// SubscriberFactory: Send + Sync + Copy.  Cloned freely and shared
// across threads to spawn Subscribers per-lcore.
static_assertions::assert_impl_all!(SubscriberFactory<'static, ()>: Send, Sync, Copy);

// Subscriber: Send (movable to its destination thread once at setup)
// but !Sync (the embedded epoch represents one specific thread's
// observed version; sharing would scramble QSBR).
static_assertions::assert_impl_all!(Subscriber<'static, ()>: Send);
static_assertions::assert_not_impl_any!(Subscriber<'static, ()>: Sync);
