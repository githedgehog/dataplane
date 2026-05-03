#![forbid(unsafe_code)]
#![deny(
    // missing_docs,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod slot;

use core::{cell::Cell, marker::PhantomData, num::NonZero};

use concurrency::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};

use crate::slot::Slot;

type NotSync = PhantomData<Cell<()>>; // can still be Send

struct Versioned<T> {
    /// Monotonic version stamp assigned by the writer.
    version: Version,
    inner: T,
}

struct Domain {
    /// Registry of per-reader observation cells.  Mutex-guarded because
    /// `register` (any thread holding a `Publisher`) and the writer's
    /// reclaim scan (`min_observed`) both mutate the Vec.  Cold path —
    /// the snapshot fast path never touches this.
    ///
    /// Each entry is the same `Arc<CachePaddedCounter>` the corresponding
    /// `Reader` holds via its `Epoch`.  When a `Reader` drops, the
    /// strong-count of its cell falls from 2 (Reader + Domain) to 1
    /// (Domain only); the next `min_observed` scan removes such entries.
    /// We use `Arc::strong_count` rather than `Weak` because loom's
    /// `loom::sync` doesn't expose a `Weak`, and `strong_count` carries
    /// the same information with one fewer indirection.
    active: Mutex<Vec<Arc<CachePaddedCounter>>>,
}

impl Domain {
    const READER_GUESS: usize = 256;

    fn new() -> Self {
        Self {
            active: Mutex::new(Vec::with_capacity(Self::READER_GUESS)),
        }
    }

    fn register(&self) -> Epoch {
        let epoch = Epoch::new();
        #[allow(clippy::expect_used)] // the mutex is poisoned only in unrecoverable error cases
        self.active
            .lock()
            .expect("qsbr mutex poisoned")
            .push(Arc::clone(&epoch.cell));
        epoch
    }

    fn min_observed(&self) -> Option<Version> {
        #[allow(clippy::expect_used)] // the mutex is poisoned only in unrecoverable error cases
        let mut active = self.active.lock().expect("qsbr mutex poisoned");
        let mut min = u64::MAX;
        active.retain(|cell| {
            if Arc::strong_count(cell) == 1 {
                // Only the Domain still holds this cell — the corresponding
                // Reader is gone.  Drop the entry.
                return false;
            }
            let observed = cell.load();
            if observed == 0 {
                // Registered reader, no snapshot yet -> doesn't pin any
                // version.  Keep the slot, but skip it for the min.
                return true;
            }
            if observed < min {
                min = observed;
            }
            true
        });
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

#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, Hash)]
pub struct Version(NonZero<u64>);

impl Version {
    // SAFETY: const fn trivially sound
    #[allow(clippy::unwrap_used)]
    const INITIAL: Self = Self(NonZero::new(1).unwrap());

    #[inline]
    const fn get(self) -> u64 {
        self.0.get()
    }

    #[inline]
    const fn next(self) -> Self {
        if let Some(nz) = self.0.checked_add(1) {
            Self(nz)
        } else {
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
        }
    }
}

pub struct Publisher<T: Send + Sync + 'static> {
    publication: Arc<Slot<Versioned<T>>>,
    domain: Arc<Domain>,
    retired: Vec<Arc<Versioned<T>>>,
    next_version: Version,
    _not_sync: NotSync,
}

pub fn channel<T: Send + Sync + 'static>(initial: T) -> (Publisher<T>, SubscriberFactory<T>) {
    let qsbr = Arc::new(Domain::new());
    let version = Version::INITIAL;
    let publication = Arc::new(Slot::from_pointee(Versioned {
        version,
        inner: initial,
    }));
    let publisher = Publisher {
        publication: Arc::clone(&publication),
        domain: Arc::clone(&qsbr),
        retired: Vec::with_capacity(8),
        next_version: Version::INITIAL.next(),
        _not_sync: PhantomData,
    };
    let subscriber = SubscriberFactory { publication, qsbr };
    (publisher, subscriber)
}

impl<T: Send + Sync + 'static> Publisher<T> {
    pub fn publish(&mut self, message: T) -> Version {
        let generation = self.next_version;
        self.next_version = self.next_version.next();
        let new_arc = Arc::new(Versioned {
            version: generation,
            inner: message,
        });
        let prev_arc = self.publication.swap(new_arc);
        self.retired.push(prev_arc);
        self.reclaim();
        generation
    }

    pub fn reclaim(&mut self) {
        match self.domain.min_observed() {
            Some(version) => {
                self.retired.retain(|x| x.version >= version);
            }
            None => {
                self.retired.clear();
            }
        }
    }

    #[must_use]
    pub fn pending_reclamation(&self) -> usize {
        self.retired.len()
    }
}

pub struct SubscriberFactory<T: Send + Sync + 'static> {
    publication: Arc<Slot<Versioned<T>>>,
    qsbr: Arc<Domain>,
}

impl<T> Clone for SubscriberFactory<T>
where
    T: Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            publication: Arc::clone(&self.publication),
            qsbr: Arc::clone(&self.qsbr),
        }
    }
}

impl<T: Send + Sync + 'static> SubscriberFactory<T> {
    #[must_use]
    pub fn reader(&self) -> Reader<T> {
        Reader {
            publication: Arc::clone(&self.publication),
            epoch: self.qsbr.register(),
            cached: None,
            _not_sync: PhantomData,
        }
    }
}

pub struct Reader<T: Send + Sync + 'static> {
    publication: Arc<Slot<Versioned<T>>>,
    epoch: Epoch,
    cached: Option<Arc<Versioned<T>>>,
    _not_sync: NotSync,
}

impl<T: Send + Sync + 'static> Reader<T> {
    pub fn snapshot(&mut self) -> &T {
        let latest = self.publication.load_full();
        let needs_refresh = self
            .cached
            .as_ref()
            .is_none_or(|cached| cached.version < latest.version);
        if needs_refresh {
            let version = latest.version;
            // Cache update MUST happen before `observe` call!
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

impl<T: Send + Sync + 'static> Drop for Reader<T> {
    fn drop(&mut self) {
        // Load-bearing: cached must drop BEFORE epoch.  If epoch dies
        // first, the cell's strong-count falls to 1, the writer's next
        // `min_observed` scan prunes our entry and returns None, and
        // `reclaim` then clears retired — but our still-live cached
        // Arc would be the last clone of `Versioned<V>`, so its
        // destructor would run on this (reader) thread, violating QSBR
        // drop affinity.  Drop cached first so the writer always holds
        // the last clone.
        self.cached = None;
    }
}
