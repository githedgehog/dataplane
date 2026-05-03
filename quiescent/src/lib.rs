#![forbid(unsafe_code)]
#![deny(
    // missing_docs,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::{
    cell::Cell,
    marker::PhantomData,
    num::NonZero,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use arc_swap::ArcSwap;

type NotSync = core::marker::PhantomData<Cell<()>>; // can still be Send

struct Versioned<T> {
    /// Monotonic version stamp assigned by the writer.
    version: Version,
    inner: T,
}

struct Domain {
    active: std::sync::Mutex<Vec<EpochTracker>>,
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
            .push(epoch.track());
        epoch
    }

    fn min_observed(&self) -> Option<Version> {
        #[allow(clippy::expect_used)] // the mutex is poisoned only in unrecoverable error cases
        let mut active = self.active.lock().expect("qsbr mutex poisoned");
        let mut min = u64::MAX;
        if active.is_empty() {
            return None;
        }
        active.retain(|weak| {
            if let Some(arc) = weak.cell.upgrade() {
                let observed = arc.load();
                if observed == 0 {
                    // Registered reader, no snapshot yet -> doesn't pin any version.
                    // Keep the slot, but skip it for the min computation.
                    return true;
                }
                if observed < min {
                    min = observed;
                }
                true
            } else {
                false
            }
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
    const fn new() -> Self {
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

    fn track(&self) -> EpochTracker {
        EpochTracker::new(Arc::downgrade(&self.cell))
    }

    fn observe(&self, version: Version) {
        self.cell.store(version.get());
    }
}

#[repr(transparent)]
#[derive(Debug)]
struct EpochTracker {
    cell: Weak<CachePaddedCounter>,
}

impl EpochTracker {
    fn new(cell: Weak<CachePaddedCounter>) -> Self {
        Self { cell }
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

pub struct Writer<T: Send + Sync + 'static> {
    publication: Arc<ArcSwap<Versioned<T>>>,
    domain: Arc<Domain>,
    retired: Vec<Arc<Versioned<T>>>,
    next_version: Version,
    _not_sync: NotSync,
}

pub fn channel<T: Send + Sync + 'static>(initial: T) -> (Writer<T>, Publisher<T>) {
    let qsbr = Arc::new(Domain::new());
    let version = Version::INITIAL;
    let publication = Arc::new(ArcSwap::from_pointee(Versioned {
        version,
        inner: initial,
    }));
    let writer = Writer {
        publication: Arc::clone(&publication),
        domain: Arc::clone(&qsbr),
        retired: Vec::with_capacity(8),
        next_version: Version::INITIAL.next(),
        _not_sync: PhantomData,
    };
    let reader = Publisher { publication, qsbr };
    (writer, reader)
}

impl<T: Send + Sync + 'static> Writer<T> {
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

#[derive(Clone)]
pub struct Publisher<T: Send + Sync + 'static> {
    publication: Arc<ArcSwap<Versioned<T>>>,
    qsbr: Arc<Domain>,
}

impl<T: Send + Sync + 'static> Publisher<T> {
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
    publication: Arc<ArcSwap<Versioned<T>>>,
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
        // first, the writer's next reclaim sees `min_observed() == None`
        // and clears retired; our still-live cached Arc would then
        // become the last clone of `Versioned<V>` and its destructor
        // would run on this (reader) thread, violating QSBR drop
        // affinity.  Drop cached first so the writer always holds the
        // last clone.
        self.cached = None;
    }
}
