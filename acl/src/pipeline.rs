// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Pipeline publication and lookup surface.
//!
//! This module provides the production-shaped publish/observe machinery
//! for ACL-style table backends.  It is intentionally backend-agnostic:
//!
//! - The [`Lookup`] trait is what NF authors program against on the
//!   data path.  Each backend implements it on its own concrete
//!   pipeline type.
//! - [`PipelineWriter`] owns the publication slot.  It runs on a single
//!   thread (typically the build worker; for DPDK that thread must be
//!   EAL-registered).
//! - [`PipelineReader`] is held one-per-reader-thread (typically one
//!   per lcore).  Its [`snapshot`](PipelineReader::snapshot) method
//!   refreshes the local cache, publishes the observed generation via
//!   QSBR, and returns an opaque value implementing [`Lookup`].
//! - The returned snapshot value is `!Send + !Sync`: the type system
//!   forbids it from leaking to another thread.
//!
//! # Memory reclamation
//!
//! Reclamation uses **Quiescent State Based Reclamation (QSBR)** with
//! the writer thread pinned as the sole reclaimer:
//!
//! - The writer retains an `Arc` clone of every published generation in
//!   a [`PipelineWriter::retired`] list.
//! - Each reader publishes its currently-observed generation to a
//!   per-reader atomic at every [`snapshot`](PipelineReader::snapshot)
//!   call.
//! - On each [`publish`](PipelineWriter::publish), the writer scans the
//!   minimum reader-observed generation and drops retired entries below
//!   that minimum.  Those drops run on the writer's thread.
//!
//! This yields a single guarantee: **the destructor for any published
//! pipeline value runs on the writer's thread.**  For backends that
//! contain FFI handles with thread requirements (e.g. DPDK ACL contexts
//! whose `Drop` calls `rte_acl_free` and must run on an EAL-registered
//! thread), this is the load-bearing invariant.
//!
//! # The publication primitive
//!
//! `arc_swap::ArcSwap` is used here as a humble atomic-pointer-publish
//! primitive.  Its drop-where-it-falls semantics are *not* relied upon;
//! the writer's retained list is what guarantees drop-on-writer.
//!
//! # Status
//!
//! Production-shaped first cut.  Expect refinement as additional
//! backends (tc-flower, rte_flow, hardware) push on the API.

#![allow(missing_docs)] // type-system surface is settling; doc once stable

use arc_swap::ArcSwap;
use arrayvec::ArrayVec;
use std::cell::Cell;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

// ============================================================================
// BATCH_SIZE -- the project-wide max batch length for [`Lookup::batch_lookup`]
// ============================================================================

/// Maximum keys per call to [`Lookup::batch_lookup`].  Sized to match
/// the typical DPDK rx_burst.
///
/// Backends MAY classify fewer than this many keys per call -- the
/// input is an [`ArrayVec`] with a runtime length up to this max.
/// Trailing entries of the output buffer beyond `keys.len()` are left
/// untouched by the default impl; callers should pre-fill `out` with
/// `None` if they need a full-buffer-clean invariant.
pub const BATCH_SIZE: usize = 64;

// ============================================================================
// Lookup -- the consumer-facing trait
// ============================================================================

/// The data-plane lookup surface.  NF authors program against this trait
/// (typically via `impl Lookup<Key = ..., Rule = ...>` parameters).
/// Backends implement it on their concrete pipeline types; the
/// publication machinery wraps those impls behind a thread-affine
/// snapshot type.
///
/// # Contract
///
/// Implementations must be pure: the same `(self, key)` produces the
/// same result on every call.  Mutation (counter updates, learning
/// table installation, etc.) is the job of a separate API and never
/// the return value of this trait.
pub trait Lookup {
    /// The key type the consumer constructs to drive a lookup.
    type Key;
    /// The rule type returned on a successful match.  Returned by
    /// reference; the borrow is tied to `&self`.
    type Rule;

    /// Look up a key.  Returns `None` if no rule matches.
    fn lookup(&self, key: &Self::Key) -> Option<&Self::Rule>;

    /// Batched lookup.  Default impl iterates [`lookup`] per key;
    /// vectorized backends (e.g. DPDK ACL via `rte_acl_classify`)
    /// override this to issue a single SIMD-batched call.
    ///
    /// `keys` may carry fewer than [`BATCH_SIZE`] entries; the default
    /// impl writes only the first `keys.len()` slots of `out`.
    /// Callers that read trailing entries should pre-fill `out` with
    /// `None`.  In practice the lcore loop reads `out[..keys.len()]`
    /// and never touches the trailing entries.
    ///
    /// [`lookup`]: Self::lookup
    fn batch_lookup<'a>(
        &'a self,
        keys: &ArrayVec<&Self::Key, BATCH_SIZE>,
        out: &mut [Option<&'a Self::Rule>; BATCH_SIZE],
    ) {
        for (key, slot) in keys.iter().zip(out.iter_mut()) {
            *slot = self.lookup(key);
        }
    }
}

/// Blanket forwarding so that `&L: Lookup` whenever `L: Lookup`.  This
/// is what makes `&Snapshot<P>` itself a `Lookup`, which in turn lets
/// [`PipelineReader::snapshot`] return `impl Lookup + '_` whose hidden
/// type is a borrow.
impl<L: Lookup + ?Sized> Lookup for &L {
    type Key = L::Key;
    type Rule = L::Rule;

    #[inline]
    fn lookup(&self, key: &Self::Key) -> Option<&Self::Rule> {
        L::lookup(self, key)
    }

    #[inline]
    fn batch_lookup<'a>(
        &'a self,
        keys: &ArrayVec<&Self::Key, BATCH_SIZE>,
        out: &mut [Option<&'a Self::Rule>; BATCH_SIZE],
    ) {
        L::batch_lookup(self, keys, out);
    }
}

// ============================================================================
// Snapshot -- private wrapper, repr(transparent) over T, !Send + !Sync
// ============================================================================
//
// The "commute trick" mirrors the existing `HeadersView<T>` pattern: `Snapshot`
// has no lifetime parameter; the lifetime rides on the borrow returned
// by `Snapshot::from_ref`.  This keeps generic bounds free of HRTB --
// `Snapshot<P>: Lookup` is a plain trait bound.

#[repr(transparent)]
struct Snapshot<T: ?Sized> {
    /// `PhantomData<*const ()>` makes `Snapshot<T>: !Send + !Sync` for
    /// any `T`.  These properties propagate to `&Snapshot<T>` (and to
    /// any `impl Trait` whose hidden type is `&Snapshot<T>`).
    _not_send: PhantomData<*const ()>,
    inner: T,
}

impl<T: ?Sized> Snapshot<T> {
    /// Reinterpret a `&T` as a `&Snapshot<T>`.
    ///
    /// `Snapshot<T>` is `#[repr(transparent)]` over `T` (the only
    /// non-ZST field), so the layouts are identical.  This is the
    /// equivalent of `HeadersView<T>::from_ref` in the headers crate.
    #[inline]
    #[allow(unsafe_code)]
    fn from_ref(t: &T) -> &Self {
        // SAFETY: `Snapshot<T>` is `#[repr(transparent)]` with `T` as
        // its sole non-ZST field; `_not_send` is `PhantomData`, a ZST.
        // Therefore `&T` and `&Snapshot<T>` have the same layout and
        // the cast is sound.
        unsafe { &*(t as *const T as *const Self) }
    }
}

/// Blanket forwarding: any `T: Lookup` makes `Snapshot<T>: Lookup`.
/// Backends never write `impl Lookup for Snapshot<...>`; they implement
/// `Lookup` on their concrete pipeline type and this blanket wires up
/// the wrapper.
impl<T: Lookup + ?Sized> Lookup for Snapshot<T> {
    type Key = T::Key;
    type Rule = T::Rule;

    #[inline]
    fn lookup(&self, key: &Self::Key) -> Option<&Self::Rule> {
        self.inner.lookup(key)
    }

    #[inline]
    fn batch_lookup<'a>(
        &'a self,
        keys: &ArrayVec<&Self::Key, BATCH_SIZE>,
        out: &mut [Option<&'a Self::Rule>; BATCH_SIZE],
    ) {
        self.inner.batch_lookup(keys, out);
    }
}

// ============================================================================
// Generation -- (gen-tag, pipeline) bundle held by Arc
// ============================================================================

struct Generation<P> {
    /// Monotonic version stamp assigned by the writer.  Used only by
    /// QSBR; lookup correctness does not depend on it.
    generation: u64,
    pipeline: P,
}

// ============================================================================
// QSBR domain + reader epoch
// ============================================================================

/// Shared registry of per-reader observed-generation cells.  Held in an
/// `Arc` between [`PipelineWriter`] and any [`PipelineReader`]s.
struct QsbrDomain {
    /// `Weak` rather than `Arc` so a reader thread that drops its
    /// [`PipelineReader`] is automatically unregistered: the
    /// [`Weak::upgrade`] call fails and the slot is pruned during the
    /// next [`min_observed`](Self::min_observed) scan.
    readers: Mutex<Vec<Weak<AtomicU64>>>,
}

impl QsbrDomain {
    fn new() -> Self {
        Self {
            readers: Mutex::new(Vec::new()),
        }
    }

    fn register(&self) -> ReaderEpoch {
        // Initial value `u64::MAX` means "this reader has not observed
        // any generation yet."  It does NOT constrain reclamation,
        // because the writer's `min_observed` skips it (treats it as
        // unconstraining) -- but only after the reader has actually
        // had a chance to call `snapshot` once.  See [`min_observed`].
        let cell = Arc::new(AtomicU64::new(u64::MAX));
        self.readers
            .lock()
            .expect("qsbr mutex poisoned")
            .push(Arc::downgrade(&cell));
        ReaderEpoch { cell }
    }

    /// Lowest observed generation across all live readers.  Returns
    /// `u64::MAX` when no readers are active OR when no reader has
    /// taken a snapshot yet (in which case there is nothing to
    /// constrain reclamation against).
    ///
    /// Stale `Weak`s (corresponding to readers that have been dropped)
    /// are pruned during the scan.
    fn min_observed(&self) -> u64 {
        let mut readers = self.readers.lock().expect("qsbr mutex poisoned");
        let mut min = u64::MAX;
        readers.retain(|weak| {
            if let Some(arc) = weak.upgrade() {
                let observed = arc.load(Ordering::Acquire);
                if observed < min {
                    min = observed;
                }
                true
            } else {
                false
            }
        });
        min
    }
}

/// Per-reader handle.  Holds an `Arc` to the same atomic that the
/// [`QsbrDomain`] holds a `Weak` to.
struct ReaderEpoch {
    cell: Arc<AtomicU64>,
}

impl ReaderEpoch {
    #[inline]
    fn observe(&self, generation: u64) {
        self.cell.store(generation, Ordering::Release);
    }
}

// ============================================================================
// PipelineWriter -- the publish + reclaim side
// ============================================================================

/// Single-thread publisher for a pipeline value of type `P`.
///
/// The `P: Send + Sync + 'static` bound is what is required to share
/// `Arc<Generation<P>>` across threads.  The writer itself is `Send`
/// (so it can be moved to the build worker thread once at startup) but
/// `!Sync` (only one thread should publish).
///
/// All destructors for retired pipeline values run on the thread that
/// calls [`publish`](Self::publish) or [`try_reclaim`](Self::try_reclaim).
/// For backends with thread-bound `Drop` impls (e.g. DPDK), that thread
/// must be the appropriately privileged one (EAL-registered for DPDK).
pub struct PipelineWriter<P: Send + Sync + 'static> {
    publication: Arc<ArcSwap<Generation<P>>>,
    qsbr: Arc<QsbrDomain>,
    retired: Vec<(u64, Arc<Generation<P>>)>,
    next_generation: u64,
    /// `PhantomData<Cell<()>>` makes the writer `Send + !Sync`: it can
    /// be moved to a specific thread, but cannot be shared between
    /// threads.  Single-publisher invariant is structural.
    _not_sync: PhantomData<Cell<()>>,
}

/// Build a publisher + reader factory pair sharing the same
/// publication slot.
///
/// `initial` is the pipeline value visible to readers before the
/// writer has called [`publish`](PipelineWriter::publish) for the
/// first time.  Passing an "empty" or "trap-everything" pipeline is a
/// reasonable choice; readers always observe *some* value, never a
/// gap.
pub fn pipeline<P: Send + Sync + 'static>(initial: P) -> (PipelineWriter<P>, ReaderFactory<P>) {
    let qsbr = Arc::new(QsbrDomain::new());
    let publication = Arc::new(ArcSwap::from_pointee(Generation {
        generation: 0,
        pipeline: initial,
    }));
    let writer = PipelineWriter {
        publication: Arc::clone(&publication),
        qsbr: Arc::clone(&qsbr),
        retired: Vec::new(),
        next_generation: 1,
        _not_sync: PhantomData,
    };
    let factory = ReaderFactory { publication, qsbr };
    (writer, factory)
}

impl<P: Send + Sync + 'static> PipelineWriter<P> {
    /// Publish a new pipeline value.  Returns the generation number
    /// assigned to it.
    ///
    /// Triggers an opportunistic [`try_reclaim`](Self::try_reclaim)
    /// pass; any retired generations whose readers have all moved
    /// past them are dropped on this thread before this method
    /// returns.
    pub fn publish(&mut self, pipeline: P) -> u64 {
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("pipeline generation counter overflowed u64");

        let new_arc = Arc::new(Generation {
            generation,
            pipeline,
        });
        let prev_gen = generation - 1;
        let prev_arc = self.publication.swap(new_arc);
        // Retain the previous Arc so the writer is the one who drops
        // it once readers move past.  Without this, ArcSwap's internal
        // drop on `swap()` could be the *only* drop on this side, and
        // the actual destructor would run on whatever thread held the
        // last reader-side clone.
        self.retired.push((prev_gen, prev_arc));

        self.try_reclaim();
        generation
    }

    /// Best-effort reclamation.  Drops retired generations whose
    /// readers have all advanced past them.  Drops happen on this
    /// thread.
    ///
    /// Called automatically by [`publish`](Self::publish); exposed for
    /// callers that want to opportunistically reclaim between
    /// publishes (e.g. on idle ticks).
    pub fn try_reclaim(&mut self) {
        let safe_below = self.qsbr.min_observed();
        // Retain entries whose generation is still potentially in use.
        // Anything strictly below `safe_below` is definitely free to
        // drop; the last `Arc` clone is held in `self.retired` and
        // dropping that entry triggers the inner `Drop` on this
        // thread.
        self.retired
            .retain(|(generation, _arc)| *generation >= safe_below);
    }

    /// Number of retired generations still pending reclamation.
    /// Useful for diagnostics and for back-pressure heuristics.
    #[must_use]
    pub fn pending_reclamation(&self) -> usize {
        self.retired.len()
    }

    /// Latest generation number this writer has published.  Returns 0
    /// before the first publish (the initial value carries gen 0).
    #[must_use]
    pub fn current_generation(&self) -> u64 {
        self.next_generation.saturating_sub(1)
    }
}

// ============================================================================
// ReaderFactory -- spawns readers tied to the same publication
// ============================================================================

/// Spawns [`PipelineReader`] handles tied to the same publication
/// slot and QSBR domain as the corresponding [`PipelineWriter`].
///
/// `Clone`able so each lcore worker can be handed its own factory at
/// setup time and construct its own reader on the destination thread.
pub struct ReaderFactory<P: Send + Sync + 'static> {
    publication: Arc<ArcSwap<Generation<P>>>,
    qsbr: Arc<QsbrDomain>,
}

impl<P: Send + Sync + 'static> ReaderFactory<P> {
    /// Construct a new [`PipelineReader`].  Each call registers a new
    /// reader slot in the QSBR domain.
    #[must_use]
    pub fn reader(&self) -> PipelineReader<P> {
        PipelineReader {
            publication: Arc::clone(&self.publication),
            epoch: self.qsbr.register(),
            cached: None,
            _not_sync: PhantomData,
        }
    }
}

impl<P: Send + Sync + 'static> Clone for ReaderFactory<P> {
    fn clone(&self) -> Self {
        Self {
            publication: Arc::clone(&self.publication),
            qsbr: Arc::clone(&self.qsbr),
        }
    }
}

// ============================================================================
// PipelineReader -- per-thread reader handle
// ============================================================================

/// One-per-thread reader handle.
///
/// `Send` so it can be moved to its destination thread once during
/// setup, but `!Sync` because the embedded epoch represents
/// *that thread's* observed generation; sharing it across threads
/// would scramble QSBR.
pub struct PipelineReader<P: Send + Sync + 'static> {
    publication: Arc<ArcSwap<Generation<P>>>,
    epoch: ReaderEpoch,
    cached: Option<Arc<Generation<P>>>,
    /// `PhantomData<Cell<()>>` makes the reader `Send + !Sync`.
    _not_sync: PhantomData<Cell<()>>,
}

impl<P: Lookup + Send + Sync + 'static> PipelineReader<P> {
    /// Refresh from the publication slot, observe the (refreshed)
    /// generation via QSBR, and return a thread-affine snapshot
    /// implementing [`Lookup`].
    ///
    /// The returned value is `!Send + !Sync`: it cannot leak to another
    /// thread.  Its lifetime is tied to `&mut self`, so two snapshots
    /// from the same reader cannot coexist -- the borrow checker
    /// enforces "one snapshot at a time per reader," matching the
    /// per-batch boundary on the data path.
    pub fn snapshot(&mut self) -> impl Lookup<Key = P::Key, Rule = P::Rule> + '_ {
        // 1. Refresh from publication, but only if the publication has
        //    advanced past our cache.  In the steady state this is a
        //    single atomic load (ArcSwap::load_full) plus a generation
        //    compare.
        let latest = self.publication.load_full();
        let needs_refresh = self
            .cached
            .as_ref()
            .is_none_or(|cached| cached.generation < latest.generation);
        if needs_refresh {
            // Replacing `cached` drops the previous Arc on this
            // thread.  Per the QSBR contract, the writer retains its
            // own clone of the previous generation in
            // `PipelineWriter::retired`, so this drop only decrements
            // the refcount; the `Drop` body for `Generation<P>` runs
            // when the writer's clone is the last one alive (i.e. on
            // the writer's thread).
            self.cached = Some(latest);
        }
        let cached = self.cached.as_ref().expect("cache populated above");

        // 2. Publish the observed generation.  This is what unblocks
        //    the writer's reclamation pass for any older generations.
        self.epoch.observe(cached.generation);

        // 3. Return a thread-affine borrow.  `Snapshot::from_ref` is a
        //    no-op layout cast.  The opaque return type's hidden type
        //    is `&Snapshot<P>`, which inherits `!Send + !Sync` from
        //    `Snapshot`.
        Snapshot::from_ref(&cached.pipeline)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::Duration;

    // -- Test fixture: a trivial Lookup impl ---------------------------------

    struct ToyPipeline {
        rules: Vec<(u32, &'static str)>,
        drop_counter: Arc<AtomicUsize>,
    }

    impl Lookup for ToyPipeline {
        type Key = u32;
        type Rule = &'static str;

        fn lookup(&self, key: &u32) -> Option<&&'static str> {
            self.rules
                .iter()
                .find_map(|(k, v)| if k == key { Some(v) } else { None })
        }
    }

    impl Drop for ToyPipeline {
        fn drop(&mut self) {
            self.drop_counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn toy(rules: Vec<(u32, &'static str)>, ctr: &Arc<AtomicUsize>) -> ToyPipeline {
        ToyPipeline {
            rules,
            drop_counter: Arc::clone(ctr),
        }
    }

    // -- Lookup contract ----------------------------------------------------

    #[test]
    fn lookup_via_snapshot_returns_matching_rule() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (writer, factory) = pipeline(toy(vec![(1, "a"), (2, "b")], &drops));
        let mut reader = factory.reader();
        let snap = reader.snapshot();
        assert_eq!(snap.lookup(&1), Some(&"a"));
        assert_eq!(snap.lookup(&2), Some(&"b"));
        assert_eq!(snap.lookup(&3), None);
        let _ = writer.current_generation();
    }

    #[test]
    fn snapshot_reflects_published_value() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut writer, factory) = pipeline(toy(vec![(1, "v0")], &drops));
        let mut reader = factory.reader();

        assert_eq!(reader.snapshot().lookup(&1), Some(&"v0"));

        writer.publish(toy(vec![(1, "v1")], &drops));
        assert_eq!(reader.snapshot().lookup(&1), Some(&"v1"));

        writer.publish(toy(vec![(1, "v2")], &drops));
        assert_eq!(reader.snapshot().lookup(&1), Some(&"v2"));
    }

    // -- Batch lookup -------------------------------------------------------

    #[test]
    fn default_batch_lookup_iterates_keys_in_order() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (_writer, factory) = pipeline(toy(vec![(1, "a"), (2, "b"), (5, "e")], &drops));
        let mut reader = factory.reader();
        let snap = reader.snapshot();

        // Batch with three of the configured BATCH_SIZE slots used.
        let key_storage = [1u32, 2, 9, 5];
        let mut keys = ArrayVec::<&u32, BATCH_SIZE>::new();
        for k in &key_storage {
            keys.push(k);
        }
        let mut out: [Option<&&'static str>; BATCH_SIZE] = [None; BATCH_SIZE];
        snap.batch_lookup(&keys, &mut out);

        assert_eq!(out[0], Some(&"a"));
        assert_eq!(out[1], Some(&"b"));
        assert_eq!(out[2], None);
        assert_eq!(out[3], Some(&"e"));
        // Trailing entries untouched (still `None` from caller's reset).
        for slot in &out[4..] {
            assert!(slot.is_none());
        }
    }

    /// Verify that an override on a backend is preferred over the
    /// default impl.  We use a marker-counting backend that bumps a
    /// counter on each `batch_lookup` call so we can assert the
    /// blanket impls forward through to the override rather than
    /// silently using the default.
    #[test]
    fn batch_lookup_override_is_preferred_over_default() {
        struct VectorizedToy {
            rules: Vec<(u32, &'static str)>,
            batch_calls: Arc<AtomicUsize>,
        }

        impl Lookup for VectorizedToy {
            type Key = u32;
            type Rule = &'static str;

            fn lookup(&self, key: &u32) -> Option<&&'static str> {
                self.rules
                    .iter()
                    .find_map(|(k, v)| if k == key { Some(v) } else { None })
            }

            fn batch_lookup<'a>(
                &'a self,
                keys: &ArrayVec<&u32, BATCH_SIZE>,
                out: &mut [Option<&'a &'static str>; BATCH_SIZE],
            ) {
                self.batch_calls.fetch_add(1, Ordering::Relaxed);
                for (key, slot) in keys.iter().zip(out.iter_mut()) {
                    *slot = self.lookup(key);
                }
            }
        }

        let batch_calls = Arc::new(AtomicUsize::new(0));
        let backend = VectorizedToy {
            rules: vec![(1, "a"), (2, "b")],
            batch_calls: Arc::clone(&batch_calls),
        };
        let (_writer, factory) = pipeline(backend);
        let mut reader = factory.reader();
        let snap = reader.snapshot();

        let key_storage = [1u32, 2];
        let mut keys = ArrayVec::<&u32, BATCH_SIZE>::new();
        for k in &key_storage {
            keys.push(k);
        }
        let mut out: [Option<&&'static str>; BATCH_SIZE] = [None; BATCH_SIZE];
        snap.batch_lookup(&keys, &mut out);

        assert_eq!(
            batch_calls.load(Ordering::Relaxed),
            1,
            "backend's batch_lookup override must be invoked through Snapshot's blanket forward",
        );
        assert_eq!(out[0], Some(&"a"));
        assert_eq!(out[1], Some(&"b"));
    }

    // -- QSBR / reclamation -------------------------------------------------

    #[test]
    fn writer_drops_retired_generations_after_reader_advances() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut writer, factory) = pipeline(toy(vec![(1, "v0")], &drops));
        let mut reader = factory.reader();

        // Reader observes gen 0.
        let _ = reader.snapshot();

        writer.publish(toy(vec![(1, "v1")], &drops));
        // Writer just retired gen 0.  Reader is still observing gen 0.
        // No drops yet (the initial v0 is held in retired list).
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(writer.pending_reclamation(), 1);

        // Reader observes gen 1.
        let _ = reader.snapshot();

        // Next publish triggers a reclaim pass that frees gen 0.
        writer.publish(toy(vec![(1, "v2")], &drops));
        // Gen 0 is now reclaimable; v0's drop has run.
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn reclamation_blocked_until_all_readers_advance() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut writer, factory) = pipeline(toy(vec![(1, "v0")], &drops));
        let mut a = factory.reader();
        let mut b = factory.reader();

        a.snapshot(); // both observe gen 0
        b.snapshot();

        writer.publish(toy(vec![(1, "v1")], &drops));
        assert_eq!(writer.pending_reclamation(), 1);
        // No drops: both readers still on gen 0.
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        // Only `a` advances.
        a.snapshot();
        writer.try_reclaim();
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        // Now `b` advances; reclamation can proceed.
        b.snapshot();
        writer.try_reclaim();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dropping_reader_unregisters_it_from_qsbr() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut writer, factory) = pipeline(toy(vec![(1, "v0")], &drops));
        let mut reader = factory.reader();
        reader.snapshot(); // observe gen 0

        writer.publish(toy(vec![(1, "v1")], &drops));
        assert_eq!(writer.pending_reclamation(), 1);

        // Reader exits without ever advancing past gen 0.  After it
        // drops, the QSBR scan should prune it and reclamation should
        // succeed.
        drop(reader);
        writer.try_reclaim();
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert_eq!(writer.pending_reclamation(), 0);
    }

    #[test]
    fn drops_run_on_writer_thread() {
        // We can't directly observe "Drop ran on thread X" without
        // carrying the thread id through the inner type.  Do that.

        struct MarkedPipeline {
            drop_thread: Arc<Mutex<Option<thread::ThreadId>>>,
        }
        impl Lookup for MarkedPipeline {
            type Key = ();
            type Rule = ();
            fn lookup(&self, _key: &()) -> Option<&()> {
                None
            }
        }
        impl Drop for MarkedPipeline {
            fn drop(&mut self) {
                *self.drop_thread.lock().expect("mutex") = Some(thread::current().id());
            }
        }

        let initial_marker = Arc::new(Mutex::new(None));
        let (mut writer, factory) = pipeline(MarkedPipeline {
            drop_thread: Arc::clone(&initial_marker),
        });

        // Reader thread observes the initial generation, then exits.
        let factory_for_reader = factory.clone();
        let reader_handle = thread::spawn(move || {
            let mut reader = factory_for_reader.reader();
            reader.snapshot();
            // reader drops here; cell pruned next time writer scans
        });
        reader_handle.join().expect("reader thread");

        // Writer thread (current thread) publishes a new generation
        // and reclaims; the initial pipeline's Drop should fire on
        // this thread, NOT on the reader thread.
        let writer_thread_id = thread::current().id();
        let final_marker = Arc::new(Mutex::new(None));
        writer.publish(MarkedPipeline {
            drop_thread: Arc::clone(&final_marker),
        });
        writer.try_reclaim();

        let observed_drop_thread = initial_marker
            .lock()
            .expect("mutex")
            .expect("initial pipeline should have been dropped");
        assert_eq!(
            observed_drop_thread, writer_thread_id,
            "initial pipeline's Drop should run on the writer's thread",
        );

        // Hold the factory alive so we can exit cleanly.
        drop(factory);
        drop(writer);
    }

    // -- Send / Sync invariants (compile-time tested via trybuild ideally;
    // here we encode them as static_assertions-style negative checks). ----

    // -- Compile-time auto-trait assertions ---------------------------------
    //
    // The static_assertions macros below cause a build error if the
    // auto-trait properties of the snapshot types ever regress.  These
    // are the load-bearing properties of this module; a regression
    // would silently allow snapshots to escape their reader thread.

    static_assertions::assert_not_impl_any!(Snapshot<()>: Send, Sync);
    static_assertions::assert_not_impl_any!(&'static Snapshot<()>: Send);

    // Reader is `Send` (movable to its destination thread once at
    // setup) but `!Sync` (the embedded epoch represents one specific
    // thread's observed generation).
    static_assertions::assert_impl_all!(PipelineReader<ToyPipeline>: Send);
    static_assertions::assert_not_impl_any!(PipelineReader<ToyPipeline>: Sync);

    // Writer same as Reader: Send but !Sync.  Single-publisher
    // invariant is structural.
    static_assertions::assert_impl_all!(PipelineWriter<ToyPipeline>: Send);
    static_assertions::assert_not_impl_any!(PipelineWriter<ToyPipeline>: Sync);

    #[test]
    fn reader_handles_short_burst_without_drops_piling_up() {
        // Sanity: 100 publish/snapshot cycles with one reader keeps
        // the retired list at a single entry steady state.
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut writer, factory) = pipeline(toy(vec![(1, "v0")], &drops));
        let mut reader = factory.reader();
        for i in 0..100 {
            reader.snapshot();
            writer.publish(toy(vec![(1, leak(format!("v{i}")))], &drops));
        }
        // Take one final snapshot, then a final publish to drain.
        reader.snapshot();
        writer.publish(toy(vec![(1, "final")], &drops));
        // Should hold roughly one retired generation (the most-recent
        // unobserved one); and we should have dropped 99 of the 101
        // toys produced, modulo the in-flight ones.
        let pending = writer.pending_reclamation();
        assert!(pending <= 2, "pending = {pending}, expected <= 2");
    }

    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    #[test]
    fn brief_smoke_test_with_a_real_reader_thread() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (mut writer, factory) = pipeline(toy(vec![(1, "v0")], &drops));

        let stop = Arc::new(AtomicU64::new(0));
        let reader_factory = factory.clone();
        let stop_for_reader = Arc::clone(&stop);
        let drops_for_reader = Arc::clone(&drops);
        let reader_thread = thread::spawn(move || {
            let mut reader = reader_factory.reader();
            while stop_for_reader.load(Ordering::Acquire) == 0 {
                let snap = reader.snapshot();
                let _ = snap.lookup(&1);
                thread::sleep(Duration::from_micros(50));
            }
            // Drop the reader so the writer can fully reclaim.
            drop(reader);
            // Touch drops_for_reader to keep the binding alive.
            let _ = drops_for_reader.load(Ordering::Relaxed);
        });

        for i in 0..50u32 {
            writer.publish(toy(vec![(1, leak(format!("v{i}")))], &drops));
            thread::sleep(Duration::from_micros(100));
        }

        stop.store(1, Ordering::Release);
        reader_thread.join().expect("reader thread");

        // Final reclaim pass on the writer thread.
        writer.try_reclaim();

        // We don't assert exact counts (timing-dependent) but the
        // pending list should be bounded.
        let pending = writer.pending_reclamation();
        assert!(
            pending <= 1,
            "pending = {pending}, expected <= 1 after final reclaim",
        );
    }
}
