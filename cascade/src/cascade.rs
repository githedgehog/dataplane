// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The cascade and its read-side snapshot.
//!
//! Wires a [`MutableHead`], a `Vec<Arc<Sealed>>` of intermediate
//! layers, and an immutable tail into a single read path.  All three
//! are published via [`Slot`] so the LSM-manager can install new
//! generations without disturbing in-flight readers.
//!
//! Reads go through [`Snapshot`], which captures a coherent view of
//! all three publication slots in a single triple of `Arc`s.  The
//! reader holds the snapshot for the duration of a batch (one DPDK
//! `rx_burst` worth of packets, typically) and walks the cascade via
//! [`Snapshot::lookup`].
//!
//! Writes go directly through [`Cascade::write`], which forwards to
//! the current head's [`MutableHead::write`].
//!
//! Generation rotation -- sealing the current head into a fresh
//! sealed layer and installing a new empty head -- is driven by
//! [`Cascade::rotate`].  Compaction (fusing old sealed layers into
//! the tail) is intentionally not yet implemented; the sealed vec
//! grows unboundedly under repeated rotation until the compactor
//! lands in a follow-on commit.

use concurrency::slot::Slot;
use concurrency::sync::Arc;

use crate::head::MutableHead;
use crate::layer::{Layer, Outcome};
use crate::merge::MergeInto;

/// A coherent view of a cascade at a moment in time.
///
/// The snapshot holds an `Arc` to each of the head, sealed vector,
/// and tail.  As long as a snapshot exists, the cascade cannot
/// reclaim the underlying generations -- this is the QSBR-style
/// reader-extends-lifetime semantic that the [`concurrency`] crate's
/// reclamation primitives build on.
///
/// Readers should take a snapshot once per batch, classify many
/// packets against it, and drop it.  Holding a snapshot indefinitely
/// pins memory and prevents compaction.
pub struct Snapshot<H, S, T>
where
    H: MutableHead<Sealed = S>,
    S: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    head: Arc<H>,
    sealed: Arc<Vec<Arc<S>>>,
    tail: Arc<T>,
}

impl<H, S, T> Snapshot<H, S, T>
where
    H: MutableHead<Sealed = S>,
    S: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    /// Walk the cascade and return the first definitive match.
    ///
    /// Order: head, then sealed layers newest-first, then tail.
    /// Each layer's [`may_contain`](Layer::may_contain) is consulted
    /// before [`lookup`](Layer::lookup) to skip layers that the
    /// bloom hint excludes.
    pub fn lookup(&self, input: &H::Input) -> Option<&H::Output> {
        // Head first.  No bloom (the head is mutable and a filter
        // would have to be atomic to stay coherent).
        match self.head.lookup(input) {
            Outcome::Match(v) => return Some(v),
            Outcome::Forbid => return None,
            Outcome::Continue => {}
        }

        // Sealed layers, newest-first.  `sealed[0]` is the most
        // recently sealed head; `sealed[len-1]` is the oldest
        // sealed layer not yet compacted into the tail.
        for layer in self.sealed.iter() {
            if !layer.may_contain(input) {
                continue;
            }
            match layer.lookup(input) {
                Outcome::Match(v) => return Some(v),
                Outcome::Forbid => return None,
                Outcome::Continue => {}
            }
        }

        // Tail.
        if !self.tail.may_contain(input) {
            return None;
        }
        match self.tail.lookup(input) {
            Outcome::Match(v) => Some(v),
            Outcome::Forbid | Outcome::Continue => None,
        }
    }

    /// Borrow the head for direct lookup-or-write access.
    ///
    /// Useful for callers that want to coordinate a write with the
    /// same head generation they just read from.  Most callers
    /// should prefer [`Cascade::write`] which always grabs the
    /// freshest head.
    #[must_use]
    pub fn head(&self) -> &H {
        &self.head
    }

    /// Number of sealed layers in this snapshot.
    #[must_use]
    pub fn sealed_depth(&self) -> usize {
        self.sealed.len()
    }
}

/// A cascade.
///
/// Owns the three publication slots and exposes the lifecycle
/// operations (snapshot, write, rotate).  Production deployments
/// will additionally drive a compactor and a drain subscription
/// alongside; neither has landed yet.
pub struct Cascade<H, S, T>
where
    H: MutableHead<Sealed = S>,
    S: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    head: Slot<H>,
    sealed: Slot<Vec<Arc<S>>>,
    tail: Slot<T>,
}

impl<H, S, T> Cascade<H, S, T>
where
    H: MutableHead<Sealed = S>,
    S: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    /// Construct a cascade with the given initial head and tail and
    /// an empty sealed vector.
    pub fn new(head: H, tail: T) -> Self {
        Self {
            head: Slot::from_pointee(head),
            sealed: Slot::from_pointee(Vec::new()),
            tail: Slot::from_pointee(tail),
        }
    }

    /// Take a coherent snapshot of the cascade's three slots.
    ///
    /// Three independent atomic loads.  The result is a triple of
    /// `Arc`s that observe a *possible* state of the cascade --
    /// possibly not the *current* state if a concurrent rotation
    /// intersects the loads, but always a state that satisfies the
    /// cascade invariant (no entry visible at write-time becomes
    /// invisible mid-snapshot).  See the comment on
    /// [`rotate`](Cascade::rotate) for the ordering that makes this
    /// hold.
    pub fn snapshot(&self) -> Snapshot<H, S, T> {
        Snapshot {
            head: self.head.load_full(),
            sealed: self.sealed.load_full(),
            tail: self.tail.load_full(),
        }
    }

    /// Apply a write to the current head.
    ///
    /// Loads the current head `Arc` and forwards the op to its
    /// [`MutableHead::write`] impl.  Concurrent writes against the
    /// same key are resolved by the value type's
    /// [`Absorb`](crate::Absorb) implementation.
    ///
    /// If a [`rotate`](Cascade::rotate) is in progress when the
    /// load completes, the write may land on the about-to-be-sealed
    /// head.  Whether that write is captured in the resulting
    /// sealed layer depends on the head implementation; well-
    /// behaved implementations should arrange for either capture or
    /// loss to be observable (a write that is "lost" is silently
    /// dropped, not racy-half-applied).  See [`MutableHead::seal`]
    /// for the contract.
    pub fn write(&self, op: H::Op) {
        self.head.load_full().write(op);
    }

    /// Borrow the current head `Arc` for callers that want to batch
    /// many writes against a single head generation.
    ///
    /// Reduces atomic-load traffic relative to [`write`](Cascade::write)
    /// when the caller knows it is going to issue many writes in a
    /// row.  Returns a fresh `Arc` each call.
    #[must_use]
    pub fn head_for_writing(&self) -> Arc<H> {
        self.head.load_full()
    }

    /// Seal the current head into a fresh sealed layer, push it
    /// onto the sealed vector, and install a new empty head.
    ///
    /// The caller supplies `fresh_head`, a closure that constructs
    /// the new empty head.  This avoids a `Default` bound on `H`
    /// and lets implementations choose their initial capacity, RNG
    /// seed, etc.
    ///
    /// # Ordering
    ///
    /// The rotate stores the new sealed vector *before* installing
    /// the new head.  Between the two stores, readers can observe:
    ///
    /// - Old head **and** new sealed vector containing the freshly
    ///   sealed layer.  Both reference the same logical entries --
    ///   harmless duplication, the head shadows the sealed layer in
    ///   the cascade walk so the right value wins.
    ///
    /// After both stores complete, readers see the new (empty) head
    /// plus the sealed vector that contains the just-sealed
    /// snapshot of the old head, plus the tail.  No entry visible
    /// before the rotate becomes invisible during it.
    ///
    /// # Reclamation
    ///
    /// The old head's `Arc` is dropped by the slot after the swap.
    /// Any reader still holding it via a [`Snapshot`] keeps it
    /// alive; when the last snapshot drops, the old head drops too.
    /// This is the QSBR-style reclamation that bounds the
    /// "duplicate state in flight" window.
    pub fn rotate<F: FnOnce() -> H>(&self, fresh_head: F) {
        // 1. Load current head and seal a snapshot of it.
        let old_head = self.head.load_full();
        let new_sealed = Arc::new(old_head.seal());

        // 2. Build the new sealed vector with the freshly-sealed
        //    layer at the front (newest first).
        let current = self.sealed.load_full();
        let mut next: Vec<Arc<S>> = Vec::with_capacity(current.len() + 1);
        next.push(new_sealed);
        next.extend(current.iter().cloned());

        // 3. Install the new sealed vector FIRST.  This gives
        //    readers the duplicate-state window described above.
        self.sealed.store(Arc::new(next));

        // 4. Install the new (empty) head.
        self.head.store(Arc::new(fresh_head()));

        // The old head's Arc is now held only by readers (if any)
        // and by the local `old_head` binding, which drops here.
        drop(old_head);
    }

    /// Fuse the oldest sealed layers into the tail.
    ///
    /// Retains `keep` sealed layers at the front of the sealed
    /// vector (the newest ones) and folds the rest into a new tail
    /// via the [`MergeInto`] trait that `S` must implement against
    /// `T`.  Passing `keep = 0` collapses every sealed layer into
    /// the tail on each call; `keep = 1` keeps one buffer layer in
    /// front of the tail (matching the cascade-depth-of-two
    /// invariant we want for hot paths).
    ///
    /// The merge logic is encoded in `S::merge_into` rather than
    /// passed as a closure.  This makes the merge discoverable via
    /// `cargo doc`, consistent across all `compact` call sites for
    /// the same layer type, and shareable with the property-test
    /// harness once that lands.  Exact-match maps walk both layers
    /// and produce a merged `HashMap`; ACL compilation re-runs the
    /// full rule-set compile with the merged rule set as input;
    /// time-aware structures (rate limiters) can apply a decay
    /// function as part of the merge.
    ///
    /// # Ordering of merges
    ///
    /// The cascade folds *oldest-first*: the back of the sealed
    /// slice (the oldest layer) is merged into the old tail first,
    /// then progressively newer layers are merged onto the
    /// accumulating result.  This matches the cascade walk's
    /// "newer shadows older" semantic -- by the time we fold the
    /// newest sealed layer, it overlays everything that came before.
    ///
    /// # Ordering of installs
    ///
    /// The new tail is installed *before* the truncated sealed
    /// vector.  Between the two stores, readers see:
    ///
    /// - The new tail (which has the merged content), plus
    /// - The full old sealed vector (which still contains the
    ///   sealed layers we just merged).
    ///
    /// Those sealed layers shadow the tail in the cascade walk, so
    /// any entry they contain wins over the merged-tail version.
    /// Because the merge was faithful (`MergeInto` contract), the
    /// two agree on every key they share -- the duplicate state is
    /// harmless.
    ///
    /// Reverse ordering would briefly hide the to-be-merged sealed
    /// layers' entries (truncated sealed vec does not contain them;
    /// old tail does not contain them either), violating the
    /// cascade invariant.
    ///
    /// # Concurrency
    ///
    /// The cascade assumes a single-writer LSM-manager.  Concurrent
    /// calls to [`rotate`](Cascade::rotate) and `compact` race in
    /// ways that can lose entries.  Production deployments should
    /// drive both from one task; this is documented as a contract,
    /// not enforced by the type system, because the eventual
    /// LSM-manager wrapper will own that invariant explicitly.
    ///
    /// # Cost
    ///
    /// `merge_into` runs synchronously, once per sealed layer being
    /// folded in.  Cheap merges (exact-match maps) finish in
    /// microseconds; expensive ones (DPDK ACL rebuild) can take
    /// milliseconds.  The cascade does not throw the work onto a
    /// worker pool -- that is the LSM-manager's decision -- so the
    /// caller should arrange for `compact` to run on a thread that
    /// is free to block.
    ///
    /// For workloads where a batched single-pass merge would be
    /// substantially more efficient than the fold, an implementation
    /// can provide a higher-level operation alongside its layer
    /// types and bypass this default.  The cascade does not yet
    /// expose a batched-merge entry point; one will land when a
    /// consumer demonstrates the need.
    pub fn compact(&self, keep: usize)
    where
        S: MergeInto<T>,
    {
        let current = self.sealed.load_full();
        if current.len() <= keep {
            // Nothing to compact.
            return;
        }

        // Newest-first layout: indices 0..keep are the youngest
        // sealed layers we retain; keep..end are the older ones we
        // fold into the tail.
        let to_keep: &[Arc<S>] = &current[..keep];
        let to_merge: &[Arc<S>] = &current[keep..];

        let old_tail = self.tail.load_full();

        // Fold oldest-first.  `to_merge` is newest-first so we
        // iterate in reverse.  The let-else handles the
        // theoretically-impossible empty case (the early return at
        // the top of this function ensures to_merge is non-empty)
        // by no-op'ing rather than panicking, in case some
        // invariant changes later.
        let mut iter = to_merge.iter().rev();
        let Some(oldest) = iter.next() else {
            return;
        };
        let mut accumulator: T = oldest.merge_into(old_tail.as_ref());
        for sealed in iter {
            accumulator = sealed.merge_into(&accumulator);
        }

        // 1. Install the new tail.  Readers can now observe
        //    duplicate state between the still-present sealed
        //    layers and the merged tail.  Harmless: sealed wins
        //    against tail in the cascade walk and both agree.
        self.tail.store(Arc::new(accumulator));

        // 2. Truncate the sealed vector to drop the layers we just
        //    folded in.
        self.sealed.store(Arc::new(to_keep.to_vec()));

        // Old tail and the merged sealed layers drop here (modulo
        // any reader snapshots still holding them).
        drop(old_tail);
    }

    /// Current depth of the sealed vector.  Diagnostic.
    #[must_use]
    pub fn sealed_depth(&self) -> usize {
        self.sealed.load_full().len()
    }
}
