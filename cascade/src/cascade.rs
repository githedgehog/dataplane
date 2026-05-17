// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The cascade and its read-side snapshot.
//!
//! Wires a [`MutableHead`], a `Vec<Arc<Frozen>>` of intermediate
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
//! Generation rotation -- freezing the current head into a fresh
//! frozen layer and installing a new empty head -- is driven by
//! [`Cascade::rotate`].  Compaction (fusing old frozen layers into
//! the tail via [`MergeInto`]) is driven by [`Cascade::compact`].
//!
//! When the `subscribe` feature is enabled, each rotate also
//! publishes the freshly-frozen `Arc<F>` to subscribers via a
//! tokio broadcast channel; see [`Cascade::subscribe`].

use concurrency::slot::Slot;
use concurrency::sync::Arc;

use crate::head::MutableHead;
use crate::layer::{Layer, Outcome};
use crate::merge::MergeInto;

/// A coherent view of a cascade at a moment in time.
///
/// The snapshot holds an `Arc` to each of the head, frozen vector,
/// and tail.  As long as a snapshot exists, the cascade cannot
/// reclaim the underlying generations -- this is the QSBR-style
/// reader-extends-lifetime semantic that the [`concurrency`] crate's
/// reclamation primitives build on.
///
/// Readers should take a snapshot once per batch, classify many
/// packets against it, and drop it.  Holding a snapshot indefinitely
/// pins memory and prevents compaction.
pub struct Snapshot<H, F, T>
where
    H: MutableHead<Frozen = F>,
    F: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    head: Arc<H>,
    // TODO: there is a real case for making this
    // `Arc<ArrayVec<Arc<F>, N>>` under the theory that more than a
    // handful of layers is indicative of a break.  Saves a dynamic
    // allocation and an pointer load, and enforces a reasonable
    // constraint.  Could expose N as a const generic on Cascade.
    frozen: Arc<Vec<Arc<F>>>,
    tail: Arc<T>,
}

// TODO: I wonder if making Frozen an associated type on H by upper
// bounding H: MutableHead might help here.  That would remove F as
// a separate type parameter (it would only appear as H::Frozen in
// where-clauses).  Probably tractable; left for a follow-on.
impl<H, F, T> Snapshot<H, F, T>
where
    H: MutableHead<Frozen = F>,
    F: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    /// Walk the cascade and return the first definitive match.
    ///
    /// Order: head, then frozen layers newest-first, then tail.
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

        // Frozen layers, newest-first.  `frozen[0]` is the most
        // recently frozen head; `frozen[len-1]` is the oldest
        // frozen layer not yet compacted into the tail.
        for layer in self.frozen.iter() {
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
    // TODO: I'm wondering if this is a footgun.  Need to think
    // about it.
    #[must_use]
    pub fn head(&self) -> &H {
        &self.head
    }

    /// Number of frozen layers in this snapshot.
    #[must_use]
    pub fn frozen_depth(&self) -> usize {
        self.frozen.len()
    }

    /// Access the frozen-layer Arcs in this snapshot, newest-first.
    ///
    /// Returns a reference to the snapshot's internal vector; the
    /// borrow is tied to `&self`.  Consumers that want to retain
    /// individual frozen layers beyond the snapshot's lifetime
    /// should `Arc::clone` the entries they need.
    // TODO: do we want that to be pub?
    #[must_use]
    pub fn frozen(&self) -> &[Arc<F>] {
        &self.frozen
    }
}

/// Default capacity for the drain broadcast channel when the
/// `subscribe` feature is enabled.  Subscribers that consume drain
/// events slower than this many rotations behind get a
/// `RecvError::Lagged(n)` from the receiver and are expected to
/// react by resyncing from a fresh [`Snapshot`].
#[cfg(feature = "subscribe")]
const DEFAULT_DRAIN_CHANNEL_CAPACITY: usize = 16;

/// A cascade.
///
/// Owns the three publication slots and exposes the lifecycle
/// operations (snapshot, write, rotate, compact).  When the
/// `subscribe` feature is enabled, additionally publishes each
/// rotation's freshly-frozen layer to subscribers via a tokio
/// broadcast channel; see [`Cascade::subscribe`].
pub struct Cascade<H, F, T>
where
    H: MutableHead<Frozen = F>,
    F: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    head: Slot<H>,
    frozen: Slot<Vec<Arc<F>>>,
    tail: Slot<T>,
    /// Broadcast channel for drain events.  Each successful
    /// [`rotate`](Cascade::rotate) emits the freshly-frozen
    /// `Arc<F>` to all current subscribers.
    #[cfg(feature = "subscribe")]
    drain_sender: tokio::sync::broadcast::Sender<Arc<F>>,
}

impl<H, F, T> Cascade<H, F, T>
where
    H: MutableHead<Frozen = F>,
    F: Layer<Input = H::Input, Output = H::Output>,
    T: Layer<Input = H::Input, Output = H::Output>,
{
    /// Construct a cascade with the given initial head and tail
    /// and an empty frozen vector.
    ///
    /// When the `subscribe` feature is enabled, this also creates
    /// the drain broadcast channel with
    /// [`DEFAULT_DRAIN_CHANNEL_CAPACITY`] slots.  Use
    /// [`Cascade::with_drain_capacity`] to choose a different
    /// capacity.
    pub fn new(head: H, tail: T) -> Self {
        #[cfg(feature = "subscribe")]
        let (drain_sender, _) = tokio::sync::broadcast::channel(DEFAULT_DRAIN_CHANNEL_CAPACITY);
        Self {
            head: Slot::from_pointee(head),
            frozen: Slot::from_pointee(Vec::new()),
            tail: Slot::from_pointee(tail),
            #[cfg(feature = "subscribe")]
            drain_sender,
        }
    }

    /// Construct a cascade with an explicit drain broadcast
    /// channel capacity.
    ///
    /// Larger capacities let subscribers fall further behind
    /// before receiving `RecvError::Lagged`.  Smaller capacities
    /// keep memory usage lower at the cost of stricter
    /// subscriber pace requirements.  The default is
    /// [`DEFAULT_DRAIN_CHANNEL_CAPACITY`].
    #[cfg(feature = "subscribe")]
    pub fn with_drain_capacity(head: H, tail: T, capacity: usize) -> Self {
        let (drain_sender, _) = tokio::sync::broadcast::channel(capacity);
        Self {
            head: Slot::from_pointee(head),
            frozen: Slot::from_pointee(Vec::new()),
            tail: Slot::from_pointee(tail),
            drain_sender,
        }
    }

    /// Subscribe to drain events.
    ///
    /// Each successful [`rotate`](Cascade::rotate) sends the
    /// freshly-frozen `Arc<F>` to the returned receiver.  The
    /// receiver only sees drains that happen *after* the call to
    /// `subscribe` -- the broadcast channel does not backfill.
    /// Consumers that need both the current state and the future
    /// stream should call `subscribe` first, then [`snapshot`]
    /// -- a drain that lands between the two calls will appear in
    /// both, and consumers are responsible for tolerating that
    /// double-application (typically by ensuring their
    /// state-update is idempotent under repeated application of
    /// the same `Arc<F>`).
    ///
    /// # Lag
    ///
    /// If a subscriber consumes drain events slower than they are
    /// produced and falls more than `DEFAULT_DRAIN_CHANNEL_CAPACITY`
    /// (or the value passed to [`with_drain_capacity`]) behind,
    /// the next `recv` returns `RecvError::Lagged(skipped_count)`.
    /// The convention is for the subscriber to respond by
    /// resyncing from a fresh [`snapshot`](Cascade::snapshot) and
    /// resuming receive from the now-current position.
    ///
    /// # Discipline
    ///
    /// Subscribers are expected to take the `Arc<F>` from `recv`,
    /// promptly snapshot the layer's contents into private state,
    /// and drop the `Arc`.  The cascade's compactor reclaims old
    /// frozen layers by `Arc::try_unwrap` semantics indirectly --
    /// holding the `Arc` indefinitely keeps the layer alive and
    /// blocks reclamation.
    ///
    /// [`snapshot`]: Cascade::snapshot
    /// [`with_drain_capacity`]: Cascade::with_drain_capacity
    #[cfg(feature = "subscribe")]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Arc<F>> {
        self.drain_sender.subscribe()
    }

    /// Current number of subscribers.  Diagnostic.
    #[cfg(feature = "subscribe")]
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.drain_sender.receiver_count()
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
    pub fn snapshot(&self) -> Snapshot<H, F, T> {
        Snapshot {
            head: self.head.load_full(),
            frozen: self.frozen.load_full(),
            tail: self.tail.load_full(),
        }
    }

    /// Apply a write to the current head.
    ///
    /// Loads the current head `Arc` and forwards the op to its
    /// [`MutableHead::write`] impl.  Concurrent writes against the
    /// same key are resolved by the value type's
    /// [`Upsert`](crate::Upsert) implementation.
    ///
    /// If a [`rotate`](Cascade::rotate) is in progress when the
    /// load completes, the write may land on the about-to-be-frozen
    /// head.  Whether that write is captured in the resulting
    /// frozen layer depends on the head implementation; well-
    /// behaved implementations should arrange for either capture or
    /// loss to be observable (a write that is "lost" is silently
    /// dropped, not racy-half-applied).  See
    /// [`MutableHead::freeze`] for the contract.
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

    /// Freeze the current head into a fresh frozen layer, push it
    /// onto the frozen vector, and install a new empty head.
    ///
    /// The caller supplies `fresh_head`, a closure that constructs
    /// the new empty head.  This avoids a `Default` bound on `H`
    /// and lets implementations choose their initial capacity, RNG
    /// seed, etc.
    ///
    /// # Ordering
    ///
    /// The rotate stores the new frozen vector *before* installing
    /// the new head.  Between the two stores, readers can observe:
    ///
    /// - Old head **and** new frozen vector containing the freshly
    ///   frozen layer.  Both reference the same logical entries --
    ///   harmless duplication, the head shadows the frozen layer in
    ///   the cascade walk so the right value wins.
    ///
    /// After both stores complete, readers see the new (empty) head
    /// plus the frozen vector that contains the just-frozen
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
    pub fn rotate<MkH: FnOnce() -> H>(&self, fresh_head: MkH) {
        // 1. Load current head and freeze a snapshot of it.
        let old_head = self.head.load_full();
        let new_frozen = Arc::new(old_head.freeze());

        // Clone the new frozen Arc up front so we can emit it to
        // subscribers after the stores complete.  Cloning an Arc is
        // one atomic increment -- negligible relative to the freeze
        // and slot stores.
        #[cfg(feature = "subscribe")]
        let new_frozen_for_emit = Arc::clone(&new_frozen);

        // 2. Build the new frozen vector with the freshly-frozen
        //    layer at the front (newest first).
        let current = self.frozen.load_full();
        let mut next: Vec<Arc<F>> = Vec::with_capacity(current.len() + 1);
        next.push(new_frozen);
        next.extend(current.iter().cloned());

        // 3. Install the new frozen vector FIRST.  This gives
        //    readers the duplicate-state window described above.
        self.frozen.store(Arc::new(next));

        // 4. Install the new (empty) head.
        self.head.store(Arc::new(fresh_head()));

        // 5. Notify drain subscribers.  After both stores so
        //    subscribers can never observe state that the cascade
        //    itself does not observe.  `send` is non-blocking; an
        //    `Err` here just means there are no current subscribers
        //    (which is fine) or the channel is full (which means
        //    some subscriber is lagging and will see
        //    `RecvError::Lagged` on their next recv).
        #[cfg(feature = "subscribe")]
        {
            let _ = self.drain_sender.send(new_frozen_for_emit);
        }

        // The old head's Arc is now held only by readers (if any)
        // and by the local `old_head` binding, which drops here.
        drop(old_head);
    }

    /// Fuse the oldest frozen layers into the tail.
    ///
    /// Retains `keep` frozen layers at the front of the frozen
    /// vector (the newest ones) and folds the rest into a new tail
    /// via the [`MergeInto`] trait that `F` must implement against
    /// `T`.  Passing `keep = 0` collapses every frozen layer into
    /// the tail on each call; `keep = 1` keeps one buffer layer in
    /// front of the tail (matching the cascade-depth-of-two
    /// invariant we want for hot paths).
    ///
    /// The merge logic is encoded in `F::merge_into` rather than
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
    /// The cascade folds *oldest-first*: the back of the frozen
    /// slice (the oldest layer) is merged into the old tail first,
    /// then progressively newer layers are merged onto the
    /// accumulating result.  This matches the cascade walk's
    /// "newer shadows older" semantic -- by the time we fold the
    /// newest frozen layer, it overlays everything that came before.
    ///
    /// # Ordering of installs
    ///
    /// The new tail is installed *before* the truncated frozen
    /// vector.  Between the two stores, readers see:
    ///
    /// - The new tail (which has the merged content), plus
    /// - The full old frozen vector (which still contains the
    ///   frozen layers we just merged).
    ///
    /// Those frozen layers shadow the tail in the cascade walk, so
    /// any entry they contain wins over the merged-tail version.
    /// Because the merge was faithful (`MergeInto` contract), the
    /// two agree on every key they share -- the duplicate state is
    /// harmless.
    ///
    /// Reverse ordering would briefly hide the to-be-merged frozen
    /// layers' entries (truncated frozen vec does not contain them;
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
    /// `merge_into` runs synchronously, once per frozen layer being
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
        F: MergeInto<T>,
    {
        let current = self.frozen.load_full();
        if current.len() <= keep {
            // Nothing to compact.
            return;
        }

        // Newest-first layout: indices 0..keep are the youngest
        // frozen layers we retain; keep..end are the older ones we
        // fold into the tail.
        let to_keep: &[Arc<F>] = &current[..keep];
        let to_merge: &[Arc<F>] = &current[keep..];

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
        for frozen in iter {
            accumulator = frozen.merge_into(&accumulator);
        }

        // 1. Install the new tail.  Readers can now observe
        //    duplicate state between the still-present frozen
        //    layers and the merged tail.  Harmless: frozen shadows
        //    tail in the cascade walk and both agree.
        self.tail.store(Arc::new(accumulator));

        // 2. Truncate the frozen vector to drop the layers we just
        //    folded in.
        self.frozen.store(Arc::new(to_keep.to_vec()));

        // Old tail and the merged frozen layers drop here (modulo
        // any reader snapshots still holding them).
        drop(old_tail);
    }

    /// Current depth of the frozen vector.  Diagnostic.
    #[must_use]
    pub fn frozen_depth(&self) -> usize {
        self.frozen.load_full().len()
    }
}
