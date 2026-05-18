// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Thin wrapper that bundles a [`Cascade`] with the subscriber
//! registry and watermark aggregation logic the pipeline manager
//! cares about.
//!
//! Each NF in the pipeline owns one [`ManagedCascade`] (or the
//! deployment-specific manager struct does, on its behalf).  The
//! managed cascade:
//!
//! - Drives [`Cascade::rotate`] with a manager-supplied
//!   [`Generation`].
//! - On every rotation, synchronously fans the resulting
//!   [`DrainEvent`] out to every registered
//!   [`MatSubscriber`].
//! - Aggregates [`WatermarkReporter::current_watermark`] reports to
//!   produce a safe compaction watermark and drives
//!   [`Cascade::compact_through`] with it.
//!
//! The cascade itself is private to the wrapper -- consumers
//! interact through [`ManagedCascade::write`],
//! [`ManagedCascade::rotate`], [`ManagedCascade::snapshot`], and
//! [`ManagedCascade::compact_to_aggregated_watermark`].  Hiding the
//! cascade prevents bypass of subscriber fan-out.

use cascade::{Cascade, DrainEvent, Generation, Layer, MergeInto, MutableHead, Snapshot};
use concurrency::sync::{Arc, Mutex};
use mat::{MatSubscriber, WatermarkReporter};

/// Closure type used by [`ManagedCascade`] to construct a fresh
/// empty head on each rotation.
///
/// Boxed and stored at construction so [`ManagedCascade::rotate`]
/// does not need a closure argument per call.
pub type HeadFactory<H> = Box<dyn Fn() -> H + Send + Sync>;

/// A cascade with attached subscribers and watermark aggregation.
///
/// See the module documentation for the design.
pub struct ManagedCascade<H, F, T>
where
    H: MutableHead<Frozen = F> + 'static,
    F: Layer<Input = H::Input, Output = H::Output> + 'static,
    T: Layer<Input = H::Input, Output = H::Output> + 'static,
{
    cascade: Cascade<H, F, T>,
    mk_head: HeadFactory<H>,
    subscribers: Mutex<Vec<Arc<dyn MatSubscriber<H, F>>>>,
    watermark_reporters: Mutex<Vec<Arc<dyn WatermarkReporter>>>,
}

impl<H, F, T> ManagedCascade<H, F, T>
where
    H: MutableHead<Frozen = F> + 'static,
    F: Layer<Input = H::Input, Output = H::Output> + 'static,
    T: Layer<Input = H::Input, Output = H::Output> + 'static,
{
    /// Construct a new managed cascade.
    ///
    /// `mk_head` is invoked on every rotation to produce a fresh
    /// empty head.  Storing it here (rather than threading it
    /// through every `rotate` call) keeps the per-NF rotation site
    /// in the manager terse.
    pub fn new(head: H, tail: T, mk_head: HeadFactory<H>) -> Self {
        Self {
            cascade: Cascade::new(head, tail),
            mk_head,
            subscribers: Mutex::new(Vec::new()),
            watermark_reporters: Mutex::new(Vec::new()),
        }
    }

    /// Register a subscriber.
    ///
    /// Subscribers receive [`DrainEvent`]s on every subsequent
    /// rotation.  Past rotations are NOT replayed -- this matches
    /// the cascade's broadcast-channel semantics for subscribers
    /// that registered after a drain.  Subscribers that need
    /// initial state should snapshot the cascade themselves before
    /// or shortly after registering.
    pub fn add_subscriber(&self, sub: Arc<dyn MatSubscriber<H, F>>) {
        let mut subs = self.subscribers.lock();
        subs.push(sub);
    }

    /// Register a watermark reporter.
    ///
    /// On every [`compact_to_aggregated_watermark`](Self::compact_to_aggregated_watermark)
    /// the manager aggregates reports across all registered
    /// reporters and uses the minimum as the safe watermark.
    pub fn add_watermark_reporter(&self, reporter: Arc<dyn WatermarkReporter>) {
        let mut reporters = self.watermark_reporters.lock();
        reporters.push(reporter);
    }

    /// Apply a write to the cascade head.  Pass-through.
    pub fn write(&self, op: H::Op) {
        self.cascade.write(op);
    }

    /// Snapshot the cascade.  Pass-through.
    pub fn snapshot(&self) -> Snapshot<H, F, T> {
        self.cascade.snapshot()
    }

    /// Rotate the cascade with the supplied [`Generation`] and
    /// synchronously fan the resulting [`DrainEvent`] out to every
    /// subscriber.
    ///
    /// Subscriber invocation order is registration order.  Each
    /// invocation receives the same `Arc<F>` (pointer-equal), so
    /// holding the Arc in any one subscriber pins the layer for
    /// all readers.
    pub fn rotate(&self, generation: Generation) {
        self.cascade.rotate(generation, &self.mk_head);

        // Capture the newly-frozen entry to build the DrainEvent
        // for subscribers.  Snapshot is cheap -- three Arc clones.
        let snap = self.cascade.snapshot();
        let Some(front) = snap.frozen().first() else {
            // Defensive: cascade.rotate just pushed an entry; the
            // frozen vec cannot be empty.  Silently no-op if
            // somehow it is rather than panicking.
            return;
        };

        let event = DrainEvent {
            generation: front.generation,
            layer: Arc::clone(&front.layer),
        };

        let subs = self.subscribers.lock();
        for sub in subs.iter() {
            sub.on_drain(event.clone());
        }
    }

    /// Compute the minimum watermark across all registered
    /// reporters and call [`Cascade::compact_through`] with it.
    ///
    /// Returns the watermark that was actually used, or `None` if
    /// no compaction was performed -- either there are no
    /// reporters or some reporter returned `None`
    /// (`current_watermark`) and the manager conservatively
    /// declines to compact.
    pub fn compact_to_aggregated_watermark(&self) -> Option<Generation>
    where
        F: MergeInto<T>,
    {
        let reporters = self.watermark_reporters.lock();
        if reporters.is_empty() {
            return None;
        }

        let mut min: Option<Generation> = None;
        for r in reporters.iter() {
            let g = r.current_watermark()?;
            min = Some(match min {
                Some(m) if m < g => m,
                _ => g,
            });
        }

        if let Some(g) = min {
            self.cascade.compact_through(g);
        }
        min
    }

    /// Depth-based compaction.  Pass-through to
    /// [`Cascade::compact`](cascade::Cascade::compact).  Useful for
    /// callers that do not need per-packet consistency (telemetry-
    /// only cascades, tests).
    pub fn compact(&self, keep: usize)
    where
        F: MergeInto<T>,
    {
        self.cascade.compact(keep);
    }

    /// Diagnostic: current frozen-chain depth.
    #[must_use]
    pub fn frozen_depth(&self) -> usize {
        self.cascade.frozen_depth()
    }

    /// Diagnostic: number of registered subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.lock().len()
    }

    /// Diagnostic: number of registered watermark reporters.
    #[must_use]
    pub fn watermark_reporter_count(&self) -> usize {
        self.watermark_reporters.lock().len()
    }
}
