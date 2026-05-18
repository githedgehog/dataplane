// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Subscriber trait surface.
//!
//! The pipeline manager owns each per-NF [`Cascade`](cascade::Cascade)
//! and an ordered set of subscribers per cascade.  On every rotation
//! the manager delivers a [`DrainEvent`](cascade::DrainEvent) to each
//! subscriber via [`MatSubscriber::on_drain`].
//!
//! Subscribers that gate compaction (notably the hardware-offload
//! programmer) additionally implement [`WatermarkReporter`], which the
//! manager polls when computing `compact_through` watermarks.
//! Subscribers that do not implement [`WatermarkReporter`] are
//! ignored for compaction purposes -- they receive drain events
//! eagerly but never hold up reclamation.

use cascade::{Generation, Layer, MutableHead};

/// A consumer of cascade drain events.
///
/// Examples:
///
/// - Hardware-offload programmer (also implements [`WatermarkReporter`]).
/// - State-sync transport (does not gate compaction).
/// - `ip-monitor`-style telemetry emitter.
///
/// The manager invokes [`on_drain`](Self::on_drain) synchronously on
/// the manager's thread.  Implementors that do expensive work
/// (asic programming, network I/O, disk writes) should hand the
/// event off to an internal worker queue and return promptly.  The
/// `Arc<F>` inside the event is the only handle the subscriber
/// receives -- holding it indefinitely pins the layer in memory.
///
/// # Sync / Send
///
/// The bound is `Send + Sync` so subscribers can be held by the
/// manager (typically `Arc<dyn MatSubscriber<F>>`) and invoked from
/// whichever thread owns the rotation loop.
pub trait MatSubscriber<H, F>: Send + Sync
where
    H: MutableHead<Frozen = F>,
    F: Layer<Input = H::Input, Output = H::Output>,
{
    /// Called once per rotation with the freshly-frozen layer.
    ///
    /// The implementor receives the layer via the `Arc<F>` inside
    /// the [`DrainEvent`](cascade::DrainEvent).  Pointer-equal with
    /// the entry in [`Snapshot::frozen`](cascade::Snapshot::frozen).
    fn on_drain(&self, event: cascade::DrainEvent<F>);
}

/// Opt-in capability for subscribers that gate compaction.
///
/// The manager aggregates `current_watermark()` across all
/// implementors and supplies the minimum to
/// [`Cascade::compact_through`](cascade::Cascade::compact_through).
/// Subscribers that have not yet observed any drain (e.g. just
/// started, no rotations seen) should return `None`; the manager
/// treats that as "do not compact past anything this subscriber
/// might still care about."
///
/// `Send + Sync` for the same reason as [`MatSubscriber`].
pub trait WatermarkReporter: Send + Sync {
    /// The highest generation this subscriber has fully drained
    /// past.  Returning `Some(g)` permits the manager to compact
    /// frozen layers with `gen <= g` into the tail.  Returning
    /// `None` blocks compaction (no safe watermark yet).
    fn current_watermark(&self) -> Option<Generation>;
}
