// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow expiry on the timer wheel of the worker that created the flow.
//!
//! Every flow in the table has one timer on the wheel of the worker that inserted it. The timer
//! reads the flow's deadline when its bucket comes due, so refreshing a flow costs nothing here.
//! It hands the flow back when the deadline has passed, or when the flow was invalidated or
//! detached (which cancels the timer, from any thread). The worker then removes the flow from the
//! table, unless something else already did.
//!
//! The same wheel keeps [`SideTimer`]s: timers for state that lives beside the flows (NAT mappings,
//! for one), owned by the worker like the flows are.

use super::table::FlowTable;
use concurrency::sync::atomic::{AtomicUsize, Ordering};
use concurrency::sync::{Arc, Mutex};
use net::flows::{FlowInfo, FlowStatus};
use std::fmt::{self, Debug};
use std::time::Instant;
use timer_wheel::{Fired, Full, Remote, Sweep, Timer, TimerRef, Wheel, WheelConfig};
use tracing::error;

/// A timer kept on a worker's wheel beside its flows.
///
/// Like a flow's, its deadline is read when its bucket comes due, so it may move later at any time
/// without touching the wheel.
pub trait SideTimer: Send {
    /// When this timer is due.
    fn deadline(&self) -> Instant;

    /// Called each time the timer is put on a wheel, with the handle that cancels it from any
    /// thread.
    fn bind(&self, timer: TimerRef) {
        let _ = timer;
    }

    /// The deadline has passed (as of `now`). Return `true` to stay on the wheel, to be looked at
    /// again at [`SideTimer::deadline`]; `false` when done.
    fn fire(&mut self, now: Instant) -> bool;
}

/// Puts [`SideTimer`]s on a worker's wheel.
pub trait Schedule {
    /// Put `timer` on a wheel. It is owned by that wheel's worker from then on.
    fn schedule(&self, timer: Box<dyn SideTimer>);
}

/// What a worker's wheel holds.
pub enum WorkerTimer {
    /// A flow in the table.
    Flow(Arc<FlowInfo>),
    /// Anything else.
    Side(Box<dyn SideTimer>),
}

impl Debug for WorkerTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flow(flow) => f.debug_tuple("Flow").field(flow.flowkey()).finish(),
            Self::Side(timer) => f.debug_tuple("Side").field(&timer.deadline()).finish(),
        }
    }
}

impl Timer for WorkerTimer {
    fn deadline(&self) -> Instant {
        match self {
            Self::Flow(flow) => flow.expires_at(),
            Self::Side(timer) => timer.deadline(),
        }
    }

    fn bind(&self, timer: TimerRef) {
        match self {
            Self::Flow(flow) => flow.bind_timer(timer),
            Self::Side(side) => side.bind(timer),
        }
    }
}

/// One worker's timers, and the flows they handed back that are still to be removed.
#[derive(Debug)]
pub(crate) struct FlowTimers {
    /// Created when first needed, anchored at that moment. Not earlier: a handle may be made
    /// before the clock is readable (ahead of a paused test runtime, for one). Not at a deadline
    /// either: a timer due before the anchor would wait until the anchor.
    wheel: Option<Wheel<WorkerTimer>>,
    /// Where other threads queue timers for this wheel; exists before the wheel does.
    remote: Remote<WorkerTimer>,
    fired: Vec<Fired<WorkerTimer>>,
}

/// What one expiry pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExpirySweep {
    /// What the wheel did.
    pub wheel: Sweep,
    /// Flows removed from the table.
    pub removed: usize,
    /// Flows handed back by the wheel but not yet removed, because the table was busy (being
    /// resharded or admitting a pair); they are removed on a later pass.
    pub pending: usize,
}

impl ExpirySweep {
    /// Whether there is expiry work left over for the next pass.
    #[must_use]
    pub fn behind(&self) -> bool {
        self.wheel.behind || self.pending > 0
    }
}

impl FlowTimers {
    pub(crate) fn new() -> Self {
        Self {
            wheel: None,
            remote: Remote::new(),
            fired: Vec::new(),
        }
    }

    pub(crate) fn remote(&self) -> Remote<WorkerTimer> {
        self.remote.clone()
    }

    fn wheel(&mut self, now: impl FnOnce() -> Instant) -> &mut Wheel<WorkerTimer> {
        let remote = &self.remote;
        self.wheel
            .get_or_insert_with(|| Wheel::with_remote(WheelConfig::standard(), now(), remote))
    }

    /// Put a timer on this worker's wheel.
    pub(crate) fn insert(&mut self, timer: WorkerTimer) {
        if let Err((Full, timer)) = self.wheel(clock::now).insert(timer) {
            // The table's capacity is far below what a wheel holds. A flow without a timer would
            // never leave the table, so take it out of service instead.
            error!("worker timer wheel full: dropping {timer:?}");
            if let WorkerTimer::Flow(flow) = timer {
                flow.invalidate();
            }
        }
    }

    /// Put a flow that was just inserted in the table on this wheel.
    pub(crate) fn schedule(&mut self, flow: &Arc<FlowInfo>) {
        self.insert(WorkerTimer::Flow(Arc::clone(flow)));
    }

    /// The number of timers on this wheel.
    pub(crate) fn len(&self) -> usize {
        self.wheel.as_ref().map_or(0, Wheel::len)
    }

    /// Look at up to `budget` timers that are due or cancelled; remove the flows from `table` and
    /// fire the side timers.
    ///
    /// Flows go first, so that a side timer due in the same pass sees what they let go of (a
    /// masquerade mapping's reaper, the flows' holds on the mapping).
    pub(crate) fn sweep(&mut self, table: &FlowTable, now: Instant, budget: usize) -> ExpirySweep {
        // Finish removing what an earlier pass could not before taking more off the wheel.
        let mut side = Vec::new();
        let wheel = if self.fired.is_empty() {
            let mut fired = Vec::new();
            let sweep = self.wheel(|| now).sweep(now, budget, &mut fired);
            for fired in fired {
                match fired {
                    Fired::Due(WorkerTimer::Side(timer)) => side.push(timer),
                    Fired::Cancelled(WorkerTimer::Side(_)) => {}
                    flow => self.fired.push(flow),
                }
            }
            sweep
        } else {
            Sweep {
                behind: true,
                ..Sweep::default()
            }
        };
        let removed = table.remove_fired(&mut self.fired);
        self.fire_side_timers(side, now);
        ExpirySweep {
            wheel,
            removed,
            pending: self.fired.len(),
        }
    }

    /// Fire the side timers that are due, putting back those that stay.
    fn fire_side_timers(&mut self, due: Vec<Box<dyn SideTimer>>, now: Instant) {
        for mut timer in due {
            if timer.fire(now) {
                self.insert(WorkerTimer::Side(timer));
            }
        }
    }
}

impl FlowTable {
    /// Remove the flows that `fired` hands back. Leaves `fired` as it is if the table is busy.
    ///
    /// - A detached flow is no longer in the table: nothing to do.
    /// - A due flow that is still active has expired: mark it so, then remove it.
    /// - A cancelled flow was invalidated: remove it. A cancelled flow that is still active lost its
    ///   timer to a newer one (it was inserted again): leave it to the newer timer.
    ///
    /// Removal checks identity, so a different flow inserted under the same key since is left alone.
    pub(crate) fn remove_fired(&self, fired: &mut Vec<Fired<WorkerTimer>>) -> usize {
        if fired.is_empty() {
            return 0;
        }
        let Some(table) = self.table.try_read() else {
            return 0;
        };
        let mut removed = 0;
        for fired in fired.drain(..) {
            let flow = match fired {
                Fired::Due(WorkerTimer::Flow(flow)) => {
                    if flow.status() == FlowStatus::Active {
                        flow.update_status(FlowStatus::Expired);
                    }
                    flow
                }
                Fired::Cancelled(WorkerTimer::Flow(flow)) => {
                    if flow.status() == FlowStatus::Active {
                        continue;
                    }
                    flow
                }
                // The sweep keeps side timers for itself.
                Fired::Due(WorkerTimer::Side(_)) | Fired::Cancelled(WorkerTimer::Side(_)) => {
                    continue;
                }
            };
            if flow.status() == FlowStatus::Detached {
                continue;
            }
            if table
                .remove_if(flow.flowkey(), |_, held| Arc::ptr_eq(held, &flow))
                .is_some()
            {
                self.live_removed();
                removed += 1;
            }
        }
        removed
    }
}

/// Every worker's timer queue, for scheduling [`SideTimer`]s from threads that have no wheel (the
/// control plane applying a configuration, for one).
///
/// Workers register as they make their [`WorkerFlowTable`](super::WorkerFlowTable). Timers
/// scheduled before any worker registered are parked, and go to the first one.
#[derive(Debug, Clone, Default)]
pub struct TimerRegistry(Arc<Registry>);

#[derive(Debug, Default)]
struct Registry {
    workers: Mutex<Workers>,
    next: AtomicUsize,
}

#[derive(Default)]
struct Workers {
    remotes: Vec<Remote<WorkerTimer>>,
    parked: Vec<WorkerTimer>,
}

impl Debug for Workers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Workers")
            .field("remotes", &self.remotes.len())
            .field("parked", &self.parked.len())
            .finish()
    }
}

impl TimerRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn register(&self, remote: Remote<WorkerTimer>) {
        let mut workers = self.0.workers.lock();
        for timer in workers.parked.drain(..) {
            remote.schedule(timer);
        }
        workers.remotes.push(remote);
    }

    /// The number of workers registered.
    #[must_use]
    pub fn workers(&self) -> usize {
        self.0.workers.lock().remotes.len()
    }

    /// The number of timers waiting for a worker to register.
    #[must_use]
    pub fn parked(&self) -> usize {
        self.0.workers.lock().parked.len()
    }
}

impl Schedule for TimerRegistry {
    /// Queue `timer` for one of the registered workers, in turn.
    fn schedule(&self, timer: Box<dyn SideTimer>) {
        let mut workers = self.0.workers.lock();
        if workers.remotes.is_empty() {
            workers.parked.push(WorkerTimer::Side(timer));
            return;
        }
        let next = self.0.next.fetch_add(1, Ordering::Relaxed) % workers.remotes.len();
        workers.remotes[next].schedule(WorkerTimer::Side(timer));
    }
}
