// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow expiry on the timer wheel of the worker that created the flow.
//!
//! Every flow in the table has one timer on the wheel of the worker that inserted it. The timer
//! reads the flow's deadline when its bucket comes due, so refreshing a flow costs nothing here.
//! It hands the flow back when the deadline has passed, or when the flow was invalidated or
//! detached (which cancels the timer, from any thread). The worker then removes the flow from the
//! table, unless something else already did.

use super::table::FlowTable;
use concurrency::sync::Arc;
use net::flows::{FlowInfo, FlowStatus};
use std::time::Instant;
use timer_wheel::{Fired, Full, Sweep, Timer, TimerRef, Wheel, WheelConfig};
use tracing::error;

/// A flow's place on a wheel.
#[derive(Debug)]
pub(crate) struct FlowTimer(Arc<FlowInfo>);

impl Timer for FlowTimer {
    fn deadline(&self) -> Instant {
        self.0.expires_at()
    }

    fn bind(&self, timer: TimerRef) {
        self.0.bind_timer(timer);
    }
}

/// One worker's flow timers, and the flows they handed back that are still to be removed.
#[derive(Debug)]
pub(crate) struct FlowTimers {
    /// Created with the first timer, anchored at that moment. Not earlier: a handle may be made
    /// before the clock is readable (ahead of a paused test runtime, for one). Not at a deadline
    /// either: a timer due before the anchor would wait until the anchor.
    wheel: Option<Wheel<FlowTimer>>,
    fired: Vec<Fired<FlowTimer>>,
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
            fired: Vec::new(),
        }
    }

    /// Put a flow that was just inserted in the table on this wheel.
    pub(crate) fn schedule(&mut self, flow: &Arc<FlowInfo>) {
        let wheel = self
            .wheel
            .get_or_insert_with(|| Wheel::new(WheelConfig::standard(), clock::now()));
        if let Err((Full, timer)) = wheel.insert(FlowTimer(Arc::clone(flow))) {
            // The table's capacity is far below what a wheel holds; without a timer the flow would
            // never leave the table, so take it out of service instead.
            error!("flow timer wheel full: invalidating {}", timer.0.flowkey());
            timer.0.invalidate();
        }
    }

    /// The number of flows on this wheel.
    pub(crate) fn len(&self) -> usize {
        self.wheel.as_ref().map_or(0, Wheel::len)
    }

    /// Look at up to `budget` timers that are due or cancelled, and remove their flows from `table`.
    pub(crate) fn sweep(&mut self, table: &FlowTable, now: Instant, budget: usize) -> ExpirySweep {
        // Finish removing what an earlier pass could not before taking more off the wheel.
        let wheel = if !self.fired.is_empty() {
            Sweep {
                behind: true,
                ..Sweep::default()
            }
        } else if let Some(wheel) = self.wheel.as_mut() {
            wheel.sweep(now, budget, &mut self.fired)
        } else {
            Sweep::default()
        };
        let removed = table.remove_fired(&mut self.fired);
        ExpirySweep {
            wheel,
            removed,
            pending: self.fired.len(),
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
    pub(crate) fn remove_fired(&self, fired: &mut Vec<Fired<FlowTimer>>) -> usize {
        if fired.is_empty() {
            return 0;
        }
        let Some(table) = self.table.try_read() else {
            return 0;
        };
        let mut removed = 0;
        for fired in fired.drain(..) {
            let flow = match fired {
                Fired::Due(FlowTimer(flow)) => {
                    if flow.status() == FlowStatus::Active {
                        flow.update_status(FlowStatus::Expired);
                    }
                    flow
                }
                Fired::Cancelled(FlowTimer(flow)) => {
                    if flow.status() == FlowStatus::Active {
                        continue;
                    }
                    flow
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
