// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The two ways into a wheel from other threads. Both are queues the owner drains on its next
//! sweep; cross-thread traffic is rare (cancellations, timers created off the owning thread), so a
//! short critical section per message is enough.

use crate::TimerId;
use concurrency::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub(crate) struct CancelQueue(Mutex<Vec<TimerId>>);

impl CancelQueue {
    /// Move everything queued into `into` (which must be empty, and keeps its capacity).
    pub(crate) fn take_into(&self, into: &mut Vec<TimerId>) {
        std::mem::swap(&mut *self.0.lock(), into);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }
}

#[derive(Debug)]
pub(crate) struct ScheduleQueue<P>(Mutex<Vec<P>>);

impl<P> Default for ScheduleQueue<P> {
    fn default() -> Self {
        Self(Mutex::new(Vec::new()))
    }
}

impl<P> ScheduleQueue<P> {
    pub(crate) fn take_into(&self, into: &mut Vec<P>) {
        std::mem::swap(&mut *self.0.lock(), into);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }
}

/// Cancels one timer, from any thread.
///
/// Cancelling queues the request for the owning wheel's next sweep, which hands the payload back as
/// [`Fired::Cancelled`](crate::Fired::Cancelled). Cancelling a timer that already fired or was
/// cancelled does nothing.
#[derive(Debug, Clone)]
pub struct TimerRef {
    queue: Arc<CancelQueue>,
    id: TimerId,
}

impl TimerRef {
    pub(crate) fn new(queue: Arc<CancelQueue>, id: TimerId) -> Self {
        Self { queue, id }
    }

    /// The timer this refers to.
    #[must_use]
    pub fn id(&self) -> TimerId {
        self.id
    }

    /// Ask the owning wheel to cancel this timer.
    pub fn cancel(&self) {
        self.queue.0.lock().push(self.id);
    }
}

/// Puts timers on a wheel from another thread.
///
/// The owning wheel adopts them on its next sweep; until then they are not on the wheel and cannot
/// fire. Each payload's [`Timer::bind`](crate::Timer::bind) runs on the owning thread when adopted.
#[derive(Debug)]
pub struct Remote<P>(Arc<ScheduleQueue<P>>);

impl<P> Clone for Remote<P> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<P> Default for Remote<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P> Remote<P> {
    /// A queue for a wheel that does not exist yet; see [`Wheel::with_remote`](crate::Wheel::with_remote).
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(ScheduleQueue::default()))
    }

    pub(crate) fn from_queue(queue: Arc<ScheduleQueue<P>>) -> Self {
        Self(queue)
    }

    pub(crate) fn queue(&self) -> &Arc<ScheduleQueue<P>> {
        &self.0
    }

    /// Queue `payload` for the owning wheel.
    pub fn schedule(&self, payload: P) {
        self.0.0.lock().push(payload);
    }
}
