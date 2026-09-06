// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK's hierarchical scheduler (`rte_sched`), and active queue management
//! over its queues.
//!
//! [`Port`] wraps the scheduler: a tree of subports, pipes, traffic classes and
//! queues, shaped by token buckets and served by strict priority above weighted
//! round robin. Three AQMs sit alongside it:
//!
//! | | signal | where it decides | state |
//! |---|---|---|---|
//! | [`Red`] | queue depth, averaged | enqueue | DPDK's `rte_red` |
//! | [`Pie`] | queue delay, estimated from a drain rate | enqueue | DPDK's `rte_pie`, [and broken](Pie) |
//! | [`Codel`] | queue delay, measured per packet | dequeue | ours |
//!
//! [`Red`] and [`Pie`] are the two modes `rte_sched` will install for itself.
//! [`Codel`] cannot be one, because the sojourn time it works from is not known
//! until the packet leaves; it runs over the burst the scheduler hands back
//! instead. [`PortCodel`] is that arrangement.
//!
//! # These are not policers
//!
//! All three answer one question -- may this packet stay -- and none of them
//! owns a queue. [`Red`] is driven by the queue's current depth in packets,
//! [`Pie`] by how long the queue is taking to drain, and [`Codel`] by how long
//! each packet actually waited. Code with no queue has none of those inputs, so
//! none of these can run in a policer; a policer that wants probabilistic drop
//! has to derive it from something else, such as a token deficit. That is a
//! different algorithm wearing the same name.

mod codel;
mod pie;
mod port;
mod red;

#[cfg(test)]
mod sim;

pub use codel::{Backlog, Codel, CodelParams, CodelParamsError, Departure};
pub use pie::Pie;
pub use port::{
    BEST_EFFORT, BEST_EFFORT_QUEUES, Color, EnqueueStamp, InvalidQueuePath, PipeProfile, Port,
    PortCodel, PortCodelError, PortError, PortParams, QUEUES_PER_PIPE, QueuePath, QueueStats,
    Shaper, TRAFFIC_CLASSES,
};
pub use red::{Red, RedConfigError};

/// What an AQM decided about one arriving packet.
///
/// This is the enqueue-side verdict, which is the only shape [`Red`] and
/// [`Pie`] have. [`Codel`] decides at dequeue and answers with a
/// [`Departure`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The packet may join the queue.
    Enqueue,
    /// Dropped because the queue is at or above its hard threshold. This is the
    /// tail drop the AQM exists to avoid, so a run dominated by these verdicts
    /// means the AQM is not configured to bite before the queue fills.
    DropThreshold,
    /// Dropped by the probabilistic rule, with room still left in the queue.
    /// This is the AQM doing its job: signalling congestion early, to one flow
    /// at a time, instead of to everything at once when the queue overflows.
    DropProbability,
}

impl Verdict {
    /// Whether the packet was dropped, whatever the reason.
    #[must_use]
    pub fn is_drop(self) -> bool {
        !matches!(self, Verdict::Enqueue)
    }
}
