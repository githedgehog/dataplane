// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Liveness and activity watchdog for the drivers' rx tasks.
//!
//! Each rx task holds a [`Watchdog`] clone and reports on it: [`Watchdog::pat`]
//! as evidence that its loop was scheduled, [`Watchdog::record`] for the packets
//! it moved. The driver's supervisor consumes both with
//! [`Watchdog::check_and_clear`].

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// The actual state of a `Watchdog`, shared by supervisor and a rx task.
/// The supervisor arms the `Watchdog`. The rx task pats it and updates the
/// stats. The stats/armed flag are flushed when read by the supervisor.
/// So, all of the state in a `Watchdog` is somewhat ephemeral.
#[derive(Default)]
struct WatchdogInner {
    armed: AtomicBool,       // false => watchdog was patted
    rx: AtomicU64,           // number of packets received by task
    tx: AtomicU64,           // number of packets sent by task
    ppline_drops: AtomicU64, // number of packets dropped by task pipeline
    tx_drops: AtomicU64,     // number of tx failures
    parse_errors: AtomicU64, // number of frames we failed to parse
    truncated: AtomicU64,    // number of frames larger than the rx buffer
    zero_len: AtomicU64,     // number of zero-length reads
    kernel_drops: AtomicU64, // number of frames the kernel dropped on the socket
}

/// A lock-free liveness + activity watchdog.
#[derive(Clone, Default)]
pub struct Watchdog(Arc<WatchdogInner>);

impl Watchdog {
    /// Create a new [`Watchdog`] in the "patted, idle" state
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Task: clear the liveness flag, providing evidence the loop was scheduled.
    pub fn pat(&self) {
        self.0.armed.store(false, Ordering::Relaxed);
    }

    /// Task: record the counters for a batch
    pub fn record(&self, counters: &RxCounters) {
        accumulate(&self.0.rx, counters.rx);
        accumulate(&self.0.tx, counters.tx);
        accumulate(&self.0.ppline_drops, counters.ppline_drops);
        accumulate(&self.0.tx_drops, counters.tx_drops);
        accumulate(&self.0.parse_errors, counters.parse_errors);
        accumulate(&self.0.truncated, counters.truncated);
        accumulate(&self.0.zero_len, counters.zero_len);
        accumulate(&self.0.kernel_drops, counters.kernel_drops);
    }

    /// Supervisor: read the counters of a watchdog (and zero them), along with the
    /// activity they denote. If `check_and_rearm` is true, check if the watchdog was
    /// patted and re-arm it. If it is false, the watchdog check (and re-arm) is
    /// omitted, meaning that this method will never return `Activity::Stuck` in that
    /// case.
    #[must_use]
    pub fn check_and_clear(&self, check_and_rearm: bool) -> (RxCounters, Activity) {
        let counters = RxCounters {
            rx: self.0.rx.swap(0, Ordering::Relaxed),
            tx: self.0.tx.swap(0, Ordering::Relaxed),
            ppline_drops: self.0.ppline_drops.swap(0, Ordering::Relaxed),
            tx_drops: self.0.tx_drops.swap(0, Ordering::Relaxed),
            parse_errors: self.0.parse_errors.swap(0, Ordering::Relaxed),
            truncated: self.0.truncated.swap(0, Ordering::Relaxed),
            zero_len: self.0.zero_len.swap(0, Ordering::Relaxed),
            kernel_drops: self.0.kernel_drops.swap(0, Ordering::Relaxed),
        };
        let patted = if check_and_rearm {
            !self.0.armed.swap(true, Ordering::Relaxed)
        } else {
            true // assume it was patted since we don't check/care
        };
        let activity = if counters.saw_frames() {
            Activity::Active
        } else if patted {
            Activity::Idle
        } else {
            debug_assert!(check_and_rearm);
            Activity::Stuck
        };
        (counters, activity)
    }
}

/// Add `val` to `counter`, saturating instead of wrapping.
fn accumulate(counter: &AtomicU64, val: u64) {
    if val > 0 {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(val))
        });
    }
}

/// The state of a [`Watchdog`] as observed by a supervisor when it checks it [`Watchdog::check_and_clear`].
#[derive(Clone, Copy)]
pub enum Activity {
    /// Watchdog was not patted
    Stuck,
    /// Watchdog was patted but task reported no work
    Idle,
    /// Task reported progress
    Active,
}

/// The counters a worker's rx task reports on its [`Watchdog`], and that the
/// supervisor reads back from it.
#[derive(Debug, Clone, Copy, Default)]
pub struct RxCounters {
    /// Pkts received
    pub rx: u64,
    /// Pkts successfully tx'ed
    pub tx: u64,
    /// Pkts received that the pipeline dropped
    pub ppline_drops: u64,
    /// Pkts received dropped on tx
    pub tx_drops: u64,
    /// Frames received but that we failed to parse
    pub parse_errors: u64,
    /// Frames received but larger than the rx buffer
    pub truncated: u64,
    /// Zero-length reads on the socket
    pub zero_len: u64,
    /// Frames the kernel dropped on the socket before we could read them
    pub kernel_drops: u64,
}

impl RxCounters {
    /// Tell if the task saw any frame, including ones it could not make use of.
    /// Frames dropped by the kernel don't count: the task never saw them.
    #[must_use]
    pub fn saw_frames(&self) -> bool {
        self.rx > 0 || self.parse_errors > 0 || self.truncated > 0 || self.zero_len > 0
    }
}

impl std::fmt::Display for Activity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Activity::Stuck => "Stuck!",
            Activity::Idle => "Idle",
            Activity::Active => "Active",
        })
    }
}

#[cfg(test)]
mod test {
    use super::{Activity, RxCounters, Watchdog};

    /// A watchdog reports the counters it holds, whatever the activity it denotes.
    /// Anything it does not report is lost, since reading clears them.
    #[test]
    fn counters_are_reported_when_not_active() {
        // tx drops, but nothing received: this is not activity for the task
        let watchdog = Watchdog::new();
        watchdog.pat();
        watchdog.record(&RxCounters {
            tx_drops: 7,
            kernel_drops: 3,
            ..RxCounters::default()
        });

        let (counters, activity) = watchdog.check_and_clear(true);
        assert!(matches!(activity, Activity::Idle));
        assert_eq!(counters.tx_drops, 7);
        assert_eq!(counters.kernel_drops, 3);

        // same, for a task that failed to pat the watchdog
        watchdog.record(&RxCounters {
            ppline_drops: 5,
            ..RxCounters::default()
        });
        let (counters, activity) = watchdog.check_and_clear(true);
        assert!(matches!(activity, Activity::Stuck));
        assert_eq!(counters.ppline_drops, 5);
    }

    /// Reading the counters clears them.
    #[test]
    fn counters_are_cleared_when_read() {
        let watchdog = Watchdog::new();
        watchdog.record(&RxCounters {
            rx: 4,
            parse_errors: 2,
            ..RxCounters::default()
        });

        let (counters, _) = watchdog.check_and_clear(false);
        assert_eq!(counters.rx, 4);
        assert_eq!(counters.parse_errors, 2);

        let (counters, _) = watchdog.check_and_clear(false);
        assert_eq!(counters.rx, 0);
        assert_eq!(counters.parse_errors, 0);
    }

    /// Frames we could not parse mean the task is busy, not idle.
    #[test]
    fn parse_errors_count_as_activity() {
        let watchdog = Watchdog::new();
        watchdog.pat();
        watchdog.record(&RxCounters {
            parse_errors: 9,
            ..RxCounters::default()
        });

        let (counters, activity) = watchdog.check_and_clear(true);
        assert!(matches!(activity, Activity::Active));
        assert_eq!(counters.parse_errors, 9);
    }
}
