// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Liveness and activity watchdog for the drivers' rx tasks.
//!
//! Each rx task holds a [`Watchdog`] clone and reports on it: [`Watchdog::pat`]
//! as evidence that its loop was scheduled, [`Watchdog::record`] for the packets
//! it moved. The driver's supervisor checks the first with
//! [`Watchdog::check_and_rearm`]. The second are running totals, which nothing
//! but the task changes: anyone may read them, at any time, through a
//! [`Totals`].

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
/// The supervisor arms the `Watchdog` and the rx task pats it. The rx task
/// adds to the counters, which are totals since it started.
#[derive(Default)]
struct WatchdogInner {
    armed: AtomicBool,       // false => watchdog was patted
    rx: AtomicU64,           // number of packets received by task
    tx: AtomicU64,           // number of packets sent by task
    ppline_drops: AtomicU64, // number of packets dropped by task pipeline
    tx_drops: AtomicU64,     // number of tx failures
    punt_drops: AtomicU64,   // number of frames for the kernel that could not be punted
    parse_errors: AtomicU64, // number of frames we failed to parse
    truncated: AtomicU64,    // number of frames larger than the rx buffer
    csum_unknown: AtomicU64, // number of frames whose checksum status did not fit the control buffer
    zero_len: AtomicU64,     // number of zero-length reads
    kernel_drops: AtomicU64, // number of frames the kernel dropped on the socket
    injected: AtomicU64,     // number of frames from the kernel sent out of the port
    inject_drops: AtomicU64, // number of frames from the kernel that could not be sent
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
        accumulate(&self.0.punt_drops, counters.punt_drops);
        accumulate(&self.0.parse_errors, counters.parse_errors);
        accumulate(&self.0.truncated, counters.truncated);
        accumulate(&self.0.csum_unknown, counters.csum_unknown);
        accumulate(&self.0.zero_len, counters.zero_len);
        accumulate(&self.0.kernel_drops, counters.kernel_drops);
        accumulate(&self.0.injected, counters.injected);
        accumulate(&self.0.inject_drops, counters.inject_drops);
    }

    /// Supervisor: tell whether the task patted the watchdog since the last check, and re-arm it.
    #[must_use]
    pub fn check_and_rearm(&self) -> bool {
        !self.0.armed.swap(true, Ordering::Relaxed)
    }

    /// What the task counted since it started.
    #[must_use]
    pub fn totals(&self) -> RxCounters {
        self.0.totals()
    }

    /// A handle that reads the totals, and can do nothing else.
    #[must_use]
    pub fn reader(&self) -> Totals {
        Totals(self.0.clone())
    }
}

impl WatchdogInner {
    fn totals(&self) -> RxCounters {
        RxCounters {
            rx: self.rx.load(Ordering::Relaxed),
            tx: self.tx.load(Ordering::Relaxed),
            ppline_drops: self.ppline_drops.load(Ordering::Relaxed),
            tx_drops: self.tx_drops.load(Ordering::Relaxed),
            punt_drops: self.punt_drops.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            truncated: self.truncated.load(Ordering::Relaxed),
            csum_unknown: self.csum_unknown.load(Ordering::Relaxed),
            zero_len: self.zero_len.load(Ordering::Relaxed),
            kernel_drops: self.kernel_drops.load(Ordering::Relaxed),
            injected: self.injected.load(Ordering::Relaxed),
            inject_drops: self.inject_drops.load(Ordering::Relaxed),
        }
    }
}

/// What an rx task counted since it started, read from its [`Watchdog`] as it stands.
#[derive(Clone, Default)]
pub struct Totals(Arc<WatchdogInner>);

impl Totals {
    /// The totals as they stand.
    #[must_use]
    pub fn load(&self) -> RxCounters {
        self.0.totals()
    }
}

/// Add `val` to `counter`, saturating instead of wrapping.
fn accumulate(counter: &AtomicU64, val: u64) {
    if val > 0 {
        // std deprecates `fetch_update` in favour of `try_update` as of 1.99, but the
        // shuttle and loom atomics behind the concurrency facade only have `fetch_update`.
        #[allow(deprecated)]
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(val))
        });
    }
}

/// What an rx task was doing between two of the supervisor's checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RxCounters {
    /// Pkts received
    pub rx: u64,
    /// Pkts received that were tx'ed, on whichever port they left by
    pub tx: u64,
    /// Pkts received that the pipeline dropped
    pub ppline_drops: u64,
    /// Pkts received dropped on tx
    pub tx_drops: u64,
    /// Pkts the pipeline marked for the kernel that could not be punted to it
    pub punt_drops: u64,
    /// Frames received but that we failed to parse
    pub parse_errors: u64,
    /// Frames received but larger than the rx buffer
    pub truncated: u64,
    /// Frames with truncated control messages, treated as needing a transport checksum refresh
    pub csum_unknown: u64,
    /// Zero-length reads on the socket
    pub zero_len: u64,
    /// Frames the kernel dropped on the socket before we could read them
    pub kernel_drops: u64,
    /// Frames the kernel sent out of the port, which the task transmitted (DPDK driver)
    pub injected: u64,
    /// Frames the kernel sent out of the port that could not be transmitted (DPDK driver)
    pub inject_drops: u64,
}

impl RxCounters {
    /// Tell if the task saw any frame, including ones it could not make use of.
    /// Frames dropped by the kernel don't count: the task never saw them.
    #[must_use]
    pub fn saw_frames(&self) -> bool {
        self.rx > 0 || self.parse_errors > 0 || self.truncated > 0 || self.zero_len > 0
    }

    /// What was counted between `earlier` totals and these.
    #[must_use]
    pub fn since(&self, earlier: &RxCounters) -> RxCounters {
        RxCounters {
            rx: self.rx.saturating_sub(earlier.rx),
            tx: self.tx.saturating_sub(earlier.tx),
            ppline_drops: self.ppline_drops.saturating_sub(earlier.ppline_drops),
            tx_drops: self.tx_drops.saturating_sub(earlier.tx_drops),
            punt_drops: self.punt_drops.saturating_sub(earlier.punt_drops),
            parse_errors: self.parse_errors.saturating_sub(earlier.parse_errors),
            truncated: self.truncated.saturating_sub(earlier.truncated),
            csum_unknown: self.csum_unknown.saturating_sub(earlier.csum_unknown),
            zero_len: self.zero_len.saturating_sub(earlier.zero_len),
            kernel_drops: self.kernel_drops.saturating_sub(earlier.kernel_drops),
            injected: self.injected.saturating_sub(earlier.injected),
            inject_drops: self.inject_drops.saturating_sub(earlier.inject_drops),
        }
    }
}

impl Activity {
    /// What a task that counted `counted` over an interval was doing, given whether it patted its
    /// watchdog. A task that saw frames was busy, patted or not.
    #[must_use]
    pub fn of(counted: &RxCounters, patted: bool) -> Activity {
        if counted.saw_frames() {
            Activity::Active
        } else if patted {
            Activity::Idle
        } else {
            Activity::Stuck
        }
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

    /// Reading the totals leaves them be: whoever reads next, and however often, sees them all.
    #[test]
    fn totals_are_kept_when_read() {
        let watchdog = Watchdog::new();
        let reader = watchdog.reader();
        watchdog.record(&RxCounters {
            rx: 4,
            parse_errors: 2,
            ..RxCounters::default()
        });
        assert_eq!(watchdog.totals().rx, 4);
        assert_eq!(reader.load().rx, 4);

        watchdog.record(&RxCounters {
            rx: 1,
            kernel_drops: 3,
            ..RxCounters::default()
        });
        let totals = reader.load();
        assert_eq!(
            (totals.rx, totals.parse_errors, totals.kernel_drops),
            (5, 2, 3)
        );
    }

    /// What was counted between two readings is what was recorded between them, whatever it was.
    #[test]
    fn since_is_what_was_recorded_in_between() {
        bolero::check!()
            .with_type::<(Vec<[u32; 12]>, Vec<[u32; 12]>)>()
            .for_each(|(before, between)| {
                let counters = |c: &[u32; 12]| RxCounters {
                    rx: c[0].into(),
                    tx: c[1].into(),
                    ppline_drops: c[2].into(),
                    tx_drops: c[3].into(),
                    punt_drops: c[4].into(),
                    parse_errors: c[5].into(),
                    truncated: c[6].into(),
                    csum_unknown: c[7].into(),
                    zero_len: c[8].into(),
                    kernel_drops: c[9].into(),
                    injected: c[10].into(),
                    inject_drops: c[11].into(),
                };
                let watchdog = Watchdog::new();
                let expected = Watchdog::new();
                for batch in before {
                    watchdog.record(&counters(batch));
                }
                let earlier = watchdog.totals();
                for batch in between {
                    watchdog.record(&counters(batch));
                    expected.record(&counters(batch));
                }
                assert_eq!(watchdog.totals().since(&earlier), expected.totals());
            });
    }

    /// A pat is seen once: the check re-arms the watchdog for the next one.
    #[test]
    fn a_pat_is_seen_by_one_check() {
        let watchdog = Watchdog::new();
        watchdog.pat();
        assert!(watchdog.check_and_rearm());
        assert!(!watchdog.check_and_rearm());
    }

    /// Frames seen, those we could not parse included, mean the task is busy, whether it patted or
    /// not. Counts that are not frames seen -- drops on transmit, punt and in the kernel -- do not.
    #[test]
    fn activity_is_frames_seen_then_pats() {
        let busy = RxCounters {
            parse_errors: 9,
            ..RxCounters::default()
        };
        assert_eq!(Activity::of(&busy, true), Activity::Active);
        assert_eq!(Activity::of(&busy, false), Activity::Active);

        let not_busy = RxCounters {
            tx_drops: 7,
            punt_drops: 2,
            kernel_drops: 3,
            ..RxCounters::default()
        };
        assert_eq!(Activity::of(&not_busy, true), Activity::Idle);
        assert_eq!(Activity::of(&not_busy, false), Activity::Stuck);
    }
}
