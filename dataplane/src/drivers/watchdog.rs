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

    /// Task: record packets rx and tx
    pub fn record(&self, rx: u64, tx: u64, ppline_drops: u64, tx_drops: u64) {
        if rx > 0 {
            let _ = self
                .0
                .rx
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(rx))
                });
        }
        if tx > 0 {
            let _ = self
                .0
                .tx
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(tx))
                });
        }
        if ppline_drops > 0 {
            let _ = self
                .0
                .ppline_drops
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(ppline_drops))
                });
        }
        if tx_drops > 0 {
            let _ = self
                .0
                .tx_drops
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_add(tx_drops))
                });
        }
    }

    /// Supervisor: check the activity count of a watchdog (and zero it).
    /// If `check_and_rearm` is true, check if the watchdog was patted and
    /// re-arm it. The status is abstracted in [`Activity`]. If `check_and_rearm`
    /// is false, the watchdog check (and re-arm) is omitted, meaning that this
    /// method will never return `Activity::Stuck` in that case.
    #[must_use]
    pub fn check_and_clear(&self, check_and_rearm: bool) -> Activity {
        let record = ActivityRecord {
            rx: self.0.rx.swap(0, Ordering::Relaxed),
            tx: self.0.tx.swap(0, Ordering::Relaxed),
            ppline_drops: self.0.ppline_drops.swap(0, Ordering::Relaxed),
            tx_drops: self.0.tx_drops.swap(0, Ordering::Relaxed),
        };
        let patted = if check_and_rearm {
            !self.0.armed.swap(true, Ordering::Relaxed)
        } else {
            true // assume it was patted since we don't check/care
        };
        if record.rx > 0 {
            Activity::Active(record)
        } else if patted {
            Activity::Idle
        } else {
            debug_assert!(check_and_rearm);
            Activity::Stuck
        }
    }
}

/// The state of a [`Watchdog`] as observed by a supervisor when it checks it [`Watchdog::check_and_clear`].
#[derive(Clone)]
pub enum Activity {
    /// Watchdog was not patted
    Stuck,
    /// Watchdog was patted but task reported no work
    Idle,
    /// Task reported progress
    Active(ActivityRecord),
}

/// An activity record from a workers' rx task
#[derive(Debug, Clone)]
pub struct ActivityRecord {
    /// Pkts received
    pub rx: u64,
    /// Pkts successfully tx'ed
    pub tx: u64,
    /// Pkts received that the pipeline dropped
    pub ppline_drops: u64,
    /// Pkts received dropped on tx
    pub tx_drops: u64,
}

impl std::fmt::Display for Activity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(match self {
            Activity::Stuck => "Stuck!",
            Activity::Idle => "Idle",
            Activity::Active(_) => "Active",
        })
    }
}
