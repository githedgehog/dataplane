// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What a polling worker spends its time on, and how it idles.
//!
//! [`LoadMeter`] times each pass of a worker's loop and adds the time to what the pass was
//! [`Spent`] on. The worker flushes it to the [`Load`] it shares with the supervisor and
//! telemetry; [`stats::WorkerLoadMetrics`] says how to read it. Only the DPDK driver's workers
//! poll, so only they have a [`Load`].

use std::time::Instant;

use args::IdleMode;
use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicU8, AtomicU64, Ordering};

/// What one pass of a worker's loop was spent on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spent {
    /// Receiving, processing, transmitting, or expiring flows.
    Busy,
    /// Polling and finding nothing, spinning or yielding the CPU.
    Polling,
    /// Asleep in a low-power monitor wait (or, for a worker without receive queues, a timed
    /// sleep), after polling and finding nothing.
    Monitor,
    /// Asleep in the kernel until a receive interrupt or a doorbell, after polling and finding
    /// nothing.
    Interrupt,
}

impl Spent {
    /// Every state, in the order [`LoadTotals::time`] indexes them.
    pub const ALL: [Spent; 4] = [
        Spent::Busy,
        Spent::Polling,
        Spent::Monitor,
        Spent::Interrupt,
    ];

    /// Its name, as telemetry labels it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Spent::Busy => "busy",
            Spent::Polling => "polling",
            Spent::Monitor => "monitor",
            Spent::Interrupt => "interrupt",
        }
    }
}

/// A worker's time and sleeps since it started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadTotals {
    /// Nanoseconds spent in each state, indexed as [`Spent::ALL`].
    pub time: [u64; 4],
    /// Low-power monitor waits (and timed sleeps) the worker went into.
    pub monitor_sleeps: u64,
    /// Sleeps on interrupts the worker went into.
    pub interrupt_sleeps: u64,
    /// Flows the worker's timer wheel expired and removed from the table.
    pub expired_flows: u64,
    /// Expiry passes that ended with work left over for the next one.
    pub expiry_behind: u64,
}

impl LoadTotals {
    /// Nanoseconds spent `spent`.
    #[must_use]
    pub fn nanos(&self, spent: Spent) -> u64 {
        self.time[spent as usize]
    }

    /// What was spent between `earlier` totals and these.
    #[must_use]
    pub fn since(&self, earlier: &LoadTotals) -> LoadTotals {
        LoadTotals {
            time: std::array::from_fn(|i| self.time[i].saturating_sub(earlier.time[i])),
            monitor_sleeps: self.monitor_sleeps.saturating_sub(earlier.monitor_sleeps),
            interrupt_sleeps: self
                .interrupt_sleeps
                .saturating_sub(earlier.interrupt_sleeps),
            expired_flows: self.expired_flows.saturating_sub(earlier.expired_flows),
            expiry_behind: self.expiry_behind.saturating_sub(earlier.expiry_behind),
        }
    }

    /// The share of the time these totals cover that was spent `spent`; zero if they cover none.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // a share, not a count
    pub fn share(&self, spent: Spent) -> f64 {
        let total: u64 = self.time.iter().sum();
        if total == 0 {
            0.0
        } else {
            self.nanos(spent) as f64 / total as f64
        }
    }
}

#[derive(Default)]
struct LoadInner {
    time: [AtomicU64; 4],
    monitor_sleeps: AtomicU64,
    interrupt_sleeps: AtomicU64,
    expired_flows: AtomicU64,
    expiry_behind: AtomicU64,
    /// The idle mode the worker was configured with, as `IdleMode`'s discriminant.
    configured: AtomicU8,
    /// The idle mode the worker idles in now, which is weaker than the configured one if a queue
    /// lacks interrupts, the CPU has no monitor wait, or a sleep failed.
    effective: AtomicU8,
}

/// A worker's load, shared by the worker, which writes it, and its readers.
#[derive(Clone, Default)]
pub struct Load(Arc<LoadInner>);

impl Load {
    /// A load for a worker configured to idle in `mode`, which it does until it says otherwise.
    #[must_use]
    pub fn new(mode: IdleMode) -> Load {
        let load = Load::default();
        load.0.configured.store(mode as u8, Ordering::Relaxed);
        load.0.effective.store(mode as u8, Ordering::Relaxed);
        load
    }

    /// A handle that reads the load, and can do nothing else.
    #[must_use]
    pub fn reader(&self) -> LoadReader {
        LoadReader(self.0.clone())
    }

    /// Worker: add what the meter measured since the last flush, and set the effective mode.
    fn record(&self, meter: &LoadMeter, effective: IdleMode) {
        for (total, spent) in self.0.time.iter().zip(meter.time) {
            total.fetch_add(spent, Ordering::Relaxed);
        }
        self.0
            .monitor_sleeps
            .fetch_add(meter.monitor_sleeps, Ordering::Relaxed);
        self.0
            .interrupt_sleeps
            .fetch_add(meter.interrupt_sleeps, Ordering::Relaxed);
        self.0
            .expired_flows
            .fetch_add(meter.expired_flows, Ordering::Relaxed);
        self.0
            .expiry_behind
            .fetch_add(meter.expiry_behind, Ordering::Relaxed);
        self.0.effective.store(effective as u8, Ordering::Relaxed);
    }
}

/// Reads a worker's [`Load`].
#[derive(Clone)]
pub struct LoadReader(Arc<LoadInner>);

impl LoadReader {
    /// The totals as they stand, as of the worker's last flush.
    #[must_use]
    pub fn load(&self) -> LoadTotals {
        LoadTotals {
            time: std::array::from_fn(|i| self.0.time[i].load(Ordering::Relaxed)),
            monitor_sleeps: self.0.monitor_sleeps.load(Ordering::Relaxed),
            interrupt_sleeps: self.0.interrupt_sleeps.load(Ordering::Relaxed),
            expired_flows: self.0.expired_flows.load(Ordering::Relaxed),
            expiry_behind: self.0.expiry_behind.load(Ordering::Relaxed),
        }
    }

    /// The idle mode the worker was configured with.
    #[must_use]
    pub fn configured(&self) -> IdleMode {
        mode(self.0.configured.load(Ordering::Relaxed))
    }

    /// The idle mode the worker idles in now.
    #[must_use]
    pub fn effective(&self) -> IdleMode {
        mode(self.0.effective.load(Ordering::Relaxed))
    }
}

/// The mode with discriminant `value`.
fn mode(value: u8) -> IdleMode {
    [IdleMode::Poll, IdleMode::Monitor, IdleMode::Interrupt]
        .into_iter()
        .find(|mode| *mode as u8 == value)
        .unwrap_or_default()
}

/// A worker's own measure of its time, kept on its stack between flushes.
pub(crate) struct LoadMeter {
    /// When the current pass began.
    lap: Instant,
    time: [u64; 4],
    monitor_sleeps: u64,
    interrupt_sleeps: u64,
    expired_flows: u64,
    expiry_behind: u64,
}

impl LoadMeter {
    /// Start measuring now.
    pub(crate) fn start() -> LoadMeter {
        LoadMeter {
            lap: clock::now(),
            time: [0; 4],
            monitor_sleeps: 0,
            interrupt_sleeps: 0,
            expired_flows: 0,
            expiry_behind: 0,
        }
    }

    /// An expiry pass removed `removed` flows, and was or was not left `behind`.
    pub(crate) fn expired(&mut self, removed: usize, behind: bool) {
        self.expired_flows = self.expired_flows.saturating_add(removed as u64);
        self.expiry_behind += u64::from(behind);
    }

    /// The pass that began at the last lap ended now, and was spent `spent`.
    pub(crate) fn lap(&mut self, spent: Spent) {
        let now = clock::now();
        let took = now.saturating_duration_since(self.lap);
        self.lap = now;
        // A pass longer than 584 years is not one to account for exactly.
        let took = u64::try_from(took.as_nanos()).unwrap_or(u64::MAX);
        self.time[spent as usize] = self.time[spent as usize].saturating_add(took);
        match spent {
            Spent::Monitor => self.monitor_sleeps += 1,
            Spent::Interrupt => self.interrupt_sleeps += 1,
            Spent::Busy | Spent::Polling => {}
        }
    }

    /// Add what was measured to `load`, with the mode the worker now idles in, and start over.
    pub(crate) fn flush(&mut self, load: &Load, effective: IdleMode) {
        load.record(self, effective);
        self.time = [0; 4];
        self.monitor_sleeps = 0;
        self.interrupt_sleeps = 0;
        self.expired_flows = 0;
        self.expiry_behind = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pass lands in its own state, sleeps are counted by kind, and a flush hands it all to
    /// the shared load, adding to what was there.
    #[test]
    fn passes_add_up_in_their_states() {
        let load = Load::new(IdleMode::Interrupt);
        let reader = load.reader();
        let mut meter = LoadMeter::start();
        for spent in [
            Spent::Busy,
            Spent::Polling,
            Spent::Monitor,
            Spent::Interrupt,
            Spent::Interrupt,
        ] {
            meter.lap(spent);
        }
        meter.expired(5, false);
        meter.expired(7, true);
        meter.flush(&load, IdleMode::Monitor);
        let first = reader.load();
        assert_eq!((first.monitor_sleeps, first.interrupt_sleeps), (1, 2));
        assert_eq!((first.expired_flows, first.expiry_behind), (12, 1));

        meter.lap(Spent::Monitor);
        meter.flush(&load, IdleMode::Monitor);
        let second = reader.load();
        assert_eq!(second.since(&first).monitor_sleeps, 1);
        assert_eq!(second.since(&first).interrupt_sleeps, 0);
        for spent in Spent::ALL {
            assert!(second.nanos(spent) >= first.nanos(spent));
        }
        assert_eq!(reader.configured(), IdleMode::Interrupt);
        assert_eq!(reader.effective(), IdleMode::Monitor);
    }

    /// Shares are of the time covered, and sum to one when any is.
    #[test]
    fn shares_are_of_the_time_covered() {
        let totals = LoadTotals {
            time: [1, 1, 0, 2],
            ..LoadTotals::default()
        };
        assert!((totals.share(Spent::Busy) - 0.25).abs() < f64::EPSILON);
        assert!((totals.share(Spent::Interrupt) - 0.5).abs() < f64::EPSILON);
        let sum: f64 = Spent::ALL.into_iter().map(|s| totals.share(s)).sum();
        assert!((sum - 1.0).abs() < 1e-12);
        assert!(LoadTotals::default().share(Spent::Busy).abs() < f64::EPSILON);
    }

    /// Every mode survives the trip through its discriminant.
    #[test]
    fn modes_round_trip() {
        for mode in [IdleMode::Poll, IdleMode::Monitor, IdleMode::Interrupt] {
            assert_eq!(super::mode(mode as u8), mode);
        }
    }
}
