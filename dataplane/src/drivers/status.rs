// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Driver status, published by the supervisor
//! Ideally, these types would not depend on the type of driver.
//!
//! The supervisor is the sole writer: once per check it builds a fresh
//! [`DriverStatus`] and publishes it through a [`DriverStatusWriter`].

use common::cliprovider::{CliDataProvider, Heading};
use concurrency::slot::Slot;
use concurrency::sync::Arc;

use std::fmt::Display;

use crate::drivers::watchdog::{Activity, RxCounters};

// The unique Id of a worker
pub(crate) type WorkerId = usize;

/// Liveness/activity of one rx task (a worker's reader for one interface),
/// as of the supervisor's last check.
#[derive(Clone)]
pub struct RxTaskStatus {
    pub ifname: Arc<str>,
    pub activity: Activity,
    pub misses: u64,
    pub total_rx: u64,
    pub total_tx: u64,
    pub total_ppline_drops: u64,
    pub total_local: u64,
    pub total_tx_drops: u64,
    pub total_parse_errors: u64,
    pub total_truncated: u64,
    pub total_zero_len: u64,
    pub total_kernel_drops: u64,
    pub pps: f64,
}
impl RxTaskStatus {
    #[must_use]
    pub fn new(ifname: Arc<str>) -> Self {
        Self {
            ifname,
            activity: Activity::Idle,
            misses: 0,
            total_rx: 0,
            total_tx: 0,
            total_ppline_drops: 0,
            total_local: 0,
            total_tx_drops: 0,
            total_parse_errors: 0,
            total_truncated: 0,
            total_zero_len: 0,
            total_kernel_drops: 0,
            pps: 0.,
        }
    }

    /// Add the counters read from a rx task watchdog to the totals. Reading a watchdog
    /// clears it, so this must be called for every read, whatever the activity reported.
    pub fn accumulate(&mut self, counters: &RxCounters) {
        self.total_rx += counters.rx;
        self.total_tx += counters.tx;
        self.total_ppline_drops += counters.ppline_drops;
        self.total_local += counters.local;
        self.total_tx_drops += counters.tx_drops;
        self.total_parse_errors += counters.parse_errors;
        self.total_truncated += counters.truncated;
        self.total_zero_len += counters.zero_len;
        self.total_kernel_drops += counters.kernel_drops;
    }
}

/// Whether a worker thread is still running or has been joined.
#[derive(Clone)]
pub enum WorkerState {
    Running,
    Terminated(WorkerEndResult),
}

/// How a worker thread ended (result when joined)
#[derive(Clone)]
pub enum WorkerEndResult {
    Ok,
    Failed(String),
    Panicked(String),
}

/// Per-worker status: its thread state plus its rx tasks' activity.
#[derive(Clone)]
pub struct WorkerStatus {
    pub worker: WorkerId,
    pub state: WorkerState,
    pub rx_tasks: Vec<RxTaskStatus>,
}
impl WorkerStatus {
    #[must_use]
    pub fn new(worker: WorkerId) -> Self {
        Self {
            worker,
            state: WorkerState::Running,
            rx_tasks: vec![],
        }
    }
}

/// What a driver is, and the periods its supervisor works to. Fixed for the
/// life of the process, but reported with the status so that a reader knows
/// which driver, and which cadence, the numbers below came from.
#[derive(Clone, Copy, Default)]
pub struct DriverParams {
    /// Name of the driver, as it is given on the command line.
    pub name: &'static str,
    /// Most packets a worker will take from an interface in one go.
    pub rx_batch: usize,
    /// How often, in seconds, the supervisor samples worker activity.
    pub poll_period: u16,
    /// How often, in seconds, a worker pats its watchdog when it is idle.
    pub pat_period: u16,
    /// How long, in seconds, the supervisor waits for a pat before calling a
    /// worker stuck.
    pub check_period: u16,
}

#[derive(Clone, Default)]
pub struct DriverStatus {
    pub params: DriverParams,
    pub workers: Vec<WorkerStatus>,
}

// ====== Types for sharing DriverStatus ===== //

pub struct DriverStatusWriter(Arc<Slot<DriverStatus>>);
impl DriverStatusWriter {
    pub fn publish(&self, status: DriverStatus) {
        self.0.store(Arc::new(status));
    }
}

#[derive(Clone)]
pub struct DriverStatusReader(Arc<Slot<DriverStatus>>);
impl DriverStatusReader {
    #[must_use]
    pub fn load(&self) -> Arc<DriverStatus> {
        self.0.load_full()
    }
}

#[must_use]
pub fn driver_status_access() -> (DriverStatusWriter, DriverStatusReader) {
    let slot = Arc::new(Slot::from_pointee(DriverStatus::default()));
    (DriverStatusWriter(slot.clone()), DriverStatusReader(slot))
}

impl CliDataProvider for DriverStatusReader {
    fn provide(&self) -> String {
        let status = self.load();
        status.to_string()
    }
}

// === Display impls === //

impl Display for WorkerEndResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerEndResult::Ok => write!(f, "Ok"),
            WorkerEndResult::Failed(s) => write!(f, "Failed: {s}"),
            WorkerEndResult::Panicked(s) => write!(f, "Panicked: {s}"),
        }
    }
}

impl Display for WorkerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerState::Running => write!(f, "running"),
            WorkerState::Terminated(res) => write!(f, "Terminated({res})"),
        }
    }
}

macro_rules! RX_TASK_TBL_FMT {
    () => {
        "   {:<16}  {:<6}  {:>14}  {:>20}  {:>20}  {:>9}"
    };
}

macro_rules! RX_DROP_TBL_FMT {
    () => {
        "   {:<16}  {:>12}  {:>10}  {:>10}  {:>10}  {:>10}  {:>10}  {:>12}"
    };
}

fn fmt_rx_task_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            RX_TASK_TBL_FMT!(),
            "iface", "status", "pps", "pkt-rx", "pkt-tx", "wd-misses"
        )
    )
}

fn fmt_rx_task(f: &mut std::fmt::Formatter<'_>, rx: &RxTaskStatus) -> std::fmt::Result {
    let pps = format!("{:.1}", rx.pps);
    writeln!(
        f,
        "{}",
        format_args!(
            RX_TASK_TBL_FMT!(),
            rx.ifname, rx.activity, pps, rx.total_rx, rx.total_tx, rx.misses
        )
    )
}

fn fmt_rx_drop_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            RX_DROP_TBL_FMT!(),
            "iface",
            "ppline-drops",
            "to-kernel",
            "tx-drops",
            "parse-err",
            "truncated",
            "zero-len",
            "kernel-drops"
        )
    )
}

fn fmt_rx_drop(f: &mut std::fmt::Formatter<'_>, rx: &RxTaskStatus) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            RX_DROP_TBL_FMT!(),
            rx.ifname,
            rx.total_ppline_drops,
            rx.total_local,
            rx.total_tx_drops,
            rx.total_parse_errors,
            rx.total_truncated,
            rx.total_zero_len,
            rx.total_kernel_drops
        )
    )
}

impl Display for DriverStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Packet driver status").fmt(f)?;
        writeln!(f, " driver: {}", self.params.name)?;
        writeln!(f, " max rx batch: {} pkts", self.params.rx_batch)?;
        write!(f, " activity poll: {} s", self.params.poll_period)?;
        write!(f, "  watchdog pat: {} s", self.params.pat_period)?;
        writeln!(f, "  watchdog check: {} s", self.params.check_period)?;

        writeln!(f)?;
        if self.workers.is_empty() {
            return writeln!(f, " (no workers)");
        }

        writeln!(f, " rx tasks")?;
        fmt_rx_task_heading(f)?;
        for worker in &self.workers {
            writeln!(f, " worker {}: {}", worker.worker, worker.state)?;
            for rx in &worker.rx_tasks {
                fmt_rx_task(f, rx)?;
            }
        }

        writeln!(f)?;
        writeln!(f, " rx drops")?;
        fmt_rx_drop_heading(f)?;
        for worker in &self.workers {
            writeln!(f, " worker {}", worker.worker)?;
            for rx in &worker.rx_tasks {
                fmt_rx_drop(f, rx)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{Arc, RxCounters, RxTaskStatus};

    /// Every counter read from a watchdog must make it to the totals.
    #[test]
    fn accumulate_keeps_every_counter() {
        let mut status = RxTaskStatus::new(Arc::from("eth0"));
        let counters = RxCounters {
            rx: 1,
            tx: 2,
            ppline_drops: 3,
            local: 9,
            tx_drops: 4,
            parse_errors: 5,
            truncated: 6,
            zero_len: 7,
            kernel_drops: 8,
        };

        status.accumulate(&counters);
        status.accumulate(&counters);

        assert_eq!(status.total_rx, 2);
        assert_eq!(status.total_tx, 4);
        assert_eq!(status.total_ppline_drops, 6);
        assert_eq!(status.total_local, 18);
        assert_eq!(status.total_tx_drops, 8);
        assert_eq!(status.total_parse_errors, 10);
        assert_eq!(status.total_truncated, 12);
        assert_eq!(status.total_zero_len, 14);
        assert_eq!(status.total_kernel_drops, 16);
    }
}
