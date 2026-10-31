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

use crate::drivers::supervisor;
use crate::drivers::watchdog::{Activity, Totals};

// The unique Id of a worker
pub(crate) type WorkerId = usize;

/// Which of a port's receive queues an rx task serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RxQueue {
    /// A queue the data path's traffic arrives on.
    Data,
    /// The queue the control plane's traffic is steered to (DPDK driver).
    Control,
}

impl RxQueue {
    /// Its name, as telemetry labels it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            RxQueue::Data => "data",
            RxQueue::Control => "control",
        }
    }
}

/// Liveness/activity of one rx task (a worker's reader for one of a port's queues),
/// as of the supervisor's last check, and its totals as they stand.
#[derive(Clone)]
pub struct RxTaskStatus {
    /// The port, by its configured interface name.
    pub port: Arc<str>,
    pub queue: RxQueue,
    pub activity: Activity,
    pub misses: u64,
    pub pps: f64,
    /// What the task counted since it started, read when wanted rather than when polled.
    pub totals: Totals,
}
impl RxTaskStatus {
    #[must_use]
    pub fn new(port: Arc<str>, queue: RxQueue, totals: Totals) -> Self {
        Self {
            port,
            queue,
            activity: Activity::Idle,
            misses: 0,
            pps: 0.,
            totals,
        }
    }

    /// The task as the CLI names it: its port, and its queue unless that is a data queue.
    fn name(&self) -> String {
        match self.queue {
            RxQueue::Data => self.port.to_string(),
            RxQueue::Control => format!("{} (control)", self.port),
        }
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

#[derive(Clone, Default)]
pub struct DriverStatus {
    /// The most frames one receive call can return, which differs between drivers.
    pub max_rx_batch: usize,
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
        "   {:<16}  {:<6}  {:>14}  {:>20}  {:>20}  {:>12}  {:>9}"
    };
}

macro_rules! RX_DROP_TBL_FMT {
    () => {
        "   {:<16}  {:>12}  {:>10}  {:>10}  {:>10}  {:>10}  {:>12}  {:>10}  {:>12}  {:>12}"
    };
}

fn fmt_rx_task_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            RX_TASK_TBL_FMT!(),
            "iface", "status", "pps", "pkt-rx", "pkt-tx", "injected", "wd-misses"
        )
    )
}

fn fmt_rx_task(f: &mut std::fmt::Formatter<'_>, rx: &RxTaskStatus) -> std::fmt::Result {
    let pps = format!("{:.1}", rx.pps);
    let totals = rx.totals.load();
    writeln!(
        f,
        "{}",
        format_args!(
            RX_TASK_TBL_FMT!(),
            rx.name(),
            rx.activity,
            pps,
            totals.rx,
            totals.tx,
            totals.injected,
            rx.misses
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
            "tx-drops",
            "punt-drops",
            "parse-err",
            "truncated",
            "csum-unknown",
            "zero-len",
            "kernel-drops",
            "inject-drops"
        )
    )
}

fn fmt_rx_drop(f: &mut std::fmt::Formatter<'_>, rx: &RxTaskStatus) -> std::fmt::Result {
    let totals = rx.totals.load();
    writeln!(
        f,
        "{}",
        format_args!(
            RX_DROP_TBL_FMT!(),
            rx.name(),
            totals.ppline_drops,
            totals.tx_drops,
            totals.punt_drops,
            totals.parse_errors,
            totals.truncated,
            totals.csum_unknown,
            totals.zero_len,
            totals.kernel_drops,
            totals.inject_drops
        )
    )
}

impl Display for DriverStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Packet driver status").fmt(f)?;
        writeln!(f, " max rx batch: {} pkts", self.max_rx_batch)?;
        write!(f, " activity poll: {} s", supervisor::TASK_POLL_PERIOD)?;
        write!(f, "  watchdog pat: {} s", supervisor::TASK_PAT_PERIOD)?;
        writeln!(f, "  watchdog check: {} s", supervisor::TASK_CHECK_PERIOD)?;

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
