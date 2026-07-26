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

use crate::drivers::kernel::DriverKernel;
use crate::drivers::watchdog::Activity;

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
    pub total_tx_drops: u64,
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
            total_tx_drops: 0,
            pps: 0.,
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
            WorkerState::Terminated(res) => write!(f, "Terminated, result: {res}"),
        }
    }
}

macro_rules! RX_TASK_TBL_FMT {
    () => {
        "   {:<16}  {:<6}  {:>14}  {:>20}  {:>20}  {:>12}  {:>8}  {:>9}"
    };
}

fn fmt_rx_task_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            RX_TASK_TBL_FMT!(),
            "iface", "status", "pps", "pkt-rx", "pkt-tx", "ppline-drops", "tx-drops", "wd-misses"
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
            rx.ifname,
            rx.activity,
            pps,
            rx.total_rx,
            rx.total_tx,
            rx.total_ppline_drops,
            rx.total_tx_drops,
            rx.misses
        )
    )
}

impl Display for DriverStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Heading("Packet driver status").fmt(f)?;
        writeln!(f, " max rx batch: {} pkts", DriverKernel::MAX_RX_PKT_BATCH)?;
        write!(f, " activity poll: {} s", DriverKernel::TASK_POLL_PERIOD)?;
        write!(f, "  watchdog pat: {} s", DriverKernel::TASK_PAT_PERIOD)?;
        writeln!(f, "  watchdog check: {} s", DriverKernel::TASK_CHECK_PERIOD)?;

        writeln!(f)?;
        if self.workers.is_empty() {
            return writeln!(f, " (no workers)");
        }

        fmt_rx_task_heading(f)?;
        for worker in &self.workers {
            writeln!(f, " worker {}: {}", worker.worker, worker.state)?;
            for rx in &worker.rx_tasks {
                fmt_rx_task(f, rx)?;
            }
            writeln!(f)?;
        }
        Ok(())
    }
}
