// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Driver status, published by the supervisor
//! Ideally, these types would not depend on the type of driver.
//!
//! The supervisor is the sole writer: once per check it builds a fresh
//! [`DriverStatus`] and publishes it through a [`DriverStatusWriter`].

use common::cliprovider::{CliDataProvider, Heading, PrettyDuration};
use concurrency::slot::Slot;
use concurrency::sync::Arc;

use std::fmt::Display;
use std::time::{Duration, Instant, SystemTime};

use crate::drivers::load::{LoadReader, LoadTotals, Spent};
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
    /// Mean frames per burst over the supervisor's last poll; zero if it received none.
    pub batch: f64,
    /// Fraction of the last poll's bursts that were full.
    pub full: f64,
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
            batch: 0.,
            full: 0.,
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

/// What a polling worker spent its time on, as it stands and over the supervisor's last poll.
#[derive(Clone)]
pub struct WorkerLoadStatus {
    /// The worker's load, read when wanted.
    pub reader: LoadReader,
    /// What it spent over the supervisor's last poll.
    pub recent: LoadTotals,
}

/// Per-worker status: its thread state plus its rx tasks' activity.
#[derive(Clone)]
pub struct WorkerStatus {
    pub worker: WorkerId,
    pub state: WorkerState,
    pub rx_tasks: Vec<RxTaskStatus>,
    /// What the worker spends its time on, if it polls (DPDK driver).
    pub load: Option<WorkerLoadStatus>,
}
impl WorkerStatus {
    #[must_use]
    pub fn new(worker: WorkerId) -> Self {
        Self {
            worker,
            state: WorkerState::Running,
            rx_tasks: vec![],
            load: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct DriverStatus {
    /// The most frames one receive call can return, which differs between drivers.
    pub max_rx_batch: usize,
    pub workers: Vec<WorkerStatus>,
    /// The driver's ports, as of the supervisor's last poll; none for a driver whose ports are the
    /// kernel's to report on.
    pub ports: Vec<PortReport>,
}

/// One of the driver's ports, as of one reading.
#[derive(Clone, Debug, Default)]
pub struct PortReport {
    /// The configured interface name.
    pub name: String,
    /// Its bus address and driver, if it would say.
    pub hardware: Option<String>,
    pub mac: String,
    pub mtu: u16,
    pub link_up: bool,
    /// Its negotiated speed in Mbit/s, if known.
    pub speed_mbps: Option<u32>,
    /// Whether the link speed was autonegotiated, if known.
    pub autoneg: Option<bool>,
    /// Whether the link is full duplex, if known.
    pub full_duplex: Option<bool>,
    /// Times the link went up or down, as seen once a second.
    pub link_changes: u64,
    /// When the link last went up or down, by the wall clock, or when the driver first read it.
    pub last_change: Option<SystemTime>,
    /// Its counters, if it would report them.
    pub counters: Option<stats::PortCounters>,
    /// Frames the driver meant to send on the port but its transmit queues would not take.
    pub tx_discards: u64,
    /// How fast the counters went up since the previous reading, if there were two readings.
    pub rates: Option<PortRates>,
    /// When the counters started from zero, by the wall clock.
    pub counters_since: Option<SystemTime>,
    /// Mbufs in use, and the size, of its rx and control pools.
    pub rx_pool: (u32, u32),
    pub control_pool: (u32, u32),
    /// The extended statistics it publishes, by its PMD's names.
    pub xstats: Vec<(String, u64)>,
}

/// How fast a port's counters went up between two readings.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct PortRates {
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
}

/// How long a burst takes to fade from the rates, by a factor e.
///
/// Rates over a single poll jump about on a quiet port, where one packet more or less is much of the
/// traffic. Switches smooth theirs the same way, over 10 seconds by default.
const RATE_SMOOTHING: Duration = Duration::from_secs(10);

/// Turns successive readings of a port's counters into rates, smoothed over the last seconds.
#[derive(Debug, Default)]
pub struct RateMeter {
    last: Option<(Instant, stats::PortCounters)>,
    smoothed: Option<PortRates>,
}

impl RateMeter {
    /// The rates given `counters` read at `now`: an exponential moving average of the rates
    /// between successive readings, each weighted by the time it covers.
    ///
    /// Returns `None` for the first reading, and when no time passed. A counter that went down
    /// (the device reset it) counts as no traffic.
    pub fn update(&mut self, counters: stats::PortCounters, now: Instant) -> Option<PortRates> {
        let previous = self.last.replace((now, counters));
        let (then, before) = previous?;
        let seconds = now.checked_duration_since(then)?.as_secs_f64();
        if seconds <= 0.0 {
            return None;
        }
        #[allow(clippy::cast_precision_loss)] // rates need no more than f64's 53 bits
        let rate = |after: u64, before: u64| after.saturating_sub(before) as f64 / seconds;
        let sample = PortRates {
            rx_bps: rate(counters.rx_bytes, before.rx_bytes) * 8.0,
            tx_bps: rate(counters.tx_bytes, before.tx_bytes) * 8.0,
            rx_pps: rate(counters.rx_packets, before.rx_packets),
            tx_pps: rate(counters.tx_packets, before.tx_packets),
        };
        // The first sample has nothing to blend with: take it as it is.
        let rates = match self.smoothed {
            None => sample,
            Some(old) => {
                let weight = 1.0 - (-seconds / RATE_SMOOTHING.as_secs_f64()).exp();
                let blend = |old: f64, new: f64| old + weight * (new - old);
                PortRates {
                    rx_bps: blend(old.rx_bps, sample.rx_bps),
                    tx_bps: blend(old.tx_bps, sample.tx_bps),
                    rx_pps: blend(old.rx_pps, sample.rx_pps),
                    tx_pps: blend(old.tx_pps, sample.tx_pps),
                }
            }
        };
        self.smoothed = Some(rates);
        Some(rates)
    }
}

/// `show dpdk port`: what each port is, and its link and pools.
pub struct DpdkPortsCli(pub DriverStatusReader);

/// `show dpdk port stats`: each port's counters and extended statistics.
pub struct DpdkPortStatsCli(pub DriverStatusReader);

/// The status's ports, or why there are none.
fn ports_or(f: &mut String, status: &DriverStatus) -> bool {
    use std::fmt::Write;
    if status.ports.is_empty() {
        let _ = writeln!(f, " (no DPDK ports: the driver in use does not report any)");
        false
    } else {
        true
    }
}

impl CliDataProvider for DpdkPortsCli {
    fn provide(&self) -> String {
        use std::fmt::Write;
        let status = self.0.load();
        let mut f = Heading("DPDK ports").to_string();
        if !ports_or(&mut f, &status) {
            return f;
        }
        let _ = writeln!(
            f,
            "   {:<16}  {:<17}  {:>5}  {:<5}  {:>8}  {:<6}  {:<4}  {:>7}  {:>12}  {:>17}  {:>17}  {:<8}",
            "port",
            "mac",
            "mtu",
            "link",
            "speed",
            "duplex",
            "auto",
            "changes",
            "since",
            "rx-pool",
            "control-pool",
            "hardware"
        );
        let pool = |(used, size): (u32, u32)| format!("{used}/{size}");
        let flag = |value: Option<bool>, yes, no| match value {
            Some(true) => yes,
            Some(false) => no,
            None => "-",
        };
        for port in &status.ports {
            let _ = writeln!(
                f,
                "   {:<16}  {:<17}  {:>5}  {:<5}  {:>8}  {:<6}  {:<4}  {:>7}  {:>12}  {:>17}  {:>17}  {:<8}",
                port.name,
                port.mac,
                port.mtu,
                if port.link_up { "up" } else { "down" },
                port.speed_mbps
                    .filter(|_| port.link_up)
                    .map_or_else(|| "-".to_string(), speed),
                flag(port.full_duplex.filter(|_| port.link_up), "full", "half"),
                flag(port.autoneg, "on", "off"),
                port.link_changes,
                ago(port.last_change),
                pool(port.rx_pool),
                pool(port.control_pool),
                port.hardware.as_deref().unwrap_or("-")
            );
        }
        f
    }
}

/// How long ago `at` was, for the tables, or "-" if unknown or in the future.
fn ago(at: Option<SystemTime>) -> String {
    at.and_then(|at| clock::system_now().duration_since(at).ok())
        .map_or_else(
            || "-".to_string(),
            |ago| PrettyDuration::new(ago).to_string(),
        )
}

/// A link speed in Mbit/s as the ports table shows it: whole or fractional gigabits, or megabits
/// below one.
fn speed(mbps: u32) -> String {
    if mbps < 1000 {
        format!("{mbps}M")
    } else if mbps.is_multiple_of(1000) {
        format!("{}G", mbps / 1000)
    } else {
        let fraction = format!("{:03}", mbps % 1000);
        format!("{}.{}G", mbps / 1000, fraction.trim_end_matches('0'))
    }
}

impl CliDataProvider for DpdkPortStatsCli {
    fn provide(&self) -> String {
        use std::fmt::Write;
        let status = self.0.load();
        let mut f = Heading("DPDK port counters").to_string();
        if !ports_or(&mut f, &status) {
            return f;
        }
        let _ = writeln!(
            f,
            "   {:<16}  {:>16}  {:>16}  {:>12}  {:>10}  {:>10}  {:>10}  {:>12}",
            "port",
            "rx-packets",
            "tx-packets",
            "rx-missed",
            "rx-errors",
            "tx-errors",
            "rx-nombuf",
            "tx-discards"
        );
        for port in &status.ports {
            match &port.counters {
                Some(c) => {
                    let _ = writeln!(
                        f,
                        "   {:<16}  {:>16}  {:>16}  {:>12}  {:>10}  {:>10}  {:>10}  {:>12}",
                        port.name,
                        c.rx_packets,
                        c.tx_packets,
                        c.rx_missed,
                        c.rx_errors,
                        c.tx_errors,
                        c.rx_no_mbuf,
                        port.tx_discards
                    );
                }
                None => {
                    let _ = writeln!(f, "   {:<16}  (counters unavailable)", port.name);
                }
            }
        }
        let _ = writeln!(
            f,
            "\n   {:<16}  {:>14}  {:>14}  {:>12}  {:>12}  {:>12}",
            "port", "rx-bps", "tx-bps", "rx-pps", "tx-pps", "counting"
        );
        for port in &status.ports {
            let rate =
                |value: Option<f64>| value.map_or_else(|| "-".to_string(), |v| format!("{v:.0}"));
            let rates = port.rates;
            let _ = writeln!(
                f,
                "   {:<16}  {:>14}  {:>14}  {:>12}  {:>12}  {:>12}",
                port.name,
                rate(rates.map(|r| r.rx_bps)),
                rate(rates.map(|r| r.tx_bps)),
                rate(rates.map(|r| r.rx_pps)),
                rate(rates.map(|r| r.tx_pps)),
                ago(port.counters_since),
            );
        }
        for port in &status.ports {
            let _ = writeln!(f, "\n {} extended statistics", port.name);
            if port.xstats.is_empty() {
                let _ = writeln!(f, "   (none published)");
            }
            for (name, value) in &port.xstats {
                let _ = writeln!(f, "   {name:<40}  {value:>16}");
            }
        }
        f
    }
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
        "   {:<25}  {:<6}  {:>14}  {:>6}  {:>6}  {:>20}  {:>20}  {:>12}  {:>9}"
    };
}

macro_rules! RX_DROP_TBL_FMT {
    () => {
        "   {:<25}  {:>12}  {:>10}  {:>10}  {:>10}  {:>10}  {:>12}  {:>10}  {:>12}  {:>12}"
    };
}

fn fmt_rx_task_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            RX_TASK_TBL_FMT!(),
            "iface", "status", "pps", "batch", "full%", "pkt-rx", "pkt-tx", "injected", "wd-misses"
        )
    )
}

fn fmt_rx_task(f: &mut std::fmt::Formatter<'_>, rx: &RxTaskStatus) -> std::fmt::Result {
    let pps = format!("{:.1}", rx.pps);
    let batch = format!("{:.1}", rx.batch);
    let full = format!("{:.0}", rx.full * 100.);
    let totals = rx.totals.load();
    writeln!(
        f,
        "{}",
        format_args!(
            RX_TASK_TBL_FMT!(),
            rx.name(),
            rx.activity,
            pps,
            batch,
            full,
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

        if self.workers.iter().any(|w| w.load.is_some()) {
            writeln!(f)?;
            writeln!(
                f,
                " worker load (over the last activity poll; sleeps and expiry-behind since start)"
            )?;
            fmt_load_heading(f)?;
            for worker in &self.workers {
                if let Some(load) = &worker.load {
                    fmt_load(f, worker.worker, load)?;
                }
            }
        }
        Ok(())
    }
}

macro_rules! LOAD_TBL_FMT {
    () => {
        "   {:<6}  {:<22}  {:>6}  {:>8}  {:>8}  {:>10}  {:>14}  {:>16}  {:>10}  {:>14}"
    };
}

fn fmt_load_heading(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(
        f,
        "{}",
        format_args!(
            LOAD_TBL_FMT!(),
            "worker",
            "idle mode",
            "busy%",
            "polling%",
            "monitor%",
            "interrupt%",
            "monitor-sleeps",
            "interrupt-sleeps",
            "expired/s",
            "expiry-behind"
        )
    )
}

fn fmt_load(
    f: &mut std::fmt::Formatter<'_>,
    worker: WorkerId,
    load: &WorkerLoadStatus,
) -> std::fmt::Result {
    let (configured, effective) = (load.reader.configured(), load.reader.effective());
    // The mode it idles in, and the one it was asked for if it fell back from that.
    let mode = if configured == effective {
        effective.to_string()
    } else {
        format!("{effective} (asked {configured})")
    };
    let pct = |spent| format!("{:.1}", load.recent.share(spent) * 100.);
    let totals = load.reader.load();
    writeln!(
        f,
        "{}",
        format_args!(
            LOAD_TBL_FMT!(),
            worker,
            mode,
            pct(Spent::Busy),
            pct(Spent::Polling),
            pct(Spent::Monitor),
            pct(Spent::Interrupt),
            totals.monitor_sleeps,
            totals.interrupt_sleeps,
            load.recent.expired_flows,
            totals.expiry_behind
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_with(ports: Vec<PortReport>) -> DriverStatusReader {
        let (writer, reader) = driver_status_access();
        writer.publish(DriverStatus {
            ports,
            ..DriverStatus::default()
        });
        reader
    }

    /// A driver with no ports of its own says so, rather than showing an empty table.
    #[test]
    fn no_ports_is_said() {
        let reader = status_with(Vec::new());
        assert!(
            DpdkPortsCli(reader.clone())
                .provide()
                .contains("no DPDK ports")
        );
        assert!(DpdkPortStatsCli(reader).provide().contains("no DPDK ports"));
    }

    /// Each port shows its link and pools, and its counters and extended statistics.
    #[test]
    fn ports_show_what_was_read() {
        let reader = status_with(vec![PortReport {
            name: "eth7".to_string(),
            mac: "02:00:00:00:00:07".to_string(),
            mtu: 9000,
            link_up: true,
            speed_mbps: Some(100_000),
            autoneg: Some(true),
            full_duplex: Some(true),
            link_changes: 2,
            counters: Some(stats::PortCounters {
                rx_missed: 4321,
                ..stats::PortCounters::default()
            }),
            rx_pool: (12, 4095),
            tx_discards: 8765,
            rates: Some(PortRates {
                rx_bps: 123_456.0,
                ..PortRates::default()
            }),
            xstats: vec![("rx_discards_phy".to_string(), 77)],
            ..PortReport::default()
        }]);
        let ports = DpdkPortsCli(reader.clone()).provide();
        for shown in ["eth7", "9000", "up", "100G", "full", "on", "12/4095"] {
            assert!(ports.contains(shown), "{shown} missing from:\n{ports}");
        }
        let stats = DpdkPortStatsCli(reader).provide();
        for shown in ["4321", "8765", "123456", "rx_discards_phy", "77"] {
            assert!(stats.contains(shown), "{shown} missing from:\n{stats}");
        }
    }

    /// Rates come from the difference between two readings, over the time between them.
    #[test]
    fn rates_come_from_successive_readings() {
        let start = clock::now();
        let mut meter = RateMeter::default();
        let reading = |bytes, packets| stats::PortCounters {
            rx_bytes: bytes,
            tx_bytes: 2 * bytes,
            rx_packets: packets,
            tx_packets: 2 * packets,
            ..stats::PortCounters::default()
        };
        assert_eq!(meter.update(reading(1000, 10), start), None);
        let rates = meter
            .update(reading(3000, 30), start + std::time::Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            rates,
            PortRates {
                rx_bps: 8000.0,
                tx_bps: 16000.0,
                rx_pps: 10.0,
                tx_pps: 20.0,
            }
        );
        // A reset counter does not make a negative rate: the rates decay towards zero.
        let rates = meter
            .update(reading(0, 0), start + std::time::Duration::from_secs(3))
            .unwrap();
        assert!(rates.rx_bps >= 0.0 && rates.rx_bps < 8000.0, "{rates:?}");
    }

    /// Rates follow the traffic smoothly: a steady rate stays as it is, a burst fades out.
    #[test]
    fn rates_are_smoothed() {
        let start = clock::now();
        let at = |secs| start + std::time::Duration::from_secs(secs);
        let reading = |bytes| stats::PortCounters {
            rx_bytes: bytes,
            ..stats::PortCounters::default()
        };
        let mut meter = RateMeter::default();
        assert!(meter.update(reading(0), at(0)).is_none());
        let mut rx_bps = |bytes, secs| meter.update(reading(bytes), at(secs)).unwrap().rx_bps;
        // 100 bytes per second, steadily.
        for secs in 1..=10 {
            assert!((rx_bps(100 * secs, secs) - 800.0).abs() < 1e-9);
        }
        // A burst of 10000 bytes in one second moves the rate by a tenth of the step or so.
        let burst = rx_bps(11_000, 11);
        assert!(burst > 800.0 && burst < 800.0 + 0.1 * 80_000.0, "{burst}");
        // Then silence, for one smoothing period: what's left of the burst is cut by e.
        let quiet = rx_bps(11_000, 21);
        assert!(
            (quiet - burst / std::f64::consts::E).abs() < 1e-6,
            "{quiet} after {burst}"
        );
    }

    /// Speeds that are not whole gigabits keep their fraction, and slow links show megabits.
    #[test]
    fn speeds_are_not_truncated() {
        for (mbps, shown) in [
            (10, "10M"),
            (100, "100M"),
            (1_000, "1G"),
            (2_500, "2.5G"),
            (1_250, "1.25G"),
            (25_000, "25G"),
            (400_000, "400G"),
        ] {
            assert_eq!(speed(mbps), shown);
        }
    }
}
