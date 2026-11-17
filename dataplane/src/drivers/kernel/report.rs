// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What the kernel driver reports about its interfaces.
//!
//! The kernel keeps the link state and counters of each interface; this reads them from sysfs,
//! and the speed, duplex and autonegotiation from ethtool netlink, so the driver can report its
//! ports the way the DPDK driver does. Reads go through the calling thread's namespace and sysfs,
//! so they must run on the driver's threads, which live in the datapath namespace.

use std::path::Path;
use std::time::{Duration, SystemTime};

use ethtool2::Duplex;
use lldp::Link;
use tracing::{debug, warn};

use super::kif::Kif;
use crate::drivers::status::{PortReport, RateMeter};

/// How long to wait for the kernel to answer an ethtool query, so that a stuck netlink socket
/// cannot hold the supervisor, which also watches the workers.
const ETHTOOL_TIMEOUT: Duration = Duration::from_millis(250);

/// How long to leave ethtool alone after a query timed out, so that a stuck netlink socket costs
/// the supervisor one timeout now and then, rather than one per port on each of its polls.
const ETHTOOL_BACKOFF: Duration = Duration::from_secs(30);

/// A port's counters, with its transmit drops, which have no field there.
type Counters = (stats::PortCounters, u64);

/// An ethtool netlink connection, on a runtime of its own, since the supervisor is not async.
struct Ethtool {
    runtime: tokio::runtime::Runtime,
    handle: ethtool2::Handle,
    /// Until when to leave ethtool alone, after a query timed out.
    quiet_until: Option<clock::Instant>,
}

impl Ethtool {
    /// Open a connection in the calling thread's namespace.
    fn open() -> Option<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .inspect_err(|e| {
                warn!("no runtime for ethtool netlink ({e}); no autonegotiation or duplex");
            })
            .ok()?;
        let (connection, handle) = runtime
            .block_on(async { ethtool2::new_connection() })
            .inspect_err(|e| warn!("no ethtool netlink socket ({e}); no autonegotiation or duplex"))
            .ok()?;
        // A current-thread runtime drives the connection whenever a query blocks on it.
        runtime.spawn(connection);
        Some(Self {
            runtime,
            handle,
            quiet_until: None,
        })
    }

    /// The link modes of `name`, or `None` if the kernel would not say, or not in time, or if a
    /// recent query timed out.
    fn link_modes(&mut self, name: &str) -> Option<ethtool2::LinkModes> {
        if self.quiet_until.is_some_and(|until| clock::now() < until) {
            return None;
        }
        // The timer must be made inside the runtime, which drives it.
        let query =
            async { tokio::time::timeout(ETHTOOL_TIMEOUT, self.handle.link_modes(name)).await };
        match self.runtime.block_on(query) {
            Ok(Ok(modes)) => Some(modes),
            Ok(Err(e)) => {
                debug!("no link modes for {name}: {e}");
                None
            }
            Err(_) => {
                warn!(
                    "ethtool netlink did not give the link modes of {name} within \
                     {ETHTOOL_TIMEOUT:?}; not asking again for {ETHTOOL_BACKOFF:?}"
                );
                self.quiet_until = Some(clock::saturating_add(clock::now(), ETHTOOL_BACKOFF));
                None
            }
        }
    }
}

/// One interface, and what is kept between readings to report on it.
struct KernelPort {
    kif: Kif,
    /// What does not change while the driver runs, read once.
    hardware: Option<String>,
    mac: String,
    /// The MTU at the driver's start, for when sysfs cannot give the current one.
    mtu: u16,
    /// `carrier_changes` at the first good reading, to count changes from the driver's start.
    baseline_changes: Option<u64>,
    /// `carrier_changes` at the last good reading, to notice a flap between readings.
    last_changes: Option<u64>,
    /// Whether the link was up at the last reading; `None` before the first.
    up: Option<bool>,
    last_change: Option<SystemTime>,
    /// The counters at the first reading, or when the kernel last reset them, and when that was:
    /// the kernel counts from the interface's creation, the report from the driver's start.
    baseline: Option<(Counters, SystemTime)>,
    rates: RateMeter,
}

/// The kernel driver's interfaces, to report on.
pub(super) struct KernelPorts {
    ports: Vec<KernelPort>,
    ethtool: Option<Ethtool>,
}

impl KernelPorts {
    /// Report on `interfaces`; call from a thread in their namespace.
    pub(super) fn new(interfaces: &[Kif]) -> Self {
        Self {
            ports: interfaces
                .iter()
                .map(|kif| KernelPort {
                    kif: kif.clone(),
                    hardware: kif.hardware(),
                    mac: kif.mac.map_or_default(|mac| mac.to_string()),
                    mtu: kif.mtu.and_then(|mtu| u16::try_from(mtu).ok()).unwrap_or(0),
                    baseline_changes: None,
                    last_changes: None,
                    up: None,
                    last_change: None,
                    baseline: None,
                    rates: RateMeter::default(),
                })
                .collect(),
            ethtool: Ethtool::open(),
        }
    }

    /// Read every interface.
    pub(super) fn report(&mut self) -> Vec<PortReport> {
        let mut reports = Vec::with_capacity(self.ports.len());
        for port in &mut self.ports {
            reports.push(port.report(self.ethtool.as_mut()));
        }
        reports
    }
}

impl KernelPort {
    fn report(&mut self, ethtool: Option<&mut Ethtool>) -> PortReport {
        let sysfs = self.kif.sysfs();
        let up = self.kif.link() == Link::Up;
        // A failed read tells nothing: keep the last good one, and the baseline for the first.
        let changes = read_u64(&sysfs.join("carrier_changes"));
        let flapped =
            matches!((changes, self.last_changes), (Some(now), Some(before)) if now != before);
        if self.up != Some(up) || flapped {
            self.last_change = Some(clock::system_now());
        }
        self.up = Some(up);
        if let Some(changes) = changes {
            self.baseline_changes.get_or_insert(changes);
            self.last_changes = Some(changes);
        }

        let counters = counters(&sysfs.join("statistics")).map(|now| self.since_baseline(now));
        let modes = ethtool.and_then(|ethtool| ethtool.link_modes(&self.kif.name));
        PortReport {
            name: self.kif.name.clone(),
            hardware: self.hardware.clone(),
            mac: self.mac.clone(),
            mtu: read_u64(&sysfs.join("mtu"))
                .and_then(|mtu| u16::try_from(mtu).ok())
                .unwrap_or(self.mtu),
            link_up: up,
            speed_mbps: modes
                .as_ref()
                .and_then(|modes| modes.speed)
                .or_else(|| read_u64(&sysfs.join("speed")).and_then(|s| u32::try_from(s).ok())),
            autoneg: modes.as_ref().and_then(|modes| modes.autoneg),
            full_duplex: modes
                .as_ref()
                .and_then(|modes| modes.duplex)
                .and_then(|duplex| match duplex {
                    Duplex::Full => Some(true),
                    Duplex::Half => Some(false),
                    _ => None,
                }),
            link_changes: self
                .last_changes
                .zip(self.baseline_changes)
                .map_or(0, |(changes, baseline)| changes.saturating_sub(baseline)),
            last_change: self.last_change,
            counters: counters.map(|(counters, _)| counters),
            tx_discards: counters.map_or(0, |(_, tx_dropped)| tx_dropped),
            rates: counters.and_then(|(counters, _)| self.rates.update(counters, clock::now())),
            counters_since: self.baseline.map(|(_, since)| since),
            ..PortReport::default()
        }
    }

    /// The counters in `now` since the baseline, which the first reading sets. A counter lower
    /// than its baseline means the kernel reset them, which becomes the new baseline (zero).
    fn since_baseline(&mut self, now: Counters) -> Counters {
        let (base, _) = self
            .baseline
            .get_or_insert_with(|| (now, clock::system_now()));
        if let Some(since) = subtract(now, *base) {
            return since;
        }
        self.baseline = Some(((stats::PortCounters::default(), 0), clock::system_now()));
        now
    }
}

/// The counters in `now` minus those in `base`, or `None` if any of them went down.
fn subtract((now, now_drops): Counters, (base, base_drops): Counters) -> Option<Counters> {
    Some((
        stats::PortCounters {
            rx_packets: now.rx_packets.checked_sub(base.rx_packets)?,
            tx_packets: now.tx_packets.checked_sub(base.tx_packets)?,
            rx_bytes: now.rx_bytes.checked_sub(base.rx_bytes)?,
            tx_bytes: now.tx_bytes.checked_sub(base.tx_bytes)?,
            rx_missed: now.rx_missed.checked_sub(base.rx_missed)?,
            rx_errors: now.rx_errors.checked_sub(base.rx_errors)?,
            tx_errors: now.tx_errors.checked_sub(base.tx_errors)?,
            rx_no_mbuf: now.rx_no_mbuf.checked_sub(base.rx_no_mbuf)?,
        },
        now_drops.checked_sub(base_drops)?,
    ))
}

/// An interface's counters from its sysfs `statistics` directory, and its transmit drops.
///
/// The kernel's receive drops (`rx_dropped`, `rx_missed_errors`) count as missed frames, the
/// closest of [`stats::PortCounters`]'s fields.
fn counters(statistics: &Path) -> Option<Counters> {
    let read = |name: &str| read_u64(&statistics.join(name));
    let counters = stats::PortCounters {
        rx_packets: read("rx_packets")?,
        tx_packets: read("tx_packets")?,
        rx_bytes: read("rx_bytes")?,
        tx_bytes: read("tx_bytes")?,
        rx_missed: read("rx_dropped")
            .unwrap_or(0)
            .saturating_add(read("rx_missed_errors").unwrap_or(0)),
        rx_errors: read("rx_errors").unwrap_or(0),
        tx_errors: read("tx_errors").unwrap_or(0),
        rx_no_mbuf: 0,
    };
    Some((counters, read("tx_dropped").unwrap_or(0)))
}

/// A sysfs file holding one unsigned number; `None` if it cannot be read or is negative, as
/// `speed` is while the link is down.
fn read_u64(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{KernelPorts, Kif, counters, read_u64, subtract};
    use net::interface::InterfaceIndex;
    use std::path::PathBuf;

    /// A fresh directory for one test.
    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("kernel-report-{}-{test}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn counters_come_from_the_statistics_directory() {
        let dir = scratch("counters");
        for (name, value) in [
            ("rx_packets", "10"),
            ("tx_packets", "20"),
            ("rx_bytes", "1000"),
            ("tx_bytes", "2000"),
            ("rx_dropped", "3"),
            ("rx_missed_errors", "4"),
            ("rx_errors", "5"),
            ("tx_errors", "6"),
            ("tx_dropped", "7"),
        ] {
            std::fs::write(dir.join(name), format!("{value}\n")).unwrap();
        }
        let (counters, tx_dropped) = counters(&dir).unwrap();
        assert_eq!(counters.rx_packets, 10);
        assert_eq!(counters.tx_bytes, 2000);
        assert_eq!(counters.rx_missed, 7);
        assert_eq!(counters.tx_errors, 6);
        assert_eq!(tx_dropped, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The loopback interface exists wherever the tests run, and has counters and a carrier.
    #[test]
    fn the_loopback_is_reported() {
        if !std::path::Path::new("/sys/class/net/lo/statistics").exists() {
            return;
        }
        let lo = Kif {
            ifindex: InterfaceIndex::try_new(1).unwrap(),
            mac: None,
            mtu: Some(65536),
            name: "lo".to_string(),
        };
        let mut ports = KernelPorts::new(&[lo]);
        let first = ports.report();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].name, "lo");
        // The first reading is the baseline: the report counts from the driver's start.
        assert_eq!(first[0].counters, Some(stats::PortCounters::default()));
        assert_eq!(first[0].tx_discards, 0);
        assert!(first[0].counters_since.is_some());
        assert!(first[0].last_change.is_some());
        assert_eq!(first[0].link_changes, 0);
        // The loopback's MTU is usually 65536, too large for the report, so expect the fallback
        let mtu = read_u64(std::path::Path::new("/sys/class/net/lo/mtu"));
        assert_eq!(
            first[0].mtu,
            mtu.and_then(|mtu| u16::try_from(mtu).ok()).unwrap_or(0)
        );
        assert!(first[0].rates.is_none(), "no rates from a single reading");
        let second = ports.report();
        assert!(second[0].rates.is_some());
    }

    #[test]
    fn a_negative_or_missing_number_is_none() {
        let dir = scratch("missing");
        let speed = dir.join("speed");
        std::fs::write(&speed, "-1\n").unwrap();
        assert_eq!(read_u64(&speed), None);
        assert_eq!(read_u64(&dir.join("absent")), None);
        assert!(counters(&dir).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn counters_count_from_the_baseline_unless_reset() {
        let reading = |rx_bytes, drops| {
            (
                stats::PortCounters {
                    rx_bytes,
                    tx_errors: 1,
                    ..stats::PortCounters::default()
                },
                drops,
            )
        };
        let (since, drops) = subtract(reading(1000, 7), reading(400, 2)).unwrap();
        assert_eq!(since.rx_bytes, 600);
        assert_eq!(since.tx_errors, 0);
        assert_eq!(drops, 5);
        // A counter below its baseline: the kernel reset them.
        assert!(subtract(reading(100, 7), reading(400, 2)).is_none());
        assert!(subtract(reading(1000, 1), reading(400, 2)).is_none());
    }
}
