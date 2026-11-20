// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What the kernel driver reports about its interfaces.
//!
//! The kernel keeps the link state and counters of each interface; this reads them from sysfs,
//! and the speed, duplex and autonegotiation from ethtool netlink, so the driver can report its
//! ports the way the DPDK driver does. Reads go through the calling thread's namespace and sysfs,
//! so they must run on the driver's threads, which live in the datapath namespace.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ethtool2::Duplex;
use lldp::Link;
use tracing::{debug, warn};

use super::kif::Kif;
use crate::drivers::status::{PortReport, RateMeter};

/// An ethtool netlink connection, on a runtime of its own, since the supervisor is not async.
struct Ethtool {
    runtime: tokio::runtime::Runtime,
    handle: ethtool2::Handle,
}

impl Ethtool {
    /// Open a connection in the calling thread's namespace.
    fn open() -> Option<Self> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .inspect_err(|e| warn!("no runtime for ethtool netlink ({e}); no port speeds"))
            .ok()?;
        let (connection, handle) = runtime
            .block_on(async { ethtool2::new_connection() })
            .inspect_err(|e| warn!("no ethtool netlink socket ({e}); no port speeds"))
            .ok()?;
        // A current-thread runtime drives the connection whenever a query blocks on it.
        runtime.spawn(connection);
        Some(Self { runtime, handle })
    }

    /// The link modes of `name`, or `None` if the kernel would not say.
    fn link_modes(&self, name: &str) -> Option<ethtool2::LinkModes> {
        self.runtime
            .block_on(self.handle.link_modes(name))
            .inspect_err(|e| debug!("no link modes for {name}: {e}"))
            .ok()
    }
}

/// One interface, and what is kept between readings to report on it.
struct KernelPort {
    kif: Kif,
    /// `carrier_changes` at the first reading, to count changes from the driver's start.
    baseline_changes: Option<u64>,
    /// `carrier_changes` at the last reading, to notice a flap between readings.
    last_changes: Option<u64>,
    /// Whether the link was up at the last reading; `None` before the first.
    up: Option<bool>,
    last_change: Option<SystemTime>,
    rates: RateMeter,
}

/// The kernel driver's interfaces, to report on.
pub(super) struct KernelPorts {
    ports: Vec<KernelPort>,
    ethtool: Option<Ethtool>,
    /// When the driver started, which stands in for when the counters started: the kernel's run
    /// since the interfaces were created, which the driver cannot tell.
    started: SystemTime,
}

impl KernelPorts {
    /// Report on `interfaces`; call from a thread in their namespace.
    pub(super) fn new(interfaces: &[Kif]) -> Self {
        Self {
            ports: interfaces
                .iter()
                .map(|kif| KernelPort {
                    kif: kif.clone(),
                    baseline_changes: None,
                    last_changes: None,
                    up: None,
                    last_change: None,
                    rates: RateMeter::default(),
                })
                .collect(),
            ethtool: Ethtool::open(),
            started: clock::system_now(),
        }
    }

    /// Read every interface.
    pub(super) fn report(&mut self) -> Vec<PortReport> {
        let ethtool = self.ethtool.as_ref();
        self.ports
            .iter_mut()
            .map(|port| port.report(ethtool, self.started))
            .collect()
    }
}

impl KernelPort {
    fn report(&mut self, ethtool: Option<&Ethtool>, started: SystemTime) -> PortReport {
        let sysfs = PathBuf::from("/sys/class/net").join(&self.kif.name);
        let up = self.kif.link() == Link::Up;
        let changes = read_u64(&sysfs.join("carrier_changes"));
        let baseline = *self.baseline_changes.get_or_insert(changes.unwrap_or(0));
        let flapped = changes.is_some() && changes != self.last_changes;
        if self.up.is_none_or(|was| was != up) || flapped {
            self.last_change = Some(clock::system_now());
        }
        self.up = Some(up);
        self.last_changes = changes;

        let counters = counters(&sysfs.join("statistics"));
        let modes = ethtool.and_then(|ethtool| ethtool.link_modes(&self.kif.name));
        PortReport {
            name: self.kif.name.clone(),
            hardware: self.kif.hardware(),
            mac: self.kif.mac.map(|mac| mac.to_string()).unwrap_or_default(),
            mtu: self
                .kif
                .mtu
                .and_then(|mtu| u16::try_from(mtu).ok())
                .unwrap_or(0),
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
            link_changes: changes.map_or(0, |changes| changes.saturating_sub(baseline)),
            last_change: self.last_change,
            counters: counters.map(|(counters, _)| counters),
            tx_discards: counters.map_or(0, |(_, tx_dropped)| tx_dropped),
            rates: counters.and_then(|(counters, _)| self.rates.update(counters, clock::now())),
            counters_since: Some(started),
            ..PortReport::default()
        }
    }
}

/// An interface's counters from its sysfs `statistics` directory, and its transmit drops.
///
/// The kernel's receive drops (`rx_dropped`, `rx_missed_errors`) count as missed frames, the
/// closest of [`stats::PortCounters`]'s fields.
fn counters(statistics: &Path) -> Option<(stats::PortCounters, u64)> {
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
    use super::{KernelPorts, Kif, counters, read_u64};
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
        assert!(first[0].counters.is_some());
        assert!(first[0].last_change.is_some());
        assert_eq!(first[0].link_changes, 0);
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
}
