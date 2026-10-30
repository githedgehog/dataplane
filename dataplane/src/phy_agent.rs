// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ask `mstlink` about each NVIDIA/Mellanox port's physical layer and PCIe link, and publish what
//! it says.
//!
//! Every NVIDIA/Mellanox port gets a task that runs `mstlink` against the port's PCI function
//! every interval: once for link state, counters, bit error rates and the eye; once for the FEC
//! histogram if the link uses FEC; and once for the PCIe link. See [`mstlink`] for why this
//! shells out.
//!
//! `mstlink` needs `CAP_SYS_ADMIN`, and a child process inherits the capabilities of the thread
//! that starts it; the agent shares the transceiver agent's one-thread runtime, which is where
//! those capabilities must be kept if the rest of the process gives them up.

use crate::drivers::cpbridge::{BridgePort, PortIdentity};
use common::cliprovider::{CliDataProvider, Heading};
use hardware::pci::address::PciAddress;
use lifecycle::{CancellationToken, Subsystem};
use mstlink::{FecHistogram, Pcie, PortReport, RunError, Runner};
use net::interface::InterfaceName;
use stats::{PcieMetrics, PhyMetrics};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

/// The PCI vendor id of NVIDIA's networking devices (Mellanox).
const MELLANOX: &str = "0x15b3";

/// Start asking about every NVIDIA/Mellanox port in `ports`, every `interval`, on `handle`.
pub(crate) fn start(
    handle: &tokio::runtime::Handle,
    metrics: &Subsystem,
    ports: &[BridgePort],
    interval: Duration,
    publish: &watch::Sender<PhySnapshot>,
) {
    for port in ports {
        metrics.spawn_on(
            watch_port(
                port.clone(),
                Runner::default(),
                interval,
                publish.clone(),
                metrics.cancel_token(),
            ),
            handle,
        );
    }
}

async fn watch_port(
    port: BridgePort,
    runner: Runner,
    interval: Duration,
    publish: watch::Sender<PhySnapshot>,
    cancel: CancellationToken,
) {
    let name = port.name.to_string();
    let show = |reading: PortPhy| {
        publish.send_modify(|snapshot| {
            snapshot.ports.insert(port.name.clone(), reading);
        });
    };
    let pci = match pci_address(port.identity.clone(), &cancel).await {
        None => return,
        Some(None) => {
            show(PortPhy::Unread("the port is not a PCI device".to_owned()));
            return;
        }
        Some(Some(pci)) => pci,
    };
    if !is_mellanox(pci) {
        debug!("port {name} is not an NVIDIA/Mellanox device; mstlink has nothing to say");
        show(PortPhy::Unread(format!(
            "{pci} is not an NVIDIA/Mellanox device, so mstlink has nothing to say"
        )));
        return;
    }
    let address = pci.to_string();
    let mut phy = PhyMetrics::new(&name);
    let mut pcie = PcieMetrics::new(&name);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut failing: Option<String> = None;

    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let reading = match runner.port(&address).await {
            Ok(report) => {
                if failing.take().is_some() {
                    info!("port {name}: mstlink answers again");
                }
                let uses_fec = report
                    .operational
                    .fec
                    .as_deref()
                    .is_some_and(|fec| fec != "No FEC");
                phy.publish(&report);
                let fec = if uses_fec {
                    match runner.fec_histogram(&address).await {
                        Ok(histogram) => {
                            phy.publish_fec(&histogram);
                            Some(histogram)
                        }
                        Err(e) => {
                            debug!("port {name}: no FEC histogram: {e}");
                            None
                        }
                    }
                } else {
                    None
                };
                Some((report, fec))
            }
            Err(RunError::Spawn(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("mstlink is not installed, so port {name} has no physical layer readings");
                show(PortPhy::Unread("mstlink is not installed".to_owned()));
                return;
            }
            Err(e) => {
                let now = e.to_string();
                if failing.as_ref() != Some(&now) {
                    warn!("port {name}: mstlink gave no report: {now}");
                    failing = Some(now.clone());
                }
                show(PortPhy::Unread(format!("mstlink gave no report: {now}")));
                None
            }
        };
        let link = match runner.pcie(&address).await {
            Ok(link) => {
                pcie.publish(&link);
                Some(link)
            }
            Err(e) => {
                debug!("port {name}: no PCIe report: {e}");
                None
            }
        };
        if let Some((report, fec)) = reading {
            show(PortPhy::Read {
                pci,
                report: Box::new(report),
                fec,
                pcie: link,
                at: clock::now(),
            });
        }
    }
}

/// The PCI function behind the port, once the driver has reported it.
///
/// `Some(None)` if the port is not a PCI device; [`None`] on cancellation.
async fn pci_address(
    mut identity: watch::Receiver<Option<PortIdentity>>,
    cancel: &CancellationToken,
) -> Option<Option<PciAddress>> {
    loop {
        if let Some(reported) = identity.borrow_and_update().as_ref() {
            return Some(reported.pci_address);
        }
        tokio::select! {
            () = cancel.cancelled() => return None,
            changed = identity.changed() => changed.ok()?,
        }
    }
}

/// Whether the function is NVIDIA/Mellanox's. Sysfs's PCI tree is the same in every network
/// namespace, so this works wherever the agent runs.
fn is_mellanox(pci: PciAddress) -> bool {
    std::fs::read_to_string(format!("/sys/bus/pci/devices/{pci}/vendor"))
        .is_ok_and(|vendor| vendor.trim() == MELLANOX)
}

/// What `mstlink` last said about every NVIDIA/Mellanox port, for `show link`.
#[derive(Debug, Default)]
pub(crate) struct PhySnapshot {
    ports: BTreeMap<InterfaceName, PortPhy>,
}

/// What `mstlink` last said about one port.
#[derive(Debug)]
enum PortPhy {
    /// Its report, FEC histogram and PCIe link, and when they were read.
    Read {
        pci: PciAddress,
        report: Box<PortReport>,
        fec: Option<FecHistogram>,
        pcie: Option<Pcie>,
        at: clock::Instant,
    },
    /// Why there is no report: not a Mellanox device, no `mstlink`, a failed run.
    Unread(String),
}

/// `show link`.
pub(crate) struct PhyCli(pub(crate) watch::Receiver<PhySnapshot>);

impl CliDataProvider for PhyCli {
    fn provide(&self) -> String {
        let snapshot = self.0.borrow();
        let now = clock::now();
        let mut out = String::new();
        let _ = write!(out, "{}", Heading("Port links (mstlink)"));
        if snapshot.ports.is_empty() {
            let _ = writeln!(out, " (no port has been asked about yet)");
        }
        for (port, reading) in &snapshot.ports {
            let _ = match reading {
                PortPhy::Unread(why) => writeln!(out, "\n {port}: {why}"),
                PortPhy::Read {
                    pci,
                    report,
                    fec,
                    pcie,
                    at,
                } => render_port(
                    &mut out,
                    port,
                    *pci,
                    report,
                    fec.as_ref(),
                    pcie.as_ref(),
                    now.saturating_duration_since(*at),
                ),
            };
        }
        out
    }
}

/// A value `mstlink` reported, or `-` for one it did not.
fn or_dash<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

/// A bit error rate, in the scientific notation `mstlink` prints.
fn ber(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.2e}"))
}

fn render_port(
    out: &mut String,
    port: &InterfaceName,
    pci: PciAddress,
    report: &PortReport,
    fec: Option<&FecHistogram>,
    pcie: Option<&Pcie>,
    age: Duration,
) -> std::fmt::Result {
    let operational = &report.operational;
    writeln!(
        out,
        "\n {port} ({pci}): {} {} {} (read {} s ago)",
        or_dash(operational.state.as_deref()),
        or_dash(operational.speed.as_deref()),
        or_dash(operational.width.as_deref()),
        age.as_secs(),
    )?;
    writeln!(
        out,
        "   physical state {}  FEC {}  auto-negotiation {}",
        or_dash(operational.physical_state.as_deref()),
        or_dash(operational.fec.as_deref()),
        or_dash(operational.auto_negotiation.as_deref()),
    )?;
    let troubleshooting = &report.troubleshooting;
    writeln!(
        out,
        "   troubleshooting: status {}{}  {}",
        or_dash(troubleshooting.status_opcode),
        troubleshooting
            .group_opcode
            .as_deref()
            .map(|group| format!(" ({group})"))
            .unwrap_or_default(),
        or_dash(troubleshooting.recommendation.as_deref()),
    )?;
    if let Some(counters) = &report.counters {
        writeln!(
            out,
            "   effective BER {}  raw BER {}  uncorrected errors {}  link down {}  error \
             recovery {}  since clear {} min",
            ber(counters.effective_ber),
            ber(counters.raw_ber),
            or_dash(counters.effective_errors),
            or_dash(counters.link_down),
            or_dash(counters.link_error_recovery),
            counters
                .minutes_since_clear
                .map_or_else(|| "-".to_owned(), |minutes| format!("{minutes:.0}")),
        )?;
    }
    render_lanes(out, report)?;
    if let Some(fec) = fec.filter(|fec| !fec.bins.is_empty()) {
        let bins: Vec<String> = fec
            .bins
            .iter()
            .map(|(bin, count)| format!("{bin} {count}"))
            .collect();
        writeln!(out, "   FEC histogram: {}", bins.join("  "))?;
    }
    if let Some(pcie) = pcie {
        writeln!(
            out,
            "   PCIe: gen {} of {}  x{} of x{}  BER {}  CRC errors {} DLLP {} TLP  rx errors {}  tx \
             errors {}",
            or_dash(pcie.generation_active),
            or_dash(pcie.generation_enabled),
            or_dash(pcie.width_active),
            or_dash(pcie.width_enabled),
            ber(pcie.effective_ber),
            or_dash(pcie.crc_errors_dllp),
            or_dash(pcie.crc_errors_tlp),
            or_dash(pcie.rx_errors),
            or_dash(pcie.tx_errors),
        )?;
    }
    Ok(())
}

/// Per lane bit errors and the eye, in one table.
fn render_lanes(out: &mut String, report: &PortReport) -> std::fmt::Result {
    let counters = report.counters.as_ref();
    let eye = report.eye.as_ref();
    let lanes = [
        counters.map_or(0, |c| c.raw_ber_per_lane.len()),
        counters.map_or(0, |c| c.raw_errors_per_lane.len()),
        eye.map_or(0, |eye| eye.lanes.len()),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    if lanes == 0 {
        return Ok(());
    }
    writeln!(
        out,
        "   {:<5} {:>10} {:>14} {:>12} {:>9} {:>17}",
        "lane", "raw BER", "raw errors", "initial FOM", "last FOM", "upper/mid/lower"
    )?;
    for lane in 0..lanes {
        let raw_ber = counters.and_then(|c| c.raw_ber_per_lane.get(lane).copied().flatten());
        let raw_errors = counters.and_then(|c| c.raw_errors_per_lane.get(lane).copied().flatten());
        let eye = eye.and_then(|eye| eye.lanes.get(lane));
        let grades = eye
            .filter(|eye| eye.upper_grade.is_some() || eye.mid_grade.is_some())
            .map(|eye| {
                format!(
                    "{}/{}/{}",
                    or_dash(eye.upper_grade),
                    or_dash(eye.mid_grade),
                    or_dash(eye.lower_grade)
                )
            });
        writeln!(
            out,
            "   {:<5} {:>10} {:>14} {:>12} {:>9} {:>17}",
            eye.map_or(lane, |eye| eye.lane as usize),
            ber(raw_ber),
            or_dash(raw_errors),
            or_dash(eye.and_then(|eye| eye.initial_fom)),
            or_dash(eye.and_then(|eye| eye.last_fom)),
            or_dash(grades),
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::InterfaceName;

    #[test]
    fn show_link_says_what_mstlink_said() {
        use mstlink::{Counters, Eye, EyeLane, Operational, Troubleshooting};
        let (publish, read) = watch::channel(PhySnapshot::default());
        let cli = PhyCli(read);
        assert!(cli.provide().contains("no port has been asked about yet"));

        let report = PortReport {
            operational: Operational {
                state: Some("Active".into()),
                physical_state: Some("LinkUp".into()),
                speed: Some("400G".into()),
                width: Some("4x".into()),
                fec: Some("Standard_RS-FEC - (544,514)".into()),
                auto_negotiation: Some("ON".into()),
            },
            troubleshooting: Troubleshooting {
                status_opcode: Some(0),
                group_opcode: Some("N/A".into()),
                recommendation: Some("No issue was observed".into()),
            },
            counters: Some(Counters {
                effective_ber: Some(1.5e-254),
                raw_ber: Some(3.2e-9),
                raw_ber_per_lane: vec![Some(3.1e-9), Some(3.3e-9)],
                raw_errors_per_lane: vec![Some(12), Some(15)],
                effective_errors: Some(0),
                link_down: Some(1),
                link_error_recovery: Some(0),
                minutes_since_clear: Some(42.0),
            }),
            eye: Some(Eye {
                fom_mode: None,
                lanes: vec![
                    EyeLane {
                        lane: 0,
                        initial_fom: Some(80),
                        last_fom: Some(78),
                        upper_grade: Some(30),
                        mid_grade: Some(28),
                        lower_grade: Some(31),
                    },
                    EyeLane {
                        lane: 1,
                        ..EyeLane::default()
                    },
                ],
            }),
        };
        publish.send_modify(|snapshot| {
            snapshot.ports.insert(
                InterfaceName::try_from("eth0").unwrap(),
                PortPhy::Read {
                    pci: PciAddress::try_from("0000:02:00.0").unwrap(),
                    report: Box::new(report),
                    fec: Some(FecHistogram {
                        bins: vec![("[0]".into(), 1_000), ("[1]".into(), 7)],
                    }),
                    pcie: Some(Pcie {
                        generation_active: Some(4),
                        generation_enabled: Some(4),
                        width_active: Some(8),
                        width_enabled: Some(16),
                        ..Pcie::default()
                    }),
                    at: clock::now(),
                },
            );
            snapshot.ports.insert(
                InterfaceName::try_from("eth1").unwrap(),
                PortPhy::Unread("mstlink is not installed".into()),
            );
        });
        let shown = cli.provide();
        assert!(
            shown.contains("eth0 (0000:02:00.0): Active 400G 4x"),
            "{shown}"
        );
        assert!(shown.contains("FEC Standard_RS-FEC - (544,514)"), "{shown}");
        assert!(shown.contains("No issue was observed"), "{shown}");
        assert!(shown.contains("raw BER 3.20e-9"), "{shown}");
        assert!(shown.contains("30/28/31"), "{shown}");
        assert!(shown.contains("FEC histogram: [0] 1000  [1] 7"), "{shown}");
        assert!(shown.contains("PCIe: gen 4 of 4  x8 of x16"), "{shown}");
        assert!(shown.contains("eth1: mstlink is not installed"), "{shown}");
    }

    /// Run one port's agent against the NVIDIA/Mellanox function at
    /// `DATAPLANE_TEST_MSTLINK_PCI`, with `mstlink` from `DATAPLANE_TEST_MSTLINK` (or `PATH`), and
    /// check what it publishes.
    ///
    /// Needs `CAP_SYS_ADMIN`, so it only runs when asked:
    /// `sudo DATAPLANE_TEST_MSTLINK_PCI=0000:02:00.0 DATAPLANE_TEST_MSTLINK=$(which mstlink)
    /// <test binary> --ignored reads_a_real_port`.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs CAP_SYS_ADMIN, mstlink and an NVIDIA/Mellanox port"]
    async fn reads_a_real_port() {
        let pci = std::env::var("DATAPLANE_TEST_MSTLINK_PCI")
            .expect("set DATAPLANE_TEST_MSTLINK_PCI to the port's PCI address");
        let pci = PciAddress::try_from(pci.as_str()).unwrap();
        let runner = std::env::var_os("DATAPLANE_TEST_MSTLINK")
            .map_or_else(Runner::default, |program| {
                Runner::default().program(program)
            });
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let scrape = recorder.handle();
        // Thread-local, and this runtime has one thread, so the agent's task records here too.
        let _recording = metrics::set_default_local_recorder(&recorder);

        let (_link, link) = watch::channel(lldp::Link::Up);
        let (_identity, identity) = watch::channel(Some(PortIdentity {
            name: InterfaceName::try_from("under-test").unwrap(),
            mac: SourceMac::new(Mac([0x02, 0, 0, 0, 0, 1])).unwrap(),
            mtu: None,
            hardware: None,
            datapath_index: None,
            pci_address: Some(pci),
        }));
        let (inject, _) = crate::drivers::cpbridge::inject_channel(1).unwrap();
        let port = BridgePort {
            name: InterfaceName::try_from("under-test").unwrap(),
            inject,
            link,
            identity,
        };
        let cancel = CancellationToken::new();
        let (publish, read) = watch::channel(PhySnapshot::default());
        let agent = tokio::spawn(watch_port(
            port,
            runner,
            Duration::from_secs(60),
            publish,
            cancel.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        cancel.cancel();
        agent.await.unwrap();

        let shown = PhyCli(read).provide();
        assert!(shown.contains("under-test ("), "{shown}");
        assert!(shown.contains("troubleshooting: status 0"), "{shown}");

        let text = scrape.render();
        let series = |prefix: &str| {
            text.lines()
                .find(|line| line.starts_with(prefix))
                .unwrap_or_else(|| panic!("no {prefix}:\n{text}"))
                .to_string()
        };
        assert!(series("port_phy_info{").ends_with(" 1"), "{text}");
        assert!(
            series("port_phy_troubleshooting_status{").ends_with(" 0"),
            "{text}"
        );
        assert!(
            series("port_pcie_width{").contains("port=\"under-test\""),
            "{text}"
        );
    }
}
