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
use hardware::pci::address::PciAddress;
use lifecycle::{CancellationToken, Subsystem};
use mstlink::{RunError, Runner};
use stats::{PcieMetrics, PhyMetrics};
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
) {
    for port in ports {
        metrics.spawn_on(
            watch_port(
                port.clone(),
                Runner::default(),
                interval,
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
    cancel: CancellationToken,
) {
    let name = port.name.to_string();
    let Some(pci) = pci_address(port.identity.clone(), &cancel).await else {
        return;
    };
    if !is_mellanox(pci) {
        debug!("port {name} is not an NVIDIA/Mellanox device; mstlink has nothing to say");
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
        match runner.port(&address).await {
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
                if uses_fec {
                    match runner.fec_histogram(&address).await {
                        Ok(histogram) => phy.publish_fec(&histogram),
                        Err(e) => debug!("port {name}: no FEC histogram: {e}"),
                    }
                }
            }
            Err(RunError::Spawn(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("mstlink is not installed, so port {name} has no physical layer readings");
                return;
            }
            Err(e) => {
                let now = e.to_string();
                if failing.as_ref() != Some(&now) {
                    warn!("port {name}: mstlink gave no report: {now}");
                    failing = Some(now);
                }
            }
        }
        match runner.pcie(&address).await {
            Ok(link) => pcie.publish(&link),
            Err(e) => debug!("port {name}: no PCIe report: {e}"),
        }
    }
}

/// The PCI function behind the port, once the driver has reported it.
///
/// [`None`] if the port is not a PCI device, or on cancellation.
async fn pci_address(
    mut identity: watch::Receiver<Option<PortIdentity>>,
    cancel: &CancellationToken,
) -> Option<PciAddress> {
    loop {
        if let Some(reported) = identity.borrow_and_update().as_ref() {
            return reported.pci_address;
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

#[cfg(test)]
mod tests {
    use super::*;
    use net::eth::mac::Mac;
    use net::interface::InterfaceName;
    use tokio::sync::mpsc;

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
            name: "under-test".to_owned(),
            mac: Mac([0x02, 0, 0, 0, 0, 1]),
            mtu: None,
            hardware: None,
            datapath_index: None,
            pci_address: Some(pci),
        }));
        let (inject, _) = mpsc::channel(1);
        let port = BridgePort {
            name: InterfaceName::try_from("under-test").unwrap(),
            inject,
            link,
            identity,
        };
        let cancel = CancellationToken::new();
        let agent = tokio::spawn(watch_port(
            port,
            runner,
            Duration::from_secs(60),
            cancel.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(2_000)).await;
        cancel.cancel();
        agent.await.unwrap();

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
