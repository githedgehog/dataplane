// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read each port's pluggable module (transceiver or cable) and publish what it says.
//!
//! Every port gets a task that waits for the driver to say which kernel netdev backs it, reads the
//! whole module once, then re-reads only its monitors and flags every interval. It reads the whole
//! module again when the link comes back up, since the module may have been swapped while it was
//! down, and every [`FULL_READ_EVERY`] polls in case a swap was too quick for the link poll to see.
//!
//! Reads go through the kernel's ethtool netlink interface, which needs a socket in the datapath
//! namespace (where the netdevs are), `CAP_NET_ADMIN`, and a thread that may block: the kernel
//! answers each read with a firmware transaction on the module's bus. So the agent runs on a
//! runtime of its own, whose threads live in the datapath namespace; see
//! [`crate::runtime`]'s `netns_runtime`.

use crate::drivers::cpbridge::BridgePort;
use lifecycle::CancellationToken;
use lifecycle::Subsystem;
use lldp::Link;
use stats::TransceiverMetrics;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};
use transceiver::ethtool::{Error, EthtoolEeprom};
use transceiver::{Capture, Image, Module, ReadError};

/// Polls between full reads of a module that is not known to have changed.
const FULL_READ_EVERY: u32 = 10;

/// Start reading the modules of every port in `ports`, every `interval`, on `handle`.
///
/// `handle` must belong to a runtime whose threads are in the datapath namespace: the netlink
/// socket is opened from one of them.
pub(crate) fn start(
    handle: &tokio::runtime::Handle,
    metrics: &Subsystem,
    ports: &[BridgePort],
    interval: Duration,
) {
    let opened = handle.block_on(handle.spawn(async { ethtool2::new_connection() }));
    let (connection, ethtool) = match opened {
        Ok(Ok(opened)) => opened,
        Ok(Err(e)) => {
            warn!("could not open an ethtool netlink socket; no transceiver readings: {e}");
            return;
        }
        Err(e) => {
            warn!("could not open an ethtool netlink socket; no transceiver readings: {e}");
            return;
        }
    };
    let cancel = metrics.cancel_token();
    metrics.spawn_on(
        async move {
            tokio::select! {
                () = cancel.cancelled() => {}
                () = connection => {}
            }
        },
        handle,
    );
    for port in ports {
        metrics.spawn_on(
            watch_port(
                port.clone(),
                ethtool.clone(),
                interval,
                metrics.cancel_token(),
            ),
            handle,
        );
    }
}

/// What the last attempt to read a port's module found, to log only what changes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Nothing,
    Module { serial_number: String },
    Absent,
}

async fn watch_port(
    port: BridgePort,
    ethtool: ethtool2::Handle,
    interval: Duration,
    cancel: CancellationToken,
) {
    let name = port.name.to_string();
    let Some(index) = datapath_index(&name, port.identity.clone(), &cancel).await else {
        return;
    };
    let eeprom = EthtoolEeprom::new(ethtool, index);
    let mut metrics = TransceiverMetrics::new(&name);
    let mut link = port.link.clone();
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut image: Option<Image> = None;
    let mut polls = 0u32;
    let mut seen = Seen::Nothing;

    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            _ = ticker.tick() => {}
            changed = link.changed() => {
                if changed.is_err() {
                    // The driver is gone; keep reading on schedule until cancelled.
                    link = watch::channel(Link::Down).1;
                    continue;
                }
                if *link.borrow_and_update() != Link::Up {
                    continue;
                }
                debug!("port {name}: link up, reading its module afresh");
                image = None;
                ticker.reset();
            }
        }

        polls = polls.wrapping_add(1);
        let capture = match image.take() {
            Some(known) if !polls.is_multiple_of(FULL_READ_EVERY) => Capture::refresh(known),
            _ => Capture::new(),
        };
        match eeprom.capture(capture).await {
            Ok((module, read)) => {
                note_module(&name, &module, &mut seen);
                metrics.publish(&module);
                image = Some(read);
            }
            Err(error) => {
                metrics.absent();
                if !note_failure(&name, &error, &mut seen) {
                    return;
                }
            }
        }
    }
}

/// The index of the port's netdev in the datapath namespace, once the driver has reported it.
///
/// [`None`] if the port has no netdev (a device bound to vfio-pci, say), or on cancellation.
async fn datapath_index(
    name: &str,
    mut identity: watch::Receiver<Option<crate::drivers::cpbridge::PortIdentity>>,
    cancel: &CancellationToken,
) -> Option<u32> {
    loop {
        if let Some(reported) = identity.borrow_and_update().as_ref() {
            if let Some(index) = reported.datapath_index {
                return Some(index.to_u32());
            }
            info!("port {name} has no kernel netdev, so its module cannot be read");
            return None;
        }
        tokio::select! {
            () = cancel.cancelled() => return None,
            changed = identity.changed() => changed.ok()?,
        }
    }
}

fn note_module(name: &str, module: &Module, seen: &mut Seen) {
    let inventory = &module.inventory;
    let now = Seen::Module {
        serial_number: inventory.serial_number.clone(),
    };
    if *seen != now {
        info!(
            "port {name}: {} module {} {} (serial {}, revision {})",
            module.identifier.name(),
            inventory.vendor,
            inventory.part_number,
            inventory.serial_number,
            inventory.revision,
        );
        *seen = now;
    }
}

/// Log a failed read if it says something new. Returns whether reading is worth trying again.
fn note_failure(name: &str, error: &ReadError<Error>, seen: &mut Seen) -> bool {
    if let ReadError::Identity(Error::Ethtool(cause)) = error {
        match cause {
            ethtool2::Error::Unsupported => {
                info!("port {name}: the driver cannot read pluggable modules");
                return false;
            }
            ethtool2::Error::PermissionDenied => {
                warn!(
                    "port {name}: reading its pluggable module needs CAP_NET_ADMIN, which this \
                     process lacks; no transceiver readings"
                );
                return false;
            }
            _ => {}
        }
    }
    if *seen != Seen::Absent {
        info!("port {name}: no pluggable module could be read: {error}");
        *seen = Seen::Absent;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::cpbridge::PortIdentity;
    use net::eth::mac::Mac;
    use net::interface::{InterfaceIndex, InterfaceName};
    use tokio::sync::mpsc;
    use transceiver::DecodeError;
    use transceiver::sff8024::Identifier;

    fn refused(error: ethtool2::Error) -> ReadError<Error> {
        ReadError::Identity(Error::Ethtool(error))
    }

    #[test]
    fn a_read_that_can_never_succeed_stops_the_port() {
        let mut seen = Seen::Nothing;
        assert!(!note_failure(
            "eth0",
            &refused(ethtool2::Error::PermissionDenied),
            &mut seen
        ));
        assert!(!note_failure(
            "eth0",
            &refused(ethtool2::Error::Unsupported),
            &mut seen
        ));
    }

    #[test]
    fn an_empty_cage_is_retried() {
        let mut seen = Seen::Module {
            serial_number: "C2606276848".into(),
        };
        let empty = refused(ethtool2::Error::NoSuchDevice { device: None });
        assert!(note_failure("eth0", &empty, &mut seen));
        assert_eq!(seen, Seen::Absent);
        let unknown = ReadError::Decode(DecodeError::Unsupported(Identifier::from_raw(0x06)));
        assert!(note_failure("eth0", &unknown, &mut seen));
    }

    /// Run one port's agent against the real module behind interface index
    /// `DATAPLANE_TEST_TRANSCEIVER_IFINDEX` and check what it publishes.
    ///
    /// Needs `CAP_NET_ADMIN` and a port with a module plugged in, so it only runs when asked:
    /// `sudo -E DATAPLANE_TEST_TRANSCEIVER_IFINDEX=5 cargo test -- --ignored reads_a_real_module`.
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs CAP_NET_ADMIN and a port with a pluggable module"]
    async fn reads_a_real_module() {
        let ifindex: u32 = std::env::var("DATAPLANE_TEST_TRANSCEIVER_IFINDEX")
            .expect("set DATAPLANE_TEST_TRANSCEIVER_IFINDEX to the port's interface index")
            .parse()
            .unwrap();
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let scrape = recorder.handle();
        // Thread-local, and this runtime has one thread, so the agent's task records here too.
        let _recording = metrics::set_default_local_recorder(&recorder);

        let (connection, ethtool) = ethtool2::new_connection().unwrap();
        tokio::spawn(connection);
        let (_link, link) = watch::channel(Link::Up);
        let (_identity, identity) = watch::channel(Some(PortIdentity {
            name: "under-test".to_owned(),
            mac: Mac([0x02, 0, 0, 0, 0, 1]),
            mtu: None,
            hardware: None,
            datapath_index: Some(InterfaceIndex::try_new(ifindex).unwrap()),
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
            ethtool,
            Duration::from_millis(100),
            cancel.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        cancel.cancel();
        agent.await.unwrap();

        let text = scrape.render();
        assert!(
            text.contains("transceiver_present{port=\"under-test\"} 1"),
            "no module was read:\n{text}"
        );
        let info = text
            .lines()
            .find(|line| line.starts_with("transceiver_info{"))
            .unwrap_or_else(|| panic!("no transceiver_info:\n{text}"));
        assert!(
            info.contains("port=\"under-test\"") && info.ends_with(" 1"),
            "{info}"
        );
        assert!(
            text.lines()
                .any(|line| line.starts_with("transceiver_temperature_celsius{")
                    && !line.ends_with("NaN")),
            "{text}"
        );
    }
}
