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
use common::cliprovider::{CliDataProvider, Heading};
use lifecycle::CancellationToken;
use lifecycle::Subsystem;
use lldp::Link;
use net::interface::InterfaceName;
use stats::TransceiverMetrics;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};
use transceiver::ethtool::{Error, EthtoolEeprom};
use transceiver::{Bounds, Capture, Crossings, Image, LaneFlags, Module, ReadError};

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
    publish: &watch::Sender<ModuleSnapshot>,
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
                publish.clone(),
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
    publish: watch::Sender<ModuleSnapshot>,
    cancel: CancellationToken,
) {
    let name = port.name.to_string();
    let show = |reading: PortModule| {
        publish.send_modify(|snapshot| {
            snapshot.ports.insert(port.name.clone(), reading);
        });
    };
    let index = match datapath_index(&name, port.identity.clone(), &cancel).await {
        None => return,
        Some(None) => {
            show(PortModule::Unread(
                "the port has no kernel netdev".to_owned(),
            ));
            return;
        }
        Some(Some(index)) => index,
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
                show(PortModule::Read {
                    module: Box::new(module),
                    at: clock::now(),
                });
                image = Some(read);
            }
            Err(error) => {
                metrics.absent();
                let retry = note_failure(&name, &error, &mut seen);
                show(PortModule::Unread(error.to_string()));
                if !retry {
                    return;
                }
            }
        }
    }
}

/// The index of the port's netdev in the datapath namespace, once the driver has reported it.
///
/// `Some(None)` if the port has no netdev (a device bound to vfio-pci, say); [`None`] on
/// cancellation.
async fn datapath_index(
    name: &str,
    mut identity: watch::Receiver<Option<crate::drivers::cpbridge::PortIdentity>>,
    cancel: &CancellationToken,
) -> Option<Option<u32>> {
    loop {
        if let Some(reported) = identity.borrow_and_update().as_ref() {
            if let Some(index) = reported.datapath_index {
                return Some(Some(index.to_u32()));
            }
            info!("port {name} has no kernel netdev, so its module cannot be read");
            return Some(None);
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

/// What was last read from every port's module, for `show transceivers`.
#[derive(Debug, Default)]
pub(crate) struct ModuleSnapshot {
    ports: BTreeMap<InterfaceName, PortModule>,
}

/// What was last read from one port's module.
#[derive(Debug)]
enum PortModule {
    /// The module, and when it was read.
    Read {
        module: Box<Module>,
        at: clock::Instant,
    },
    /// Why nothing could be read: an empty cage, a driver that cannot read modules, and so on.
    Unread(String),
}

/// `show transceivers`.
pub(crate) struct ModulesCli(pub(crate) watch::Receiver<ModuleSnapshot>);

impl CliDataProvider for ModulesCli {
    fn provide(&self) -> String {
        let snapshot = self.0.borrow();
        let now = clock::now();
        let mut out = String::new();
        let _ = write!(out, "{}", Heading("Transceivers"));
        if snapshot.ports.is_empty() {
            let _ = writeln!(out, " (no port's module has been read yet)");
        }
        for (port, reading) in &snapshot.ports {
            let _ = match reading {
                PortModule::Unread(why) => writeln!(out, "\n {port}: {why}"),
                PortModule::Read { module, at } => {
                    render_module(&mut out, port, module, now.saturating_duration_since(*at))
                }
            };
        }
        out
    }
}

/// A reading, or `-` for a monitor the module does not implement.
fn or_dash<T: std::fmt::Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

fn render_module(
    out: &mut String,
    port: &InterfaceName,
    module: &Module,
    age: Duration,
) -> std::fmt::Result {
    let inventory = &module.inventory;
    writeln!(
        out,
        "\n {port}: {} {} {} (read {} s ago)",
        module.identifier.name(),
        inventory.vendor,
        inventory.part_number,
        age.as_secs(),
    )?;
    let wavelength = inventory
        .wavelength
        .map(|wavelength| format!("  wavelength {:.2} nm", wavelength.nanometres()))
        .unwrap_or_default();
    writeln!(
        out,
        "   serial {}  revision {}  date {}  connector {}{wavelength}",
        inventory.serial_number,
        inventory.revision,
        inventory.date_code,
        inventory.connector.name(),
    )?;
    writeln!(out, "   {}", memory_map(&module.detail))?;

    let monitors = &module.monitors;
    writeln!(
        out,
        "   temperature {}  supply {}",
        or_dash(monitors.temperature),
        or_dash(monitors.supply)
    )?;
    if !monitors.lanes.is_empty() {
        let rx = match monitors.rx_power_kind {
            transceiver::RxPowerKind::Average => "rx power",
            transceiver::RxPowerKind::Oma => "rx power (OMA)",
        };
        writeln!(
            out,
            "   {:<5} {:>10} {:>22} {:>22}",
            "lane", "tx bias", "tx power", rx
        )?;
        for (lane, reading) in monitors.lanes.iter().enumerate() {
            writeln!(
                out,
                "   {:<5} {:>10} {:>22} {:>22}",
                lane + 1,
                or_dash(reading.tx_bias),
                or_dash(reading.tx_power),
                or_dash(reading.rx_power),
            )?;
        }
    }

    if let Some(thresholds) = &module.thresholds {
        render_thresholds(out, thresholds)?;
    }
    if let Some(flags) = &module.flags {
        render_flags(out, flags)?;
    }
    Ok(())
}

/// The memory map, and what only it says about the module's state.
fn memory_map(detail: &transceiver::Detail) -> String {
    match detail {
        transceiver::Detail::Cmis(cmis) => {
            let data_path = cmis
                .data_path
                .iter()
                .map(|state| format!("{state:?}"))
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "CMIS {}.{}  state {:?}  firmware {}.{}  data path [{}]",
                cmis.revision.major,
                cmis.revision.minor,
                cmis.state,
                cmis.firmware.major,
                cmis.firmware.minor,
                if data_path.is_empty() {
                    "-"
                } else {
                    &data_path
                },
            )
        }
        transceiver::Detail::Sff8636(sff8636) => format!(
            "SFF-8636 ({}){}",
            sff8636.revision.name(),
            if sff8636.data_not_ready {
                "  monitors not ready yet"
            } else {
                ""
            },
        ),
        transceiver::Detail::Sff8472(sff8472) => format!(
            "SFF-8472 {}{}",
            sff8472
                .compliance_revision
                .revision()
                .unwrap_or("(revision unspecified)"),
            match sff8472.status {
                Some(status) if !status.data_ready => "  monitors not ready yet",
                _ => "",
            },
        ),
    }
}

fn render_thresholds(out: &mut String, thresholds: &transceiver::Thresholds) -> std::fmt::Result {
    fn row<T: std::fmt::Display>(
        out: &mut String,
        name: &str,
        bounds: Option<Bounds<T>>,
    ) -> std::fmt::Result {
        let Some(bounds) = bounds else {
            return Ok(());
        };
        writeln!(
            out,
            "   {:<12} {:>22} {:>22} {:>22} {:>22}",
            name,
            bounds.low_alarm.to_string(),
            bounds.low_warning.to_string(),
            bounds.high_warning.to_string(),
            bounds.high_alarm.to_string(),
        )
    }
    writeln!(
        out,
        "   {:<12} {:>22} {:>22} {:>22} {:>22}",
        "limits", "low alarm", "low warning", "high warning", "high alarm"
    )?;
    row(out, "temperature", thresholds.temperature)?;
    row(out, "supply", thresholds.supply)?;
    row(out, "tx bias", thresholds.tx_bias)?;
    row(out, "tx power", thresholds.tx_power)?;
    row(out, "rx power", thresholds.rx_power)
}

/// The limits a quantity has crossed, by name.
fn crossed(quantity: &str, crossings: Crossings, into: &mut Vec<String>) {
    let named = [
        (crossings.high_alarm, "high alarm"),
        (crossings.low_alarm, "low alarm"),
        (crossings.high_warning, "high warning"),
        (crossings.low_warning, "low warning"),
    ];
    for (set, name) in named {
        if set {
            into.push(format!("{quantity} {name}"));
        }
    }
}

/// The flags a lane has raised, by name.
fn raised(lane: &LaneFlags) -> Vec<String> {
    let mut raised: Vec<String> = [
        (lane.tx_fault, "tx fault"),
        (lane.tx_los, "tx LOS"),
        (lane.tx_lol, "tx CDR LOL"),
        (lane.rx_los, "rx LOS"),
        (lane.rx_lol, "rx CDR LOL"),
    ]
    .into_iter()
    .filter(|(set, _)| *set == Some(true))
    .map(|(_, name)| name.to_owned())
    .collect();
    crossed("tx bias", lane.tx_bias, &mut raised);
    crossed("tx power", lane.tx_power, &mut raised);
    crossed("rx power", lane.rx_power, &mut raised);
    raised
}

fn render_flags(out: &mut String, flags: &transceiver::Flags) -> std::fmt::Result {
    let mut module = Vec::new();
    crossed("temperature", flags.temperature, &mut module);
    crossed("supply", flags.supply, &mut module);
    let lanes: Vec<(usize, Vec<String>)> = flags
        .lanes
        .iter()
        .enumerate()
        .map(|(lane, flags)| (lane + 1, raised(flags)))
        .filter(|(_, raised)| !raised.is_empty())
        .collect();
    // SFF-8636 and CMIS clear their flags when read, so this is what the agent's last read saw.
    if module.is_empty() && lanes.is_empty() {
        return writeln!(out, "   flags: none raised at the last read");
    }
    writeln!(out, "   flags raised at the last read:")?;
    if !module.is_empty() {
        writeln!(out, "     module: {}", module.join(", "))?;
    }
    for (lane, raised) in lanes {
        writeln!(out, "     lane {lane}: {}", raised.join(", "))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drivers::cpbridge::PortIdentity;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::{InterfaceIndex, InterfaceName};
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

    /// An SFP with internally calibrated diagnostics: vendor "ACME", 39.5 C, a raised receive LOS.
    fn sfp() -> Module {
        use transceiver::{HALF, I2cAddress, Region};
        let mut a0 = [b' '; HALF];
        a0[0] = 0x03; // SFP
        a0[2] = 0x07; // LC
        a0[20..24].copy_from_slice(b"ACME");
        a0[40..48].copy_from_slice(b"SFP-10G1");
        a0[68..71].copy_from_slice(b"S42");
        a0[84..90].copy_from_slice(b"261019");
        a0[60..62].copy_from_slice(&850u16.to_be_bytes());
        a0[92] = 0x68; // diagnostics, internally calibrated, average rx power
        a0[93] = 0x90; // alarm and warning flags, soft RX_LOS
        a0[94] = 0x08;
        let mut a2 = [0u8; HALF];
        a2[96..98].copy_from_slice(&0x2780u16.to_be_bytes()); // 39.5 C
        a2[98..100].copy_from_slice(&33_000u16.to_be_bytes()); // 3.3 V
        a2[110] = 0x02; // RX_LOS
        a2[113] = 0x40; // rx power low alarm
        let mut image = Image::new();
        image.insert(Region::Lower(I2cAddress::A0), a0);
        image.insert(Region::Lower(I2cAddress::A2), a2);
        transceiver::decode(&image).unwrap()
    }

    #[test]
    fn show_transceivers_says_what_was_read() {
        let (publish, read) = watch::channel(ModuleSnapshot::default());
        let cli = ModulesCli(read);
        assert!(cli.provide().contains("no port's module has been read yet"));

        publish.send_modify(|snapshot| {
            snapshot.ports.insert(
                InterfaceName::try_from("eth0").unwrap(),
                PortModule::Read {
                    module: Box::new(sfp()),
                    at: clock::now(),
                },
            );
            snapshot.ports.insert(
                InterfaceName::try_from("eth1").unwrap(),
                PortModule::Unread("no module plugged in".to_owned()),
            );
        });
        let shown = cli.provide();
        assert!(shown.contains("eth0: SFP ACME SFP-10G1"), "{shown}");
        assert!(shown.contains("serial S42"), "{shown}");
        assert!(shown.contains("wavelength 850.00 nm"), "{shown}");
        assert!(shown.contains("SFF-8472 12.3"), "{shown}");
        assert!(shown.contains("temperature 39.50 C"), "{shown}");
        assert!(shown.contains("supply 3.3000 V"), "{shown}");
        assert!(
            shown.contains("lane 1: rx LOS, rx power low alarm"),
            "{shown}"
        );
        assert!(shown.contains("eth1: no module plugged in"), "{shown}");
        assert!(
            shown.find("eth0:") < shown.find("eth1:"),
            "ports are shown in order: {shown}"
        );
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
            name: InterfaceName::try_from("under-test").unwrap(),
            mac: SourceMac::new(Mac([0x02, 0, 0, 0, 0, 1])).unwrap(),
            mtu: None,
            hardware: None,
            datapath_index: Some(InterfaceIndex::try_new(ifindex).unwrap()),
            pci_address: None,
        }));
        let (inject, _) = crate::drivers::cpbridge::inject_channel(1).unwrap();
        let port = BridgePort {
            name: InterfaceName::try_from("under-test").unwrap(),
            inject,
            link,
            identity,
        };
        let cancel = CancellationToken::new();
        let (publish, read) = watch::channel(ModuleSnapshot::default());
        let agent = tokio::spawn(watch_port(
            port,
            ethtool,
            Duration::from_millis(100),
            publish,
            cancel.clone(),
        ));
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        cancel.cancel();
        agent.await.unwrap();

        let shown = ModulesCli(read).provide();
        assert!(shown.contains("under-test: "), "{shown}");
        assert!(shown.contains("temperature "), "{shown}");

        let text = scrape.render();
        assert!(
            text.contains("transceiver_present{transceiver=\"under-test\"} 1"),
            "no module was read:\n{text}"
        );
        let info = text
            .lines()
            .find(|line| line.starts_with("transceiver_info{"))
            .unwrap_or_else(|| panic!("no transceiver_info:\n{text}"));
        assert!(
            info.contains("transceiver=\"under-test\"") && info.ends_with(" 1"),
            "{info}"
        );
        assert!(
            text.lines()
                .any(|line| line.starts_with("transceiver_temperature{") && !line.ends_with("NaN")),
            "{text}"
        );
    }
}
