// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Advertise this gateway with LLDP on every port.
//!
//! The dataplane owns its NICs, so nothing else can speak LLDP for them. Each port gets two tasks:
//! one composes what the port advertises from what the dataplane knows, and one ([`lldp::transmit`])
//! sends it on schedule through the port's control-plane injection queue.
//!
//! What each port advertises:
//!
//! | TLV | Value |
//! |---|---|
//! | Chassis ID | locally assigned: the dataplane's name (`--name`, else the hostname) |
//! | Port ID | interface name: the name the port was configured with |
//! | Port Description | the device behind the port: bus address and driver |
//! | System Name | the gateway's name from its k8s config, else the chassis ID |
//! | System Description | this dataplane and its version, and whether it awaits configuration |
//! | System Capabilities | router, enabled |
//! | Management Address | the host's address (see [`management_address`]) |
//! | 802.3 Maximum Frame Size | the port's MTU plus Ethernet header and FCS |
//!
//! A port advertises as soon as it is known, before any configuration: a gateway whose configuration
//! never arrives is the one most worth finding. The chassis ID is therefore a name the dataplane has
//! from startup, and it does not change when a configuration arrives, since neighbours key on it;
//! the k8s name, the one a person will recognise, is the system name.

use crate::drivers::cpbridge::{BridgePort, HeardFrame, PortIdentity};
use common::cliprovider::{CliDataProvider, Heading};
use lifecycle::Subsystem;
use lldp::{Advertisement, Inputs, Link, Neighbor, Neighbors, Timing, transmit};
use net::headers::Headers;
use net::interface::InterfaceName;
use net::lldp::{
    ChassisId, Dot3Tlv, IdOctets, InterfaceNumber, InterfaceNumbering, Lldpdu, ManagementAddress,
    NetworkAddress, ObjectIdentifier, OptionalTlv, OrganizationallySpecific, PortId,
    SystemCapabilities, SystemCapability, Text,
};
use net::parse::Parse;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::watch;
use tracing::{debug, warn};

/// What every port says this system is.
const SYSTEM_DESCRIPTION: &str = concat!("Hedgehog gateway dataplane ", env!("CARGO_PKG_VERSION"));

/// What every port says this system is, until a configuration has named the gateway.
const SYSTEM_DESCRIPTION_UNCONFIGURED: &str = concat!(
    "Hedgehog gateway dataplane ",
    env!("CARGO_PKG_VERSION"),
    " (awaiting configuration)"
);

/// Octets an Ethernet frame adds around its payload: the header and the frame check sequence.
const ETHERNET_OVERHEAD: u16 = 14 + 4;

/// Where to tell each port's transmitter that a new neighbour has appeared on it.
pub(crate) type NewNeighbors = HashMap<InterfaceName, watch::Sender<()>>;

/// Start advertising on every port in `ports`, as `chassis`.
///
/// `chassis` is the dataplane's own name (`--name`, else the hostname), which it has from startup and
/// keeps across restarts, so a gateway whose configuration never arrives can still be found by its
/// neighbours. The configured gateway name becomes the system name once there is one.
///
/// Returns where to signal each port's new neighbours, for [`listen`].
pub(crate) fn start(
    handle: &tokio::runtime::Handle,
    mgmt: &Subsystem,
    ports: &[BridgePort],
    chassis: &str,
    gateway_name: &watch::Receiver<Option<String>>,
    management: &watch::Receiver<Option<IpAddr>>,
) -> NewNeighbors {
    let mut new_neighbors = HashMap::with_capacity(ports.len());
    for port in ports {
        let (advertisement, advertised) = watch::channel(None);
        let (new_neighbor, new_neighbor_rx) = watch::channel(());
        new_neighbors.insert(port.name.clone(), new_neighbor);
        mgmt.spawn_on(
            compose(
                port.name.clone(),
                port.identity.clone(),
                chassis.to_owned(),
                gateway_name.clone(),
                management.clone(),
                advertisement,
                mgmt.cancel_token(),
            ),
            handle,
        );
        mgmt.spawn_on(
            transmit(
                Inputs {
                    link: port.link.clone(),
                    advertisement: advertised,
                    new_neighbor: new_neighbor_rx,
                    sink: port.inject.clone(),
                    timing: Timing::default(),
                },
                mgmt.cancel_token(),
            ),
            handle,
        );
    }
    debug!("LLDP: advertising on {} port(s)", ports.len());
    new_neighbors
}

/// Keep one port's advertisement current until cancelled or an input goes away.
///
/// Returning drops `advertisement`, which tells the transmitter to retract it.
async fn compose(
    port: InterfaceName,
    mut identity: watch::Receiver<Option<PortIdentity>>,
    chassis: String,
    mut gateway_name: watch::Receiver<Option<String>>,
    mut management: watch::Receiver<Option<IpAddr>>,
    advertisement: watch::Sender<Option<Advertisement>>,
    cancel: lifecycle::CancellationToken,
) {
    loop {
        let now = advertise(
            &port,
            identity.borrow_and_update().as_ref(),
            &chassis,
            gateway_name.borrow_and_update().as_deref(),
            *management.borrow_and_update(),
        );
        advertisement.send_if_modified(|current| {
            if *current == now {
                return false;
            }
            *current = now;
            true
        });
        let changed = tokio::select! {
            () = cancel.cancelled() => return,
            changed = identity.changed() => changed,
            changed = gateway_name.changed() => changed,
            changed = management.changed() => changed,
        };
        if changed.is_err() {
            return;
        }
    }
}

/// What `port` advertises, or `None` if there is not yet enough to say.
///
/// Only the port's identity is waited for. Without a configured `gateway_name` the system name is the
/// `chassis` name and the system description says that configuration is awaited.
fn advertise(
    port: &InterfaceName,
    identity: Option<&PortIdentity>,
    chassis: &str,
    gateway_name: Option<&str>,
    management: Option<IpAddr>,
) -> Option<Advertisement> {
    let identity = identity?;
    let Ok(chassis_id) = IdOctets::new(chassis.as_bytes()) else {
        warn!("LLDP: the name {chassis:?} is too long for a chassis ID; not advertising");
        return None;
    };
    let Ok(port_id) = IdOctets::new(port.to_string().as_bytes()) else {
        unreachable!("an interface name is a valid port ID");
    };
    let source = identity.mac;

    let mut optional = vec![
        OptionalTlv::PortDescription(text(
            identity.hardware.as_deref().unwrap_or("unknown device"),
        )),
        OptionalTlv::SystemName(text(gateway_name.unwrap_or(chassis))),
        OptionalTlv::SystemDescription(text(if gateway_name.is_some() {
            SYSTEM_DESCRIPTION
        } else {
            SYSTEM_DESCRIPTION_UNCONFIGURED
        })),
        OptionalTlv::SystemCapabilities(SystemCapabilities::new(
            SystemCapability::ROUTER,
            SystemCapability::ROUTER,
        )),
    ];
    if let Some(address) = management {
        let address = match address {
            IpAddr::V4(v4) => NetworkAddress::Ipv4(v4),
            IpAddr::V6(v6) => NetworkAddress::Ipv6(v6),
        };
        let Ok(identifier) = ObjectIdentifier::new(&[]) else {
            unreachable!("an empty object identifier is valid");
        };
        if let Ok(tlv) = ManagementAddress::new(
            address,
            InterfaceNumber::new(InterfaceNumbering::Unknown, 0),
            identifier,
        ) {
            optional.push(OptionalTlv::ManagementAddress(tlv));
        }
    }
    // Left out rather than guessed when the driver could not learn the port's MTU.
    if let Some(mtu) = identity.mtu {
        optional.push(OptionalTlv::OrganizationallySpecific(
            OrganizationallySpecific::Dot3(Dot3Tlv::MaximumFrameSize(
                mtu.saturating_add(ETHERNET_OVERHEAD),
            )),
        ));
    }

    match Advertisement::new(
        source,
        ChassisId::LocallyAssigned(chassis_id),
        PortId::InterfaceName(port_id),
        optional,
    ) {
        Ok(advertisement) => Some(advertisement),
        Err(e) => {
            warn!(
                "LLDP: what port {port} would advertise does not fit in a frame ({e}); not advertising"
            );
            None
        }
    }
}

/// `value` as TLV text, cut at a character boundary if it is longer than a TLV can carry.
fn text(value: &str) -> Text {
    let mut end = value.len().min(255);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    Text::new(&value.as_bytes()[..end]).unwrap_or_else(|_| unreachable!("at most 255 octets"))
}

/// How often to look for the host's management address again.
const MANAGEMENT_REFRESH: Duration = Duration::from_secs(60);

/// Publish the host's management address, refreshed every minute.
///
/// The management address is the source address the host would use to reach the outside world: the
/// one on its default route. Found by connecting a UDP socket, which sends nothing but makes the
/// kernel choose a source address, so this must run where the host's routes are: on the host runtime.
/// IPv4 is preferred; with no IPv4 default route, IPv6 is tried.
pub(crate) async fn management_address(
    publish: watch::Sender<Option<IpAddr>>,
    cancel: lifecycle::CancellationToken,
) {
    // Documentation addresses (RFC 5737, RFC 3849): routed by a default route, owned by nobody.
    const PROBES: [&str; 2] = ["192.0.2.1:9", "[2001:db8::1]:9"];
    loop {
        let mut found = None;
        for probe in PROBES {
            let unspecified = if probe.starts_with('[') {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let Ok(socket) = tokio::net::UdpSocket::bind(unspecified).await else {
                continue;
            };
            if socket.connect(probe).await.is_ok()
                && let Ok(local) = socket.local_addr()
            {
                found = Some(local.ip());
                break;
            }
        }
        publish.send_if_modified(|current| {
            if *current == found {
                return false;
            }
            if let Some(address) = found {
                debug!("LLDP: the host's management address is {address}");
            } else {
                warn!("LLDP: the host has no default route, so no management address to advertise");
            }
            *current = found;
            true
        });
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(MANAGEMENT_REFRESH) => {}
        }
    }
}

/// How many neighbours one port may have. A point-to-point link has one.
const MAX_NEIGHBORS_PER_PORT: NonZeroUsize = NonZeroUsize::new(8).unwrap();

/// Every neighbour heard, with the port it was heard on, and what had to be thrown away.
#[derive(Debug, Clone, Default)]
pub(crate) struct NeighborSnapshot {
    neighbors: Vec<(InterfaceName, Neighbor)>,
    discards: Discards,
}

impl NeighborSnapshot {
    /// How many neighbours are known.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.neighbors.len()
    }
}

/// What the receiver threw away: IEEE 802.1AB's `statsFramesDiscardedTotal` and
/// `statsTLVsDiscardedTotal`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Discards {
    /// LLDP frames discarded as a whole.
    frames: u64,
    /// TLVs discarded from frames which were otherwise kept.
    tlvs: u64,
}

/// How often a discarded frame may be logged. A neighbour sending malformed LLDP does so every
/// few seconds, forever; the counters keep the tally in between.
const DISCARD_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Keep the neighbour table from what arrives on the ports, publishing it on every change.
pub(crate) fn listen(
    handle: &tokio::runtime::Handle,
    mgmt: &Subsystem,
    heard: mpsc::Receiver<HeardFrame>,
    ports: &[BridgePort],
    new_neighbors: NewNeighbors,
    publish: watch::Sender<NeighborSnapshot>,
) {
    // A port that goes down takes its neighbours with it (IEEE 802.1AB-2016 §9.2.7.7); one forwarder
    // per port turns its link state into events the table can wait on alongside everything else.
    let (down_tx, down) = mpsc::channel(ports.len().max(1));
    for port in ports {
        mgmt.spawn_on(
            forward_link_down(port.name.clone(), port.link.clone(), down_tx.clone()),
            handle,
        );
    }
    mgmt.spawn_on(
        receive(heard, down, new_neighbors, publish, mgmt.cancel_token()),
        handle,
    );
}

/// Send `port` on `down` every time its link goes down, until either end goes away.
async fn forward_link_down(
    port: InterfaceName,
    mut link: watch::Receiver<Link>,
    down: mpsc::Sender<InterfaceName>,
) {
    while link.changed().await.is_ok() {
        if *link.borrow_and_update() == Link::Down && down.send(port.clone()).await.is_err() {
            return;
        }
    }
}

async fn receive(
    mut heard: mpsc::Receiver<HeardFrame>,
    mut down: mpsc::Receiver<InterfaceName>,
    new_neighbors: NewNeighbors,
    publish: watch::Sender<NeighborSnapshot>,
    cancel: lifecycle::CancellationToken,
) {
    let mut table = Neighbors::new(MAX_NEIGHBORS_PER_PORT);
    let mut reception = Reception::default();
    loop {
        let expiry = table.next_expiry();
        let changed = tokio::select! {
            () = cancel.cancelled() => return,
            frame = heard.recv() => match frame {
                Some(frame) => {
                    let heard = hear(&mut table, &mut reception, &frame);
                    if heard == Some(lldp::Heard::New) {
                        // newNeighbor: the port's transmitter fast-starts so the newcomer learns
                        // about us as quickly as we learned about it.
                        if let Some(signal) = new_neighbors.get(&frame.port) {
                            signal.send_replace(());
                        }
                    }
                    // A refresh changes only when the neighbour expires, but that is shown too.
                    // Not short-circuited: asking is what marks the counters as published.
                    reception.discards_changed()
                        | heard.is_some_and(|heard| heard != lldp::Heard::TooMany)
                }
                None => return,
            },
            Some(port) = down.recv() => table.forget_port(&port) > 0,
            () = async {
                match expiry {
                    Some(at) => tokio::time::sleep_until(at.into()).await,
                    None => std::future::pending().await,
                }
            } => table.expire(clock::now()) > 0,
        };
        if changed {
            publish.send_replace(NeighborSnapshot {
                neighbors: table
                    .iter()
                    .map(|(port, neighbor)| (port.clone(), neighbor.clone()))
                    .collect(),
                discards: reception.discards,
            });
        }
    }
}

/// The receiver's discard counters, and when a discard was last logged.
#[derive(Default)]
struct Reception {
    discards: Discards,
    published: Discards,
    last_logged: Option<std::time::Instant>,
}

impl Reception {
    /// Whether the counters moved since this was last asked.
    fn discards_changed(&mut self) -> bool {
        let changed = self.discards != self.published;
        self.published = self.discards;
        changed
    }

    fn discard_tlvs(&mut self, port: &InterfaceName, count: u16) {
        if count == 0 {
            return;
        }
        self.discards.tlvs += u64::from(count);
        if self.may_log() {
            warn!("LLDP: discarded {count} malformed TLV(s) from a frame received on {port}");
        }
    }

    fn discard_frame(&mut self, port: &InterfaceName, error: &dyn std::fmt::Display) {
        self.discards.frames += 1;
        if self.may_log() {
            warn!("LLDP: discarded a frame received on {port}: {error}");
        }
    }

    fn may_log(&mut self) -> bool {
        let now = clock::now();
        if self
            .last_logged
            .is_some_and(|at| now.saturating_duration_since(at) < DISCARD_LOG_INTERVAL)
        {
            return false;
        }
        self.last_logged = Some(now);
        true
    }
}

/// Record what `frame` says, returning what it did to the table, or `None` if it said nothing usable.
fn hear(
    table: &mut Neighbors<InterfaceName>,
    reception: &mut Reception,
    frame: &HeardFrame,
) -> Option<lldp::Heard> {
    let Ok((mut headers, consumed)) = Headers::parse(&frame.frame) else {
        debug!("LLDP: a frame received on {} did not parse", frame.port);
        return None;
    };
    let Some(eth) = headers.eth() else {
        debug!(
            "LLDP: a frame received on {} had no Ethernet header",
            frame.port
        );
        return None;
    };
    let source = eth.source();
    let is_lldp = eth.ether_type() == net::lldp::ETHTYPE;
    let lldpdu = match headers.take_lldp() {
        Some(lldpdu) => *lldpdu,
        // The byte-exact parse refused the LLDPDU; keep what the receive rules allow
        // (IEEE 802.1AB-2005 §10.3.2).
        None if is_lldp => {
            let payload = frame
                .frame
                .get(consumed.get() as usize..)
                .unwrap_or_default();
            match Lldpdu::receive(payload) {
                Ok(received) => {
                    reception.discard_tlvs(&frame.port, received.discarded);
                    received.lldpdu
                }
                Err(error) => {
                    reception.discard_frame(&frame.port, &error);
                    return None;
                }
            }
        }
        None => {
            debug!("LLDP: a frame received on {} carried no LLDPDU", frame.port);
            return None;
        }
    };
    let heard = table.hear(&frame.port, source, lldpdu, clock::now());
    if heard == lldp::Heard::TooMany {
        warn!(
            "LLDP: ignoring a new neighbour on {}, which already has {MAX_NEIGHBORS_PER_PORT}",
            frame.port
        );
    }
    Some(heard)
}

/// `show lldp neighbors`.
pub(crate) struct NeighborsCli(pub(crate) watch::Receiver<NeighborSnapshot>);

impl CliDataProvider for NeighborsCli {
    fn provide(&self) -> String {
        let snapshot = self.0.borrow();
        let mut rows: Vec<_> = snapshot.neighbors.iter().collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        let now = clock::now();
        let mut out = String::new();
        let _ = write!(out, "{}", Heading("LLDP neighbors"));
        let _ = writeln!(
            out,
            " {:<16} {:<24} {:<20} {:<24} {:<16} {:>9}",
            "port", "chassis", "remote port", "system name", "management", "expires"
        );
        for (port, neighbor) in rows {
            let pdu = &neighbor.lldpdu;
            let system_name = pdu.optional().iter().find_map(|tlv| match tlv {
                net::lldp::OptionalTlv::SystemName(name) => Some(name.to_string()),
                _ => None,
            });
            let management = pdu.optional().iter().find_map(|tlv| match tlv {
                net::lldp::OptionalTlv::ManagementAddress(address) => {
                    Some(address.address().to_string())
                }
                _ => None,
            });
            let _ = writeln!(
                out,
                " {:<16} {:<24} {:<20} {:<24} {:<16} {:>8}s",
                port.to_string(),
                pdu.chassis_id().to_string(),
                pdu.port_id().to_string(),
                system_name.as_deref().unwrap_or("-"),
                management.as_deref().unwrap_or("-"),
                neighbor.expires.saturating_duration_since(now).as_secs(),
            );
        }
        if snapshot.neighbors.is_empty() {
            let _ = writeln!(out, " (none)");
        }
        let Discards { frames, tlvs } = snapshot.discards;
        let _ = writeln!(out, "\n discarded: {frames} frame(s), {tlvs} TLV(s)");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{advertise, text};
    use crate::drivers::cpbridge::PortIdentity;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::InterfaceName;
    use net::lldp::{ChassisId, IdOctets, OptionalTlv};

    fn identity() -> PortIdentity {
        PortIdentity {
            name: InterfaceName::try_from("eth1").unwrap(),
            mac: SourceMac::new(Mac([0x02, 0, 0, 0, 0, 1])).unwrap(),
            mtu: Some(9000),
            hardware: Some("0000:03:00.0 (mlx5_pci)".to_owned()),
        }
    }

    fn port() -> InterfaceName {
        InterfaceName::try_from("eth1").unwrap()
    }

    fn system_name_and_description(advertised: &lldp::Advertisement) -> (String, String) {
        let optional = advertised.lldpdu().optional();
        let find = |pick: fn(&OptionalTlv) -> Option<String>| {
            optional.iter().find_map(pick).expect("advertised")
        };
        (
            find(|tlv| match tlv {
                OptionalTlv::SystemName(name) => Some(name.to_string()),
                _ => None,
            }),
            find(|tlv| match tlv {
                OptionalTlv::SystemDescription(description) => Some(description.to_string()),
                _ => None,
            }),
        )
    }

    #[test]
    fn nothing_is_advertised_before_the_port_is_known() {
        assert_eq!(advertise(&port(), None, "dp-1", Some("gw-1"), None), None);
    }

    /// A gateway whose configuration never arrives is exactly the one someone will want to find.
    #[test]
    fn an_unconfigured_gateway_advertises_and_says_it_is_waiting() {
        let advertised = advertise(&port(), Some(&identity()), "dp-1", None, None)
            .expect("advertised before configuration");
        assert_eq!(
            *advertised.lldpdu().chassis_id(),
            ChassisId::LocallyAssigned(IdOctets::new(b"dp-1").unwrap())
        );
        let (name, description) = system_name_and_description(&advertised);
        assert_eq!(name, "dp-1");
        assert!(
            description.ends_with("(awaiting configuration)"),
            "{description}"
        );
    }

    #[test]
    fn a_long_text_is_cut_at_a_character_boundary() {
        let long = "é".repeat(200);
        assert_eq!(text(&long).len(), 254);
    }

    /// The chassis ID stays put when the configuration arrives: neighbours key on it, so changing it
    /// would look to them like a new neighbour.
    #[test]
    fn a_configured_gateway_advertises_its_name_as_system_name() {
        let advertised = advertise(
            &port(),
            Some(&identity()),
            "dp-1",
            Some("gw-1"),
            Some("10.0.0.1".parse().unwrap()),
        )
        .expect("a configured gateway advertises");
        let pdu = advertised.lldpdu();
        assert_eq!(
            *pdu.chassis_id(),
            ChassisId::LocallyAssigned(IdOctets::new(b"dp-1").unwrap())
        );
        let (name, description) = system_name_and_description(&advertised);
        assert_eq!(name, "gw-1");
        assert!(!description.contains("awaiting"), "{description}");
        assert!(
            pdu.optional()
                .iter()
                .any(|tlv| matches!(tlv, OptionalTlv::ManagementAddress(_)))
        );
    }

    mod receiving {
        use super::super::{HeardFrame, NeighborSnapshot, NeighborsCli, receive};
        use common::cliprovider::CliDataProvider;
        use lldp::Advertisement;
        use net::eth::mac::{Mac, SourceMac};
        use net::interface::InterfaceName;
        use net::lldp::{ChassisId, IdOctets, OptionalTlv, PortId, Text, TimeToLive};
        use std::time::Duration;
        use tokio::sync::{mpsc, watch};

        /// A frame from switch `leaf`, as it arrives on one of our ports.
        fn from_leaf(port: &str, leaf: &str, ttl: u16) -> HeardFrame {
            let advertisement = Advertisement::new(
                SourceMac::new(Mac([0x02, 0, 0, 0, 0, 0x10])).unwrap(),
                ChassisId::LocallyAssigned(IdOctets::new(leaf.as_bytes()).unwrap()),
                PortId::InterfaceName(IdOctets::new(b"Ethernet8").unwrap()),
                [OptionalTlv::SystemName(Text::new(leaf.as_bytes()).unwrap())],
            )
            .unwrap();
            HeardFrame {
                port: InterfaceName::try_from(port).unwrap(),
                frame: advertisement.frame(TimeToLive::new(ttl)),
            }
        }

        struct Listener {
            heard: mpsc::Sender<HeardFrame>,
            down: mpsc::Sender<InterfaceName>,
            snapshot: watch::Receiver<NeighborSnapshot>,
            /// eth1's new-neighbour signal.
            new_on_eth1: watch::Receiver<()>,
        }

        impl Listener {
            fn start() -> Listener {
                let (heard, heard_rx) = mpsc::channel(8);
                let (down, down_rx) = mpsc::channel(8);
                let (publish, snapshot) = watch::channel(NeighborSnapshot::default());
                let (new_neighbor, new_on_eth1) = watch::channel(());
                let new_neighbors = [(InterfaceName::try_from("eth1").unwrap(), new_neighbor)]
                    .into_iter()
                    .collect();
                tokio::spawn(receive(
                    heard_rx,
                    down_rx,
                    new_neighbors,
                    publish,
                    lifecycle::CancellationToken::new(),
                ));
                Listener {
                    heard,
                    down,
                    snapshot,
                    new_on_eth1,
                }
            }

            fn neighbours(&self) -> usize {
                self.snapshot.borrow().len()
            }
        }

        async fn settle() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        #[test]
        fn a_neighbour_is_learned_shown_and_forgotten_when_its_ttl_runs_out() {
            clock::virtual_time::Paused::new().block_on(async {
                let listener = Listener::start();
                listener
                    .heard
                    .send(from_leaf("eth1", "leaf-1", 10))
                    .await
                    .unwrap();
                settle().await;
                assert_eq!(listener.neighbours(), 1);

                let shown = NeighborsCli(listener.snapshot.clone()).provide();
                for expected in ["eth1", "leaf-1", "Ethernet8"] {
                    assert!(
                        shown.contains(expected),
                        "{expected} missing from:\n{shown}"
                    );
                }

                tokio::time::sleep(Duration::from_secs(11)).await;
                assert_eq!(listener.neighbours(), 0, "the neighbour outlived its TTL");
            });
        }

        /// `show lldp neighbors` reads its expiry from the snapshot, so a neighbour that keeps
        /// advertising has to move it. A switch sending every 5 s with a 20 s TTL used to show
        /// 0 s for as long as it stayed.
        #[test]
        fn a_refresh_moves_the_expiry_that_is_shown() {
            clock::virtual_time::Paused::new().block_on(async {
                let listener = Listener::start();
                listener
                    .heard
                    .send(from_leaf("eth1", "leaf-1", 20))
                    .await
                    .unwrap();
                settle().await;
                tokio::time::sleep(Duration::from_secs(15)).await;
                listener
                    .heard
                    .send(from_leaf("eth1", "leaf-1", 20))
                    .await
                    .unwrap();
                settle().await;

                let left = listener.snapshot.borrow().neighbors[0]
                    .1
                    .expires
                    .saturating_duration_since(clock::now());
                assert!(
                    left > Duration::from_secs(15),
                    "the snapshot still expires {left:?} from now, as of the first frame"
                );
            });
        }

        #[test]
        fn a_shutdown_frame_or_a_downed_link_forgets_at_once() {
            clock::virtual_time::Paused::new().block_on(async {
                let listener = Listener::start();
                listener
                    .heard
                    .send(from_leaf("eth1", "leaf-1", 120))
                    .await
                    .unwrap();
                listener
                    .heard
                    .send(from_leaf("eth2", "leaf-2", 120))
                    .await
                    .unwrap();
                settle().await;
                assert_eq!(listener.neighbours(), 2);

                listener
                    .heard
                    .send(from_leaf("eth1", "leaf-1", 0))
                    .await
                    .unwrap();
                settle().await;
                assert_eq!(listener.neighbours(), 1);

                listener
                    .down
                    .send(InterfaceName::try_from("eth2").unwrap())
                    .await
                    .unwrap();
                settle().await;
                assert_eq!(listener.neighbours(), 0);
            });
        }

        #[test]
        fn only_a_new_neighbour_signals_the_transmitter() {
            clock::virtual_time::Paused::new().block_on(async {
                let mut listener = Listener::start();
                listener
                    .heard
                    .send(from_leaf("eth1", "leaf-1", 120))
                    .await
                    .unwrap();
                settle().await;
                assert!(
                    listener.new_on_eth1.has_changed().unwrap(),
                    "a newcomer is signalled"
                );
                listener.new_on_eth1.mark_unchanged();

                listener
                    .heard
                    .send(from_leaf("eth1", "leaf-1", 120))
                    .await
                    .unwrap();
                settle().await;
                assert!(
                    !listener.new_on_eth1.has_changed().unwrap(),
                    "a known neighbour refreshing is not"
                );
            });
        }

        /// A frame from `leaf` whose system name is longer than the 255 octets 802.1AB allows,
        /// followed by a valid system description. `tlv` builds it by hand, as nothing here
        /// will serialise a TLV that is wrong.
        fn from_leaf_with_an_oversized_name(port: &str) -> HeardFrame {
            fn tlv(typ: u8, value: &[u8]) -> Vec<u8> {
                let length = u16::try_from(value.len()).unwrap();
                let mut out = vec![
                    (typ << 1) | u8::try_from(length >> 8).unwrap(),
                    u8::try_from(length & 0xff).unwrap(),
                ];
                out.extend_from_slice(value);
                out
            }
            let mut frame = from_leaf(port, "leaf-1", 120).frame;
            frame.truncate(14);
            frame.extend(tlv(1, b"\x07leaf-1"));
            frame.extend(tlv(2, b"\x05Ethernet8"));
            frame.extend(tlv(3, &120u16.to_be_bytes()));
            frame.extend(tlv(5, &[b'x'; 300]));
            frame.extend(tlv(6, b"SONiC"));
            frame.extend([0, 0]);
            HeardFrame {
                port: InterfaceName::try_from(port).unwrap(),
                frame,
            }
        }

        /// IEEE 802.1AB-2005 §10.3.2: a TLV with an error of its own is discarded and counted,
        /// and the rest of the LLDPDU is still heard.
        #[test]
        fn a_malformed_tlv_is_discarded_and_the_neighbour_still_heard() {
            clock::virtual_time::Paused::new().block_on(async {
                let listener = Listener::start();
                listener
                    .heard
                    .send(from_leaf_with_an_oversized_name("eth1"))
                    .await
                    .unwrap();
                settle().await;
                assert_eq!(listener.neighbours(), 1);
                let shown = NeighborsCli(listener.snapshot.clone()).provide();
                for expected in ["leaf-1", "Ethernet8", "0 frame(s), 1 TLV(s)"] {
                    assert!(
                        shown.contains(expected),
                        "{expected} missing from:\n{shown}"
                    );
                }
            });
        }

        #[test]
        fn a_frame_without_a_valid_chassis_id_is_discarded_and_counted() {
            clock::virtual_time::Paused::new().block_on(async {
                let listener = Listener::start();
                let mut frame = from_leaf("eth1", "leaf-1", 120);
                frame.frame[14] = 0xff; // wreck the chassis ID TLV header
                listener.heard.send(frame).await.unwrap();
                settle().await;
                assert_eq!(listener.neighbours(), 0);
                let shown = NeighborsCli(listener.snapshot.clone()).provide();
                assert!(
                    shown.contains("1 frame(s), 0 TLV(s)"),
                    "discard missing from:\n{shown}"
                );
            });
        }
    }
}
