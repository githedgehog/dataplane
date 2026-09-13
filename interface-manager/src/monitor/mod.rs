// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A small interface monitor. The interface monitor listens to netlink events asynchronously
//! and disseminates them over a broadcast channel. It does not make any attempt to interpret
//! the events received via netlink. The interface monitor reports events on ethernet interfaces.
//! For testing, it can be allowed to report events for other types of network devices.
//!
//! # What it can and cannot see under the DPDK driver
//!
//! The socket is opened in the calling thread's network namespace and the names it tracks are the
//! *configured* interface names. With the DPDK driver and a datapath namespace, that means it
//! watches the **taps** the control-plane bridge made -- which do carry those names, in the control
//! namespace this runs in -- and not the physical ports, which are in the datapath namespace with
//! different indices.
//!
//! So it reports the tap's state, which is whatever the bridge last set it to, and never the
//! physical link's. A port going down looks to FRR like a link that is still up, and nothing here
//! can fix that: the state lives on the other side of a namespace boundary, in the DPDK driver,
//! which already knows it. Propagating it onto the tap is a follow-on, and it belongs to the driver
//! rather than to this monitor.

use concurrency::sync::Arc;
use futures::TryStreamExt;
use net::eth::mac::{Mac, SourceMac};
use net::interface::{InterfaceIndex, InterfaceName};
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

#[allow(unused)]
use tracing::{debug, error, info, warn};

/// A type representing an event on an Ethernet interface.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct EthEvent {
    pub name: InterfaceName,
    pub ifindex: InterfaceIndex,
    pub ifup: bool,
    pub iflowerup: bool,
    pub ifrunning: bool,
    pub carrier: bool,
    pub carrierup: u32,
    pub carrierdown: u32,
    /// The interface's link-layer address, when the message carried one.
    ///
    /// Carried because it *changes*, and because nothing else propagates that. The routing
    /// `Interface` takes its MAC from the configuration, captured once when the config was built,
    /// and the datapath tests every arriving frame's destination against it. A MAC set after that
    /// moment -- which is exactly what happens to the control-plane bridge's taps, since a tap is
    /// born with a random address and only later takes its port's -- left the datapath comparing
    /// against an address the interface no longer had, and every unicast frame for it was dropped
    /// as `MacNotForUs`.
    ///
    /// `None` when the message had no address attribute, which is not the same as "no MAC" and
    /// must not be treated as a change to nothing.
    pub mac: Option<SourceMac>,
}
impl std::fmt::Display for EthEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ifup = if self.ifup { "yes" } else { "no" };
        let ifloup = if self.iflowerup { "yes" } else { "no" };
        let ifrun = if self.ifrunning { "yes" } else { "no" };
        let carrier = if self.carrier { "yes" } else { "no" };
        write!(
            f,
            "ifname:{} ({}) ifup:{ifup} iflowerup:{ifloup} ifrun:{ifrun} carrier:{carrier} carrierup:{} carrierdown:{} mac:{}",
            self.name,
            self.ifindex,
            self.carrierup,
            self.carrierdown,
            self.mac
                .map_or_else(|| "none".to_string(), |mac| mac.to_string())
        )
    }
}

/// Interface monitor
/// How often the monitor re-reads every tracked interface's state.
///
/// Short enough that a dropped notification costs seconds rather than the life of the process,
/// long enough that the dump is irrelevant next to the traffic it protects: a handful of
/// interfaces every few seconds.
const RECONCILE_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);

pub struct InterfaceMonitor {
    tx: broadcast::Sender<EthEvent>,
    ct: CancellationToken,
    tracked: Vec<InterfaceName>,
}
impl InterfaceMonitor {
    #[must_use]
    pub fn new(ct: CancellationToken, track: &[InterfaceName]) -> Self {
        let (tx, _) = broadcast::channel::<EthEvent>(100);
        Self {
            tx,
            ct,
            tracked: track.into(),
        }
    }
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EthEvent> {
        self.tx.subscribe()
    }

    /// Convert a netlink message to an `EthEvent` if it is a `NewLink` message for a tracked interface
    fn netlink_to_event(&self, msg: NetlinkMessage<RouteNetlinkMessage>) -> Option<EthEvent> {
        let (_hdr, payload) = msg.into_parts();

        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg)) = payload else {
            return None;
        };
        self.link_to_event(&link_msg)
    }

    /// Convert a `LinkMessage` to an `EthEvent` if it describes a tracked interface.
    ///
    /// Split out from [`Self::netlink_to_event`] so that [`Self::resync`] can feed it messages
    /// from a `RTM_GETLINK` dump, which arrive as bare `LinkMessage`s rather than wrapped in a
    /// multicast notification.
    fn link_to_event(&self, link_msg: &LinkMessage) -> Option<EthEvent> {
        let ifindex = link_msg.header.index;
        let ifup = link_msg.header.flags.contains(LinkFlags::Up);
        let iflowerup = link_msg.header.flags.contains(LinkFlags::LowerUp);
        let ifrunning = link_msg.header.flags.contains(LinkFlags::Running);
        let ifname = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        })?;
        let ifname = InterfaceName::try_from(ifname).ok()?;
        if !self.tracked.contains(&ifname) {
            return None;
        }
        let carrier = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::Carrier(value) => Some(value),
            _ => None,
        })?;
        let carrierup = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::CarrierUpCount(value) => Some(*value),
            _ => None,
        })?;
        let carrierdown = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::CarrierDownCount(value) => Some(*value),
            _ => None,
        })?;
        // Optional, unlike the attributes above: a message that does not carry an address is not
        // a message saying the address was removed, and the `?` used for the others would throw
        // away an otherwise perfectly good event.
        let mac = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::Address(bytes) => {
                let octets: [u8; 6] = bytes.as_slice().try_into().ok()?;
                SourceMac::new(Mac::from(octets)).ok()
            }
            _ => None,
        });

        // `LinkAttribute::OperState` is not reliable for events, so we ignore it.
        // N.B. the above attributes are required (watch the ?)

        // construct the event object
        let event = EthEvent {
            name: ifname,
            ifindex: InterfaceIndex::new(ifindex.try_into().ok()?),
            ifup,
            iflowerup,
            ifrunning,
            carrier: *carrier != 0,
            carrierup,
            carrierdown,
            mac,
        };
        info!("Got event for {event}");
        Some(event)
    }

    /// Emit an event for every tracked interface's *current* state.
    ///
    /// The multicast subscription is edge-triggered: it reports changes, and only those that
    /// happen while it is listening. That leaves two ways for the router's interface table to
    /// hold an address the interface no longer has, and it stays wrong forever because the MAC
    /// never changes again:
    ///
    /// 1. the change lands before the router has the interface in its table, and
    ///    `handle_ifevent` drops the event for an unknown ifindex;
    /// 2. the change happens before this monitor is even listening -- which is the normal case,
    ///    since init creates the control-plane tap and gives it the port's MAC during startup.
    ///
    /// The datapath compares every arriving frame's destination against the table's address, so
    /// the result is that every unicast frame is dropped as `MacNotForUs`: no ARP, no BGP, no
    /// traffic. Reading the current state closes that loop.
    ///
    /// # Errors
    ///
    /// Returns the netlink error if the dump could not be issued.
    pub async fn resync(&self, handle: &rtnetlink::Handle) -> Result<usize, rtnetlink::Error> {
        let mut links = handle.link().get().execute();
        let mut emitted = 0;
        while let Some(link) = links.try_next().await? {
            if let Some(event) = self.link_to_event(&link) {
                emitted += 1;
                if self.tx.send(event).is_err() {
                    debug!("resync: no link event readers");
                }
            }
        }
        Ok(emitted)
    }

    /// Start an interface monitor to track the set of network devices
    ///
    /// # Errors
    ///
    pub async fn run(monitor: Arc<Self>) -> std::io::Result<()> {
        info!("Starting interface monitor");
        for i in &monitor.tracked {
            info!("Will track status of interface {i}");
        }
        let (conn, _, mut messages) = rtnetlink::new_multicast_connection(&[MulticastGroup::Link])
            .inspect_err(|e| error!("Failed to open netlink connection: {e}"))?;

        tokio::spawn(conn);

        // A second, request-capable connection: the multicast one above only receives.
        let (req_conn, req_handle, _) = rtnetlink::new_connection()
            .inspect_err(|e| error!("Failed to open netlink request connection: {e}"))?;
        tokio::spawn(req_conn);

        // Read current state *before* processing any notification. Most of what this monitor
        // needs to know has already happened by the time it starts listening -- see `resync`.
        match monitor.resync(&req_handle).await {
            Ok(n) => info!("Interface monitor resynced {n} tracked interface(s)"),
            Err(e) => error!("Initial interface resync failed: {e}"),
        }

        let tx = monitor.tx.clone();
        let ct = monitor.ct.clone();
        // Re-read periodically as well. A notification can be dropped downstream -- the router
        // discards events for an ifindex it does not yet know -- and nothing would ever resend
        // it, because an interface's MAC does not change twice. This is the level-triggered
        // backstop that makes such a loss self-correcting rather than permanent.
        let mut reconcile = tokio::time::interval(RECONCILE_INTERVAL);
        reconcile.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        reconcile.tick().await; // the first tick is immediate; we just resynced
        loop {
            tokio::select! {
                _ = reconcile.tick() => {
                    if let Err(e) = monitor.resync(&req_handle).await {
                        warn!("Periodic interface resync failed: {e}");
                    }
                }
                nlmsg = messages.recv() => {
                    match nlmsg {
                        Ok((msg, _)) => {
                            if let Some(event) = monitor.netlink_to_event(msg) && tx.send(event).is_err() {
                                warn!("Warning, there are no link event readers!");
                            }
                        }
                        Err(e) => {
                            error!("Recv error in netlink socket: {e}");
                            break;
                        }
                    }
                }
                () = ct.cancelled() => {
                    info!("Interface monitor got cancelled");
                    break;
                }
            }
        }
        info!("Interface monitor is shutting down now");
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::InterfaceMonitor;
    use caps::Capability;
    use concurrency::sync::Arc;
    use fixin::wrap;
    use net::interface::InterfaceName;
    use rtnetlink::{LinkDummy, LinkMessageBuilder, new_connection};
    use test_utils::with_caps;
    use tokio::time::Duration;
    use tokio_util::sync::CancellationToken;
    use tracing::debug;
    use tracing_test::traced_test;

    async fn create_dummy(name: &str) {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        let msg = LinkMessageBuilder::<LinkDummy>::new(name).build();
        handle.link().add(msg).execute().await.unwrap();
    }

    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    #[ignore = "disabled until nv_m support is re-enabled"]
    async fn test_interface_monitor() {
        const INTERFACE: &str = "test-dummy";
        let test_ifname = InterfaceName::try_from(INTERFACE).unwrap();
        let ct = CancellationToken::new();
        let ifmonitor = Arc::new(InterfaceMonitor::new(ct, &[test_ifname]));
        let mut subsc1 = ifmonitor.subscribe();
        let mut subsc2 = ifmonitor.subscribe();
        tokio::spawn(InterfaceMonitor::run(ifmonitor.clone()));

        create_dummy(INTERFACE).await;

        let j1 = tokio::spawn(async move {
            let event = subsc1.recv().await.unwrap();
            println!("listener1: {event}");
        });
        let j2 = tokio::spawn(async move {
            let event = subsc2.recv().await.unwrap();
            println!("listener2: {event}");
        });
        tokio::time::sleep(Duration::from_secs(3)).await;
        debug!("Will now cancel the interface monitor");
        ifmonitor.ct.cancel();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(ifmonitor.ct.is_cancelled());
        let _ = j1.await;
        let _ = j2.await;
    }
}

#[cfg(test)]
mod resync_conversion {
    use super::{EthEvent, InterfaceMonitor};
    use concurrency::sync::Arc;
    use net::interface::InterfaceName;
    use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
    use tokio_util::sync::CancellationToken;

    /// The MAC a control-plane tap adopts from its DPDK port.
    const PORT_MAC: [u8; 6] = [0x58, 0xa2, 0xe1, 0xb3, 0x3d, 0x94];

    fn monitor(tracked: &str) -> InterfaceMonitor {
        let name = InterfaceName::try_from(tracked.to_string()).expect("valid ifname");
        InterfaceMonitor::new(CancellationToken::new(), &[name])
    }

    /// A `RTM_GETLINK` dump entry, which is what `resync` walks. Carries the same attributes the
    /// kernel puts on a link notification.
    fn dumped_link(name: &str, mac: Option<[u8; 6]>) -> LinkMessage {
        let mut msg = LinkMessage::default();
        msg.header.index = 2;
        msg.header.flags = LinkFlags::Up | LinkFlags::LowerUp | LinkFlags::Running;
        msg.attributes.push(LinkAttribute::IfName(name.to_string()));
        msg.attributes.push(LinkAttribute::Carrier(1));
        msg.attributes.push(LinkAttribute::CarrierUpCount(1));
        msg.attributes.push(LinkAttribute::CarrierDownCount(0));
        if let Some(mac) = mac {
            msg.attributes.push(LinkAttribute::Address(mac.to_vec()));
        }
        msg
    }

    /// The whole point of `resync`: reading current state must yield the address the interface
    /// has *now*, without any change having occurred while the monitor was listening.
    ///
    /// This is the failure it exists to prevent -- the router's table keeping a tap's random
    /// birth address, and the datapath dropping every unicast frame as `MacNotForUs`.
    #[test]
    fn a_dumped_link_yields_its_current_mac() {
        let mon = monitor("enp2s1np0");
        let ev: EthEvent = mon
            .link_to_event(&dumped_link("enp2s1np0", Some(PORT_MAC)))
            .expect("a dumped tracked link must produce an event");
        assert_eq!(
            ev.mac.expect("the dump carried an address").inner().0,
            PORT_MAC,
            "resync must report the address the interface currently has"
        );
    }

    /// A dump walks every link on the box; only the configured ones are ours.
    #[test]
    fn an_untracked_link_is_ignored() {
        let mon = monitor("enp2s1np0");
        assert!(
            mon.link_to_event(&dumped_link("some-other-nic", Some(PORT_MAC)))
                .is_none(),
            "a link we were not asked to track must not produce an event"
        );
    }

    /// A message without an address attribute is not a message saying the address was removed,
    /// and must not throw away the rest of an otherwise good event.
    #[test]
    fn a_link_without_an_address_still_reports_state() {
        let mon = monitor("enp2s1np0");
        let ev = mon
            .link_to_event(&dumped_link("enp2s1np0", None))
            .expect("an event is still useful without an address");
        assert!(ev.mac.is_none());
        assert!(
            ev.ifup,
            "the rest of the state must survive a missing address"
        );
    }

    /// `Arc` is how the monitor is held by the run loop; keep the type usable that way.
    #[test]
    fn monitor_is_shareable() {
        let _: Arc<InterfaceMonitor> = Arc::new(monitor("enp2s1np0"));
    }
}
