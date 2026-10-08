// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Broadcasts kernel interface events from the calling thread's network namespace.
//!
//! With an isolated datapath, configured names identify control-plane taps. This
//! monitor sees tap state, not physical link state. Propagating DPDK port state to
//! the taps remains a driver task.

use concurrency::sync::Arc;
use futures::TryStreamExt;
use net::eth::mac::SourceMac;
use net::interface::{InterfaceIndex, InterfaceName};
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage, State};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

#[allow(unused)]
use tracing::{debug, error, info, warn};

/// A type representing an event on an Ethernet interface.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct EthEvent {
    ifindex: InterfaceIndex,
    ifup: bool,
    iflowerup: bool,
    ifrunning: bool,
    name: Option<InterfaceName>,
    oper_state: Option<State>,
    carrier: Option<bool>,
    carrierup: Option<u32>,   // stats
    carrierdown: Option<u32>, // stats
    mac: Option<SourceMac>,
}
impl EthEvent {
    #[must_use]
    pub fn new(ifindex: InterfaceIndex, ifup: bool, iflowerup: bool, ifrunning: bool) -> Self {
        Self {
            ifindex,
            ifup,
            iflowerup,
            ifrunning,
            name: None,
            oper_state: None,
            carrier: None,
            carrierup: None,
            carrierdown: None,
            mac: None,
        }
    }
    #[must_use]
    pub fn set_carrier(mut self, carrier: Option<bool>) -> Self {
        self.carrier = carrier;
        self
    }
    #[must_use]
    pub fn set_carrierup(mut self, carrierup: Option<u32>) -> Self {
        self.carrierup = carrierup;
        self
    }
    #[must_use]
    pub fn set_carrierdown(mut self, carrierdown: Option<u32>) -> Self {
        self.carrierdown = carrierdown;
        self
    }
    #[must_use]
    pub fn set_oper_state(mut self, oper_state: Option<State>) -> Self {
        self.oper_state = oper_state;
        self
    }
    #[must_use]
    pub fn set_mac(mut self, mac: Option<SourceMac>) -> Self {
        self.mac = mac;
        self
    }
    #[must_use]
    pub fn set_name(mut self, name: Option<InterfaceName>) -> Self {
        self.name = name;
        self
    }

    #[must_use]
    pub fn ifindex(&self) -> InterfaceIndex {
        self.ifindex
    }
    #[must_use]
    pub fn name(&self) -> Option<&InterfaceName> {
        self.name.as_ref()
    }
    #[must_use]
    pub fn ifup(&self) -> bool {
        self.ifup
    }
    #[must_use]
    pub fn iflowerup(&self) -> bool {
        self.iflowerup
    }
    #[must_use]
    pub fn ifrunning(&self) -> bool {
        self.ifrunning
    }
    #[must_use]
    pub fn oper_state(&self) -> Option<State> {
        self.oper_state
    }
    #[must_use]
    pub fn carrier(&self) -> Option<bool> {
        self.carrier
    }
    #[must_use]
    pub fn carrierup(&self) -> Option<u32> {
        self.carrierup
    }
    #[must_use]
    pub fn carrierdown(&self) -> Option<u32> {
        self.carrierdown
    }
    #[must_use]
    pub fn mac(&self) -> Option<SourceMac> {
        self.mac
    }
}
impl std::fmt::Display for EthEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ifup = if self.ifup { "yes" } else { "no" };
        let ifloup = if self.iflowerup { "yes" } else { "no" };
        let ifrun = if self.ifrunning { "yes" } else { "no" };
        let carrier = self.carrier.map_or("--", |v| if v { "yes" } else { "no" });

        write!(f, "ifindex: {}", self.ifindex)?;
        if let Some(ifname) = self.name.as_ref() {
            write!(f, " ifname:{ifname}")?;
        }
        write!(
            f,
            " ifup:{ifup} iflowerup:{ifloup} ifrun:{ifrun} carrier:{carrier}",
        )?;
        if let Some(value) = self.carrierup {
            write!(f, " carrierup:{value}")?;
        }
        if let Some(value) = self.carrierdown {
            write!(f, " carrierdown:{value}")?;
        }
        if let Some(opstate) = self.oper_state {
            write!(f, " opstate:{opstate:?}")?;
        }
        Ok(())
    }
}

/// How often the monitor re-reads interface state.
///
/// Short enough that a dropped notification costs seconds rather than the life of the process,
/// long enough that the dump is irrelevant next to the traffic it protects: a handful of
/// interfaces every few seconds.
const RECONCILE_INTERVAL: tokio::time::Duration = tokio::time::Duration::from_secs(5);

/// Interface monitor.
pub struct InterfaceMonitor {
    tx: broadcast::Sender<EthEvent>,
    ct: CancellationToken,
}
impl InterfaceMonitor {
    #[must_use]
    pub fn new(ct: CancellationToken) -> Self {
        let (tx, _) = broadcast::channel::<EthEvent>(100);
        Self { tx, ct }
    }
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EthEvent> {
        self.tx.subscribe()
    }

    /// Convert a netlink message to an `EthEvent` if it is a `NewLink` message
    /// This is the main function used by the `InterfaceMonitor` to process netlink
    #[must_use]
    pub fn netlink_to_event(msg: NetlinkMessage<RouteNetlinkMessage>) -> Option<EthEvent> {
        let (_hdr, payload) = msg.into_parts();

        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg)) = payload else {
            return None;
        };
        Self::link_to_event(&link_msg)
    }

    /// Convert a `LinkMessage` to an `EthEvent` for a valid interface index.
    ///
    /// Split out from [`Self::netlink_to_event`] so that [`Self::resync`] can feed it messages
    /// from a `RTM_GETLINK` dump, which arrive as bare `LinkMessage`s rather than wrapped in a
    /// multicast notification.
    fn link_to_event(link_msg: &LinkMessage) -> Option<EthEvent> {
        let ifindex = link_msg.header.index;
        let Ok(ifindex) = InterfaceIndex::try_from(ifindex) else {
            error!("Received kernel event with invalid interface index: {ifindex}");
            return None;
        };
        let ifup = link_msg.header.flags.contains(LinkFlags::Up);
        let iflowerup = link_msg.header.flags.contains(LinkFlags::LowerUp);
        let ifrunning = link_msg.header.flags.contains(LinkFlags::Running);

        // optional
        let ifname = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::IfName(name) => match InterfaceName::try_from(name.as_str()) {
                Ok(valid) => Some(valid),
                Err(e) => {
                    warn!("Got kernel event for ifindex {ifindex} with invalid name {name}: {e}");
                    // we continue
                    None
                }
            },
            _ => None,
        });
        let carrier = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::Carrier(value) => Some(*value != 0),
            _ => None,
        });
        let carrierup = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::CarrierUpCount(value) => Some(*value),
            _ => None,
        });
        let carrierdown = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::CarrierDownCount(value) => Some(*value),
            _ => None,
        });
        let oper_state = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::OperState(value) => Some(*value),
            _ => None,
        });
        let mac = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::Address(value) => match SourceMac::try_from(value) {
                Ok(mac) => Some(mac),
                Err(e) => {
                    warn!("Got invalid mac {value:?}: {e}");
                    None
                }
            },
            _ => None,
        });

        // build `EthEvent` object
        let event = EthEvent::new(ifindex, ifup, iflowerup, ifrunning)
            .set_name(ifname)
            .set_oper_state(oper_state)
            .set_carrier(carrier)
            .set_carrierdown(carrierdown)
            .set_carrierup(carrierup)
            .set_mac(mac);

        debug!("Got event for {event}");
        Some(event)
    }

    /// Emit an event for every interface's current state.
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
            if let Some(event) = Self::link_to_event(&link) {
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
    /// This method fails if a netlink connection cannot be created.
    pub async fn run(monitor: Arc<Self>) -> std::io::Result<()> {
        info!("Starting interface monitor");
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
            Ok(n) => info!("Interface monitor resynced {n} interface(s)"),
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
                            if let Some(event) = Self::netlink_to_event(msg) && tx.send(event).is_err() {
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
        let _test_ifname = InterfaceName::try_from(INTERFACE).unwrap();
        let ct = CancellationToken::new();
        let ifmonitor = Arc::new(InterfaceMonitor::new(ct));
        let mut subsc1 = ifmonitor.subscribe();
        let mut subsc2 = ifmonitor.subscribe();
        tokio::spawn(InterfaceMonitor::run(ifmonitor.clone()));

        create_dummy(INTERFACE).await;

        // FIXME: Interface manager no longer filters by name. So here we should loop until
        // we hear something for interface INTERFACE (or timeout) since we could otherwise
        // get events for another interface. Fix when this test is not ignored
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
    use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
    use tokio_util::sync::CancellationToken;

    /// The MAC a control-plane tap adopts from its DPDK port.
    const PORT_MAC: [u8; 6] = [0x58, 0xa2, 0xe1, 0xb3, 0x3d, 0x94];

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
        let ev: EthEvent =
            InterfaceMonitor::link_to_event(&dumped_link("enp2s1np0", Some(PORT_MAC)))
                .expect("a dumped link must produce an event");
        assert_eq!(
            ev.mac.expect("the dump carried an address").inner().0,
            PORT_MAC,
            "resync must report the address the interface currently has"
        );
    }

    #[test]
    fn all_interface_names_are_reported() {
        for name in ["enp2s1np0", "some-other-nic"] {
            let event = InterfaceMonitor::link_to_event(&dumped_link(name, Some(PORT_MAC)))
                .expect("valid links are reported without configuration filtering");
            assert_eq!(event.name().unwrap().as_ref(), name);
        }
    }

    /// A message without an address attribute is not a message saying the address was removed,
    /// and must not throw away the rest of an otherwise good event.
    #[test]
    fn a_link_without_an_address_still_reports_state() {
        let ev = InterfaceMonitor::link_to_event(&dumped_link("enp2s1np0", None))
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
        let _: Arc<InterfaceMonitor> = Arc::new(InterfaceMonitor::new(CancellationToken::new()));
    }
}
