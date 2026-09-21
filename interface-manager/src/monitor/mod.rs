// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A small interface monitor. The interface monitor listens to netlink events asynchronously
//! and disseminates them over a broadcast channel. It does not make any attempt to interpret
//! the events received via netlink. The interface monitor reports events on ethernet interfaces.
//! For testing, it can be allowed to report events for other types of network devices.

use concurrency::sync::Arc;
use net::eth::mac::SourceMac;
use net::interface::{InterfaceIndex, InterfaceName};
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

#[allow(unused)]
use tracing::{debug, error, info, warn};

/// A type representing an event on an Ethernet interface.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct EthEvent {
    ifindex: InterfaceIndex,
    name: InterfaceName,
    ifup: bool,
    iflowerup: bool,
    ifrunning: bool,
    carrier: Option<bool>,
    carrierup: Option<u32>,   // stats
    carrierdown: Option<u32>, // stats
    mac: Option<SourceMac>,
}
impl EthEvent {
    #[must_use]
    pub fn new(
        ifindex: InterfaceIndex,
        name: InterfaceName,
        ifup: bool,
        iflowerup: bool,
        ifrunning: bool,
    ) -> Self {
        Self {
            ifindex,
            name,
            ifup,
            iflowerup,
            ifrunning,
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
    pub fn set_mac(mut self, mac: Option<SourceMac>) -> Self {
        self.mac = mac;
        self
    }

    #[must_use]
    pub fn ifindex(&self) -> InterfaceIndex {
        self.ifindex
    }
    #[must_use]
    pub fn name(&self) -> &InterfaceName {
        &self.name
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

        write!(
            f,
            "ifname:{} ({}) ifup:{ifup} iflowerup:{ifloup} ifrun:{ifrun} carrier:{carrier}",
            self.name, self.ifindex
        )?;
        if let Some(value) = self.carrierup {
            write!(f, " carrierup:{value}")?;
        }
        if let Some(value) = self.carrierdown {
            write!(f, " carrierdown:{value}")?;
        }
        Ok(())
    }
}

/// Interface monitor
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
    /// N.B. we don't assume that all of the info will be reported.
    /// FIXME(fredi): name should not be considered mandatory, but we do here
    fn netlink_to_event(&self, msg: NetlinkMessage<RouteNetlinkMessage>) -> Option<EthEvent> {
        let (_hdr, payload) = msg.into_parts();

        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg)) = payload else {
            return None;
        };
        let ifindex = link_msg.header.index;
        let Ok(ifindex) = InterfaceIndex::try_from(ifindex) else {
            error!("Received kernel event with invalid interface index: {ifindex}");
            return None;
        };
        let ifup = link_msg.header.flags.contains(LinkFlags::Up);
        let iflowerup = link_msg.header.flags.contains(LinkFlags::LowerUp);
        let ifrunning = link_msg.header.flags.contains(LinkFlags::Running);

        // interface name: strictly speaking, this is optional but we count on it for filtering.
        // In practice we should always get it, but log otherwise
        // FIXME(fredi)
        let Some(name) = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::IfName(name) => Some(name.clone()),
            _ => None,
        }) else {
            error!("Received kernel event for ifindex {ifindex} without name!");
            return None;
        };
        let Ok(ifname) = InterfaceName::try_from(name.clone()) else {
            error!("Received kernel event for ifindex {ifindex} with invalid name {name}");
            return None;
        };
        if !self.tracked.contains(&ifname) {
            return None;
        }

        // optional
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

        // `LinkAttribute::OperState` is not reliable for events, so we ignore it.
        // N.B. the above attributes are required (watch the ?)

        // build event object
        let event = EthEvent::new(ifindex, ifname, ifup, iflowerup, ifrunning)
            .set_carrier(carrier)
            .set_carrierdown(carrierdown)
            .set_carrierup(carrierup)
            .set_mac(mac);

        info!("Got event for {event}");
        Some(event)
    }

    /// Start an interface monitor to track the set of network devices
    ///
    /// # Errors
    ///
    /// This method fails if a netlink connection cannot be created.
    pub async fn run(monitor: Arc<Self>) -> std::io::Result<()> {
        info!("Starting interface monitor");
        for i in &monitor.tracked {
            info!("Will track status of interface {i}");
        }
        let (conn, _, mut messages) = rtnetlink::new_multicast_connection(&[MulticastGroup::Link])
            .inspect_err(|e| error!("Failed to open netlink connection: {e}"))?;

        tokio::spawn(conn);

        let tx = monitor.tx.clone();
        let ct = monitor.ct.clone();
        loop {
            tokio::select! {
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
