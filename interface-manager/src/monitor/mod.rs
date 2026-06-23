// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A small interface monitor. The interface monitor listens to netlink events asynchronously
//! and disseminates them over a broadcast channel. It does not make any attempt to interpret
//! the events received via netlink. The interface monitor reports events on ethernet interfaces.
//! For testing, it can be allowed to report events for other types of network devices.

use concurrency::sync::Arc;
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
    pub name: InterfaceName,
    pub ifindex: InterfaceIndex,
    pub ifup: bool,
    pub iflowerup: bool,
    pub ifrunning: bool,
    pub carrier: bool,
    pub carrierup: u32,
    pub carrierdown: u32,
}
impl std::fmt::Display for EthEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ifup = if self.ifup { "yes" } else { "no" };
        let ifloup = if self.iflowerup { "yes" } else { "no" };
        let ifrun = if self.ifrunning { "yes" } else { "no" };
        let carrier = if self.carrier { "yes" } else { "no" };
        write!(
            f,
            "ifname:{} ({}) ifup:{ifup} iflowerup:{ifloup} ifrun:{ifrun} carrier:{carrier} carrierup:{} carrierdown:{}",
            self.name, self.ifindex, self.carrierup, self.carrierdown
        )
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
    fn netlink_to_event(&self, msg: NetlinkMessage<RouteNetlinkMessage>) -> Option<EthEvent> {
        let (_hdr, payload) = msg.into_parts();

        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg)) = payload else {
            return None;
        };
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
        };
        info!("Got event for {event}");
        Some(event)
    }

    /// Start an interface monitor to track the set of network devices
    ///
    /// # Errors
    ///
    /// This method fails if a netlink connection cannot be created.
    pub async fn run(self: Arc<Self>) -> Result<(), ()> {
        info!("Starting interface monitor");
        for i in &self.tracked {
            info!("Will track status of interface {i}");
        }
        let (conn, _, mut messages) = rtnetlink::new_multicast_connection(&[MulticastGroup::Link])
            .inspect_err(|e| error!("Failed to open netlink connection: {e}"))
            .map_err(|_| ())?;

        tokio::spawn(conn);

        let tx = self.tx.clone();
        let ct = self.ct.clone();
        loop {
            tokio::select! {
                nlmsg = messages.recv() => {
                    match nlmsg {
                        Ok((msg, _)) => {
                            if let Some(event) = self.netlink_to_event(msg) && tx.send(event).is_err() {
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

    #[traced_test]
    #[tokio::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[n_vm::in_vm]
    #[cfg_attr(not(emulated), traced_test)]
    #[ignore = "disabled until nv_m support is re-enabled"]
    async fn test_interface_monitor() {
        const INTERFACE: &str = "test-dummy";
        let test_ifname = InterfaceName::try_from(INTERFACE).unwrap();
        let ct = CancellationToken::new();
        let ifmonitor = Arc::new(InterfaceMonitor::new(ct, &[test_ifname]));
        let mut subsc1 = ifmonitor.subscribe();
        let mut subsc2 = ifmonitor.subscribe();
        tokio::spawn(ifmonitor.clone().run());

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
