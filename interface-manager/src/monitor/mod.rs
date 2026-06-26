// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A small interface monitor. The interface monitor listens to netlink events asynchronously
//! and disseminates them over a broadcast channel. It does not make any attempt to interpret
//! the events received via netlink. The interface monitor reports events on ethernet interfaces.
//! For testing, it can be allowed to report events for any network device.

use concurrency::sync::Arc;
use net::interface::{InterfaceIndex, InterfaceName};
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkLayerType};
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
    pub iflowerup: bool, // not really needed for eths
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

/// Convert a netlink message to an `EthEvent`
fn netlink_to_event(msg: NetlinkMessage<RouteNetlinkMessage>, phy_only: bool) -> Option<EthEvent> {
    let (_hdr, payload) = msg.into_parts();

    // we only care about `NewLink` messages and ethernet
    let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link_msg)) = payload else {
        return None;
    };
    if link_msg.header.link_layer_type != LinkLayerType::Ether {
        return None;
    }

    let ifindex = link_msg.header.index;
    let ifup = link_msg.header.flags.contains(LinkFlags::Up);
    let iflowerup = link_msg.header.flags.contains(LinkFlags::LowerUp);
    let ifrunning = link_msg.header.flags.contains(LinkFlags::Running);

    // heuristic to determine if interface is physical: should not have linkinfo.
    // we also allow veths for testing.
    let info = link_msg
        .attributes
        .iter()
        .find(|a| matches!(a, LinkAttribute::LinkInfo(_)));

    let is_veth = if let Some(info) = info
        && let LinkAttribute::LinkInfo(v) = info
    {
        v.iter()
            .find(|i| matches!(i, LinkInfo::Kind(InfoKind::Veth)))
            .is_some()
    } else {
        false
    };

    // we allow veths for testing
    if info.is_some() && !is_veth && phy_only {
        return None;
    }

    let ifname = link_msg.attributes.iter().find_map(|a| match a {
        LinkAttribute::IfName(name) => Some(name.clone()),
        _ => None,
    })?;
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
    // `LinkAttribute::OperState` is not reliable for events

    // construct the event object
    let event = EthEvent {
        name: InterfaceName::try_from(ifname).ok()?,
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

/// Interface monitor
pub struct InterfaceMonitor {
    tx: broadcast::Sender<EthEvent>,
    ct: CancellationToken,
    phy_only: bool,
}
impl InterfaceMonitor {
    #[must_use]
    pub fn new(ct: CancellationToken) -> Self {
        let (tx, _) = broadcast::channel::<EthEvent>(100);
        Self {
            tx,
            ct,
            phy_only: false,
        }
    }
    #[must_use]
    pub fn phy_only(mut self) -> Self {
        self.phy_only = true;
        self
    }
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EthEvent> {
        self.tx.subscribe()
    }

    /// Start the interface monitor
    ///
    /// # Errors
    ///
    /// This method fails if a netlink connection cannot be created.
    pub async fn run(self: Arc<Self>) -> Result<(), ()> {
        info!("Starting interface monitor");
        let (conn, _, mut messages) = rtnetlink::new_multicast_connection(&[MulticastGroup::Link])
            .inspect_err(|e| error!("Failed to open netlink connection: {e}"))
            .map_err(|_| ())?;

        tokio::spawn(conn);

        let tx = self.tx.clone();
        let ct = self.ct.clone();
        let phy_only = self.phy_only;
        loop {
            tokio::select! {
                nlmsg = messages.recv() => {
                    match nlmsg {
                        Ok((msg, _)) => {
                            if let Some(event) = netlink_to_event(msg, phy_only) && tx.send(event).is_err() {
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
    #[ignore = "could not make this test to run"]
    async fn test_interface_monitor() {
        let ct = CancellationToken::new();
        let ifmonitor = Arc::new(InterfaceMonitor::new(ct));
        let mut subsc1 = ifmonitor.subscribe();
        let mut subsc2 = ifmonitor.subscribe();
        tokio::spawn(ifmonitor.clone().run());
        create_dummy("dummy-test-iface").await;

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
