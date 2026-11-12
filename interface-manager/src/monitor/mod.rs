// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Broadcasts kernel interface events from the calling thread's network namespace.
//!
//! With an isolated datapath, configured names identify control-plane taps. This
//! monitor sees tap state, not physical link state. Propagating DPDK port state to
//! the taps remains a driver task.

use concurrency::sync::Arc;
use net::eth::mac::SourceMac;
use net::interface::{InterfaceIndex, InterfaceName, Mtu};
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, State};
use std::fmt::Display;
use tokio::sync::{broadcast, watch};
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
    mtu: Option<Mtu>,
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
            mtu: None,
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
    pub fn set_mtu(mut self, mtu: Option<Mtu>) -> Self {
        self.mtu = mtu;
        self
    }

    // ==  Getters == //
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
    #[must_use]
    pub fn mtu(&self) -> Option<Mtu> {
        self.mtu
    }
}
impl Display for EthEvent {
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
        if let Some(mac) = self.mac {
            write!(f, " mac:{mac}")?;
        }
        if let Some(mtu) = self.mtu {
            write!(f, " mtu:{mtu}")?;
        }
        Ok(())
    }
}

/// Interface monitor
pub struct InterfaceMonitor {
    tx: broadcast::Sender<EthEvent>,
    ct: CancellationToken,
    // report readiness. Currently only needed for tests
    ready: watch::Sender<bool>,
}
impl InterfaceMonitor {
    #[must_use]
    pub fn new(ct: CancellationToken) -> Self {
        let (tx, _) = broadcast::channel::<EthEvent>(100);
        let (ready, _) = watch::channel(false);
        Self { tx, ct, ready }
    }
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<EthEvent> {
        self.tx.subscribe()
    }

    /// wait until the monitor reports it is ready. This is only used in tests
    #[cfg(test)]
    pub async fn wait_ready(&self) {
        let _ = self.ready.subscribe().wait_for(|is_ready| *is_ready).await;
    }

    /// Convert a netlink message to an `EthEvent` if it is a `NewLink` message
    /// This is the main function used by the `InterfaceMonitor` to process netlink
    pub fn netlink_to_event(msg: NetlinkMessage<RouteNetlinkMessage>) -> Option<EthEvent> {
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
        let mtu = link_msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::Mtu(value) => match Mtu::try_from(*value) {
                Ok(mtu) => Some(mtu),
                Err(e) => {
                    warn!("Got invalid mtu {value}: {e}");
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
            .set_mac(mac)
            .set_mtu(mtu);

        debug!("Got event for {event}");
        Some(event)
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
        monitor.ready.send_replace(true);

        let tx = monitor.tx.clone();
        let ct = monitor.ct.clone();
        loop {
            tokio::select! {
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
    use crate::interface::TapDevice;
    use concurrency::sync::Arc;
    use net::interface::InterfaceName;
    use rtnetlink::Handle;
    use rtnetlink::{LinkUnspec, new_connection};
    use tokio::time::{Duration, timeout};
    use tokio_util::sync::CancellationToken;
    use tracing_test::traced_test;

    async fn bring_up_tap(nl_handle: &Handle, tap: &TapDevice) {
        println!("Bringing tap {}, index {} UP...", tap.name(), tap.index());
        nl_handle
            .link()
            .set(
                LinkUnspec::new_with_index(tap.index().to_u32())
                    .up()
                    .build(),
            )
            .execute()
            .await
            .expect("Failed to send netlink request");
    }

    async fn bring_down_tap(nl_handle: &Handle, tap: &TapDevice) {
        println!("Bringing tap {}, index {} DOWN...", tap.name(), tap.index());
        nl_handle
            .link()
            .set(
                LinkUnspec::new_with_index(tap.index().to_u32())
                    .down()
                    .build(),
            )
            .execute()
            .await
            .expect("Failed to send netlink request");
    }

    /// Test that a subscriber hears the events about an interface and that the monitor shutdowns on cancel
    #[n_vm::test]
    #[traced_test]
    async fn test_interface_monitor() {
        let name = InterfaceName::try_from("test-tap-1").unwrap();
        let ct = CancellationToken::new();
        let ifmonitor = Arc::new(InterfaceMonitor::new(ct.clone()));
        let mut events = ifmonitor.subscribe();
        let monitor = tokio::spawn(InterfaceMonitor::run(ifmonitor.clone()));
        timeout(Duration::from_secs(5), ifmonitor.wait_ready())
            .await
            .expect("monitor not ready in 5 secs");

        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        // create tap (generates event)
        let tap = TapDevice::open(&name).unwrap();

        // listen for events
        timeout(Duration::from_secs(5), async {
            let mut events_seen = 0;
            loop {
                let event = events.recv().await.unwrap();
                if event.name() == Some(&name) {
                    assert_eq!(event.ifindex(), tap.index());
                    match events_seen {
                        0 => {
                            assert!(!event.ifup());
                            bring_up_tap(&handle, &tap).await;
                        }
                        1 => {
                            assert!(event.ifup());
                            bring_down_tap(&handle, &tap).await;
                        }
                        2 => {
                            assert!(!event.ifup());
                            return;
                        }
                        _ => {}
                    }
                    events_seen += 1;
                }
            }
        })
        .await
        .expect("no event foir the tap was heard in 5 secs");

        ct.cancel();

        // check that the monitor task ended successfully after cancellation
        timeout(Duration::from_secs(5), monitor)
            .await
            .expect("monitor did not stop after cancellation")
            .expect("monitor task failed")
            .expect("monitor returned an error");
    }

    /// Test that changing the carrier in a tap produces netlink events that are propagated
    #[n_vm::test]
    async fn test_tap_carrier_is_seen_in_events() {
        let name = InterfaceName::try_from("test-tap-2").unwrap();
        let ct = CancellationToken::new();
        let ifmonitor = Arc::new(InterfaceMonitor::new(ct.clone()));
        let mut events = ifmonitor.subscribe();
        let _monitor = tokio::spawn(InterfaceMonitor::run(ifmonitor.clone()));
        timeout(Duration::from_secs(5), ifmonitor.wait_ready())
            .await
            .expect("monitor not ready in 5 secs");

        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        // create tap (generates event), bring it up and then down
        let tap = TapDevice::open(&name).unwrap();

        // listen for events
        timeout(Duration::from_secs(5), async {
            let mut events_seen = 0;
            loop {
                let event = events.recv().await.unwrap();
                if event.name() == Some(&name) {
                    assert_eq!(event.ifindex(), tap.index());
                    match events_seen {
                        0 => {
                            assert!(!event.ifup());
                            bring_up_tap(&handle, &tap).await;
                        }
                        1 => {
                            assert!(event.ifup());
                            assert!(event.iflowerup());
                            assert_eq!(event.carrier(), Some(true));
                            tap.set_carrier(false).expect("Failed to set carrier");
                        }
                        2 => {
                            assert!(event.ifup());
                            assert!(!event.iflowerup());
                            assert_eq!(event.carrier(), Some(false));
                            tap.set_carrier(true).expect("Failed to set carrier");
                        }
                        3 => {
                            // all is up as the result of set carrier in event 2
                            assert!(event.ifup());
                            assert!(event.iflowerup());
                            assert_eq!(event.carrier(), Some(true));
                            return;
                        }
                        _ => {}
                    }
                    events_seen += 1;
                }
            }
        })
        .await
        .expect("no event foir the tap was heard in 5 secs");

        ct.cancel();
    }
}
