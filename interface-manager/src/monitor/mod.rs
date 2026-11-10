// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Broadcasts kernel interface events from the calling thread's network namespace.
//!
//! With an isolated datapath, configured names identify control-plane taps. This
//! monitor sees tap state, not physical link state. Propagating DPDK port state to
//! the taps remains a driver task.

use concurrency::sync::Arc;
use rtnetlink::MulticastGroup;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::LinkMessage;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

#[allow(unused)]
use tracing::{debug, error, info, warn};

/// What the [`InterfaceMonitor`] reports.
///
/// Link messages are passed on as the kernel sent them: what to make of one is up to the
/// subscriber.
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    /// A link was created or changed (`RTM_NEWLINK`).
    NewLink(LinkMessage),
    /// A link was removed (`RTM_DELLINK`).
    DelLink(LinkMessage),
    /// The kernel dropped link events: the monitor's socket buffer was full (`ENOBUFS`, which
    /// netlink-proto reports as an `NLMSG_OVERRUN`). The kernel does not say which links changed,
    /// so anything a subscriber keeps from link events may now be stale and should be looked up
    /// again.
    Overrun,
}

/// Interface monitor
pub struct InterfaceMonitor {
    tx: broadcast::Sender<MonitorEvent>,
    ct: CancellationToken,
    // report readiness. Currently only needed for tests
    ready: watch::Sender<bool>,
}
impl InterfaceMonitor {
    #[must_use]
    pub fn new(ct: CancellationToken) -> Self {
        let (tx, _) = broadcast::channel::<MonitorEvent>(100);
        let (ready, _) = watch::channel(false);
        Self { tx, ct, ready }
    }
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<MonitorEvent> {
        self.tx.subscribe()
    }

    /// Wait until the monitor is listening for link changes. A change after this returns is
    /// reported to the subscribers.
    pub async fn wait_ready(&self) {
        let _ = self.ready.subscribe().wait_for(|is_ready| *is_ready).await;
    }

    /// What the monitor reports about a netlink message, if anything.
    #[must_use]
    pub fn netlink_to_monitor_event(
        msg: NetlinkMessage<RouteNetlinkMessage>,
    ) -> Option<MonitorEvent> {
        match msg.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
                Some(MonitorEvent::NewLink(link))
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
                Some(MonitorEvent::DelLink(link))
            }
            NetlinkPayload::Overrun(_) => {
                warn!("Netlink socket overrun: the kernel dropped link events");
                Some(MonitorEvent::Overrun)
            }
            _ => None,
        }
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
                            if let Some(event) = Self::netlink_to_monitor_event(msg) && tx.send(event).is_err() {
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
    use super::{InterfaceMonitor, MonitorEvent};
    use crate::interface::TapDevice;
    use concurrency::sync::Arc;
    use net::interface::InterfaceName;
    use rtnetlink::Handle;
    use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
    use rtnetlink::{LinkUnspec, new_connection};
    use tokio::time::{Duration, timeout};
    use tokio_util::sync::CancellationToken;
    use tracing_test::traced_test;

    /// An overrun is reported, so that subscribers know to look again (the kernel has dropped
    /// link events it will not repeat); a new link is reported as a link event.
    #[test]
    fn an_overrun_is_reported() {
        use rtnetlink::packet_core::{
            NLMSG_OVERRUN, NetlinkHeader, NetlinkMessage, NetlinkPayload,
        };
        use rtnetlink::packet_route::RouteNetlinkMessage;

        // as netlink-proto makes it from ENOBUFS
        let mut header = NetlinkHeader::default();
        header.message_type = NLMSG_OVERRUN;
        let overrun =
            NetlinkMessage::<RouteNetlinkMessage>::new(header, NetlinkPayload::Overrun(Vec::new()));
        assert!(matches!(
            InterfaceMonitor::netlink_to_monitor_event(overrun),
            Some(MonitorEvent::Overrun)
        ));

        let mut link = LinkMessage::default();
        link.header.index = 7;
        let new_link = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)),
        );
        assert!(matches!(
            InterfaceMonitor::netlink_to_monitor_event(new_link),
            Some(MonitorEvent::NewLink(link)) if link.header.index == 7
        ));

        let mut link = LinkMessage::default();
        link.header.index = 8;
        let del_link = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)),
        );
        assert!(matches!(
            InterfaceMonitor::netlink_to_monitor_event(del_link),
            Some(MonitorEvent::DelLink(link)) if link.header.index == 8
        ));
    }

    /// A `RTM_NEWLINK` about the link named `name`, with what the tests check about it.
    fn link_named(event: MonitorEvent, name: &InterfaceName) -> Option<(LinkMessage, LinkView)> {
        let MonitorEvent::NewLink(link) = event else {
            assert!(
                !matches!(event, MonitorEvent::Overrun),
                "the monitor overran: the kernel dropped the events under test"
            );
            return None;
        };
        let named = link.attributes.iter().any(
            |attribute| matches!(attribute, LinkAttribute::IfName(raw) if raw == name.as_ref()),
        );
        if !named {
            return None;
        }
        let view = LinkView {
            up: link.header.flags.contains(LinkFlags::Up),
            lower_up: link.header.flags.contains(LinkFlags::LowerUp),
            carrier: link
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::Carrier(value) => Some(*value != 0),
                    _ => None,
                }),
        };
        Some((link, view))
    }

    /// What the tests check about a link message.
    struct LinkView {
        up: bool,
        lower_up: bool,
        carrier: Option<bool>,
    }

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
                if let Some((link, event)) = link_named(events.recv().await.unwrap(), &name) {
                    assert_eq!(link.header.index, tap.index().to_u32());
                    match events_seen {
                        0 => {
                            assert!(!event.up);
                            bring_up_tap(&handle, &tap).await;
                        }
                        1 => {
                            assert!(event.up);
                            bring_down_tap(&handle, &tap).await;
                        }
                        2 => {
                            assert!(!event.up);
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
                if let Some((link, event)) = link_named(events.recv().await.unwrap(), &name) {
                    assert_eq!(link.header.index, tap.index().to_u32());
                    match events_seen {
                        0 => {
                            assert!(!event.up);
                            bring_up_tap(&handle, &tap).await;
                        }
                        1 => {
                            assert!(event.up);
                            assert!(event.lower_up);
                            assert_eq!(event.carrier, Some(true));
                            tap.set_carrier(false).expect("Failed to set carrier");
                        }
                        2 => {
                            assert!(event.up);
                            assert!(!event.lower_up);
                            assert_eq!(event.carrier, Some(false));
                            tap.set_carrier(true).expect("Failed to set carrier");
                        }
                        3 => {
                            // all is up as the result of set carrier in event 2
                            assert!(event.up);
                            assert!(event.lower_up);
                            assert_eq!(event.carrier, Some(true));
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
