// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Keep the router's view of the kernel's links current.
//!
//! The router used to apply each link event as it came, and drop any event for an interface its
//! configuration did not name yet. An event lost that way was lost for good: the kernel does not
//! repeat itself. That is how a tap given its port's MAC while the first configuration was being
//! built kept its random MAC in the router (githedgehog/fabricator#2268), and events the monitor's
//! subscribers fell behind on were lost the same way.
//!
//! Here a link event is only a cue to look again. Each one leads to a complete observation of the
//! kernel's links, which the router takes in place of the last. The router's view is then as new as
//! the latest observation, and the latest observation is taken after the latest change, however the
//! changes were reported or interleaved with configurations.

use interface_manager::monitor::InterfaceMonitor;

use clock::Duration;
use concurrency::sync::Arc;
use futures::StreamExt;
use net::eth::mac::SourceMac;
use net::interface::{InterfaceIndex, InterfaceIndexError, InterfaceName, Mtu};
use routing::{IfState, LinkState, LinkStates, RouterCtlSender};
use rtnetlink::packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage, State};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tracing::{debug, error, warn};

/// How long to wait before observing again after an observation failed.
const RETRY: Duration = Duration::from_millis(100);

/// Why a link was left out of an observation.
///
/// Leaving such a link out loses nothing: a router configuration cannot name an interface without
/// a valid index.
#[derive(Debug, thiserror::Error)]
enum NotObserved {
    #[error("invalid interface index: {0}")]
    Index(#[from] InterfaceIndexError),
}

/// The link state in a `RTM_NEWLINK`.
///
/// This reads only what every link has (index, name, address, MTU, flags and operational state),
/// so every kind of link is observed, whether or not interface-manager can model it. A virtio-net
/// port, a VLAN subinterface, a veth or the loopback the router is configured with has to be
/// observed as surely as a tap; an interface the observation leaves out keeps the state its
/// configuration was built with, which is how a port kept a stale MAC in #2268.
///
/// An address that is not a usable source MAC (the loopback's zeros, a tunnel's IPv4 address) is
/// observed as no MAC; the router only takes a MAC for interface types that have one anyway. A
/// name the kernel accepts but an [`InterfaceName`] does not (`port+blue`) is observed as no name,
/// and the rest of the link's state is observed all the same: the link is still there, under its
/// index. An MTU outside the range of an [`Mtu`] is observed as no MTU.
fn link_state(message: &LinkMessage) -> Result<LinkState, NotObserved> {
    let ifindex = InterfaceIndex::try_new(message.header.index)?;
    let mut name = None;
    let mut mac = None;
    let mut mtu = None;
    let mut kernel_oper_state = None;
    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::IfName(raw) => {
                name = InterfaceName::try_from(raw.as_str())
                    .inspect_err(|e| debug!("Link {ifindex} has a name the router can't take: {e}"))
                    .ok();
            }
            LinkAttribute::Address(raw) => mac = SourceMac::try_from(raw).ok(),
            LinkAttribute::Mtu(raw) => mtu = Mtu::try_from(*raw).ok(),
            LinkAttribute::OperState(state) => kernel_oper_state = Some(*state),
            _ => {}
        }
    }
    let flags = message.header.flags;
    Ok(LinkState {
        ifindex,
        name,
        mac,
        mtu,
        admin_state: IfState::from(flags.contains(LinkFlags::Up)),
        oper_state: oper_state(kernel_oper_state, flags),
    })
}

/// The operational state of a link, as the router (and the egress stage, which drops packets for an
/// interface that is operationally down) understands it.
///
/// The kernel's operational state decides when it says up or down. It does not always say
/// (`IF_OPER_UNKNOWN` is what a driver that does not manage it reports, a tap among them), and the
/// other states (testing, unknown, and anything newer) say nothing either way, so those fall back to
/// `IFF_RUNNING`. Carrier and `IFF_LOWER_UP` are not considered.
fn oper_state(kernel: Option<State>, flags: LinkFlags) -> IfState {
    match kernel {
        Some(State::Up) => IfState::Up,
        Some(State::Down | State::LowerLayerDown | State::Dormant | State::NotPresent) => {
            IfState::Down
        }
        Some(_) | None => IfState::from(flags.contains(LinkFlags::Running)),
    }
}

/// Why an observation of the kernel's links failed.
#[derive(Debug, thiserror::Error)]
enum ObserveError {
    #[error(transparent)]
    Netlink(#[from] rtnetlink::Error),
    /// The links changed while the kernel was dumping them (`NLM_F_DUMP_INTR`), so the dump may
    /// leave out or repeat links. Look again.
    #[error("the link dump was interrupted by a change")]
    Interrupted,
    /// The dump ended without a successful `NLMSG_DONE`: the connection went away, or the kernel
    /// reported an error at the end of it. It may leave out links.
    #[error("the link dump ended without a successful NLMSG_DONE")]
    Incomplete,
    #[error("failed to open a netlink connection: {0}")]
    Connection(#[from] std::io::Error),
}

/// The links of one link dump, as its messages come.
#[derive(Default)]
struct LinkDump {
    links: Vec<LinkState>,
    interrupted: bool,
    done: bool,
}

impl LinkDump {
    /// Take one message of the dump's response.
    ///
    /// The kernel flags a dump that links changed during, on any of its messages (`NLM_F_DUMP_INTR`,
    /// see `nl_dump_check_consistent`). rtnetlink's link request drops the headers that carry the
    /// flag, which is why the dump is read here. A dump is only complete with its `NLMSG_DONE`,
    /// which netlink-proto only hands over with `set_forward_done(true)` (see [`observe`]); the
    /// flag may be on that message alone.
    fn read(&mut self, message: NetlinkMessage<RouteNetlinkMessage>) -> Result<(), ObserveError> {
        self.interrupted |= message.header.flags & NLM_F_DUMP_INTR != 0;
        match message.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(message)) => {
                match link_state(&message) {
                    Ok(link) => self.links.push(link),
                    Err(e) => debug!("Not observing link {}: {e}", message.header.index),
                }
            }
            NetlinkPayload::Done(done) => self.done = done.code == 0,
            NetlinkPayload::Error(e) => return Err(rtnetlink::Error::NetlinkError(e).into()),
            _ => {}
        }
        Ok(())
    }

    /// The complete observation, unless the dump did not end with a successful `NLMSG_DONE`, or
    /// links changed during it.
    fn finish(self) -> Result<LinkStates, ObserveError> {
        if self.interrupted {
            return Err(ObserveError::Interrupted);
        }
        if !self.done {
            return Err(ObserveError::Incomplete);
        }
        Ok(self.links.into_iter().collect())
    }
}

/// Observe all of the kernel's links.
///
/// Each observation has a connection of its own: one that went away (its task ended) cannot leave
/// every later observation failing. The connection ends with the observation, when its handle is
/// dropped.
async fn observe() -> Result<LinkStates, ObserveError> {
    let (mut connection, mut handle, _) = rtnetlink::new_connection()?;
    connection.set_forward_done(true);
    tokio::spawn(connection);

    let mut request = NetlinkMessage::from(RouteNetlinkMessage::GetLink(LinkMessage::default()));
    request.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    let mut messages = handle.request(request)?;
    let mut dump = LinkDump::default();
    while let Some(message) = messages.next().await {
        dump.read(message)?;
    }
    dump.finish()
}

/// Hand the router a fresh observation of the kernel's links whenever they change.
pub(crate) async fn sync_link_state(monitor: Arc<InterfaceMonitor>, router: RouterCtlSender) {
    // Watch first, then look: a change after the monitor is listening is a cue for another
    // observation, and the first observation is taken after that, so it covers every change
    // before.
    let mut changes = monitor.subscribe();
    monitor.wait_ready().await;
    loop {
        match observe().await {
            Ok(links) => {
                debug!("Observed the state of {} links", links.len());
                if router.send_link_state(links).await.is_err() {
                    warn!("Failed to hand the router the state of the links");
                }
            }
            Err(ObserveError::Interrupted) => {
                // the change that interrupted it is in the kernel now: the next dump sees it
                debug!("The kernel's links changed while observing them. Looking again");
                continue;
            }
            Err(e) => {
                error!("Failed to observe the kernel's links: {e}. Will try again.");
                tokio::time::sleep(RETRY).await;
                continue;
            }
        }

        // Wait for a change, then consume every other change already queued: the next observation
        // covers them all. Falling behind loses nothing either; it is just another change. Nor does
        // the kernel dropping events when the monitor's socket overruns: the monitor reports the
        // overrun, and that is a change like any other.
        //
        // The channel does not close while `monitor` is held. If the monitor's task ends, mgmt
        // treats that as fatal (see `run_mgmt`), so there is no stale state to outlive.
        if let Err(RecvError::Closed) = changes.recv().await {
            break;
        }
        while let Ok(_) | Err(TryRecvError::Lagged(_)) = changes.try_recv() {}
    }
}

#[cfg(test)]
mod test {
    use super::{LinkDump, NotObserved, ObserveError, link_state};
    use interface_manager::interface::TryFromLinkMessage;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::{Interface, InterfaceIndex, InterfaceName, Mtu};
    use routing::LinkStates;
    use routing::{IfState, LinkState};
    use rtnetlink::packet_core::{
        DoneMessage, ErrorMessage, NLM_F_DUMP_INTR, NLM_F_MULTIPART, NetlinkHeader, NetlinkMessage,
        NetlinkPayload,
    };
    use rtnetlink::packet_route::RouteNetlinkMessage;
    use rtnetlink::packet_route::link::{
        InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage, State,
    };

    /// A `RTM_NEWLINK` as the kernel sends it, with only the attributes the tests care about.
    fn message(index: u32, flags: LinkFlags, attributes: Vec<LinkAttribute>) -> LinkMessage {
        let mut message = LinkMessage::default();
        message.header.index = index;
        message.header.flags = flags;
        message.attributes = attributes;
        message
    }

    fn mac(raw: &str) -> Vec<u8> {
        Mac::try_from(raw).unwrap().as_ref().to_vec()
    }

    /// The operational state follows the kernel's when it says up or down, and `IFF_RUNNING`
    /// when it does not: the mapping the router used before link state was observed, which the
    /// egress stage's drops for an operationally down interface depend on.
    #[test]
    fn a_tap_is_observed_with_its_flags_and_operational_state() {
        let up = LinkFlags::Up;
        let running = LinkFlags::Up | LinkFlags::Running;
        // (flags, kernel oper state) -> (admin, oper)
        let cases = [
            (running, Some(State::Up), IfState::Up, IfState::Up),
            (up, Some(State::Up), IfState::Up, IfState::Up),
            (
                LinkFlags::empty(),
                Some(State::Down),
                IfState::Down,
                IfState::Down,
            ),
            (running, Some(State::Down), IfState::Up, IfState::Down),
            (running, Some(State::Dormant), IfState::Up, IfState::Down),
            (
                running,
                Some(State::LowerLayerDown),
                IfState::Up,
                IfState::Down,
            ),
            (running, Some(State::NotPresent), IfState::Up, IfState::Down),
            // the kernel does not say: IFF_RUNNING decides
            (running, Some(State::Unknown), IfState::Up, IfState::Up),
            (up, Some(State::Unknown), IfState::Up, IfState::Down),
            (running, Some(State::Testing), IfState::Up, IfState::Up),
            (up, Some(State::Testing), IfState::Up, IfState::Down),
            (running, None, IfState::Up, IfState::Up),
            (up, None, IfState::Up, IfState::Down),
        ];
        for (flags, oper, admin_state, oper_state) in cases {
            let mut attributes = vec![
                LinkAttribute::IfName("Eth0".to_string()),
                LinkAttribute::Address(mac("02:0a:0b:0c:0d:01")),
                LinkAttribute::Mtu(9100),
                LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Tun)]),
            ];
            attributes.extend(oper.map(LinkAttribute::OperState));
            let tap = message(10, flags, attributes);
            assert_eq!(
                link_state(&tap).unwrap(),
                LinkState {
                    ifindex: InterfaceIndex::try_new(10).unwrap(),
                    name: Some(InterfaceName::try_from("Eth0").unwrap()),
                    mac: Some(SourceMac::try_from("02:0a:0b:0c:0d:01").unwrap()),
                    mtu: Some(Mtu::try_from(9100u32).unwrap()),
                    admin_state,
                    oper_state,
                },
                "{flags:?} {oper:?}"
            );
        }
    }

    /// Links interface-manager cannot model are observed all the same (githedgehog/fabricator#2268
    /// in kernel-driver mode).
    #[test]
    fn a_link_interface_manager_cannot_model_is_observed() {
        let up = LinkFlags::Up | LinkFlags::Running | LinkFlags::LowerUp;
        let links = [
            // a virtio-net port: its parent device is not a PCI address
            message(
                2,
                up,
                vec![
                    LinkAttribute::IfName("enp1s0".to_string()),
                    LinkAttribute::OperState(State::Up),
                    LinkAttribute::Address(mac("52:54:00:12:34:56")),
                    LinkAttribute::Mtu(1500),
                    LinkAttribute::ParentDevName("virtio0".to_string()),
                ],
            ),
            // a VLAN subinterface
            message(
                3,
                up,
                vec![
                    LinkAttribute::IfName("enp1s0.100".to_string()),
                    LinkAttribute::OperState(State::Up),
                    LinkAttribute::Address(mac("52:54:00:12:34:56")),
                    LinkAttribute::Mtu(1500),
                    LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Vlan)]),
                ],
            ),
            // a veth
            message(
                4,
                up,
                vec![
                    LinkAttribute::IfName("veth0".to_string()),
                    LinkAttribute::OperState(State::Up),
                    LinkAttribute::Address(mac("02:00:00:00:00:04")),
                    LinkAttribute::Mtu(1500),
                    LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Veth)]),
                ],
            ),
        ];
        for link in links {
            assert!(
                Interface::try_from_link_message(&link).is_err(),
                "interface-manager models {link:?} now; this test no longer shows anything"
            );
            let observed = link_state(&link).unwrap();
            assert_eq!(observed.ifindex.to_u32(), link.header.index);
            assert!(observed.mac.is_some());
            assert_eq!(observed.admin_state, IfState::Up);
            assert_eq!(observed.oper_state, IfState::Up);
        }
    }

    /// The loopback and tunnels have addresses, but no source MAC.
    #[test]
    fn an_address_that_is_not_a_source_mac_is_no_mac() {
        let lo = message(
            1,
            LinkFlags::Up | LinkFlags::Loopback,
            vec![
                LinkAttribute::IfName("lo".to_string()),
                LinkAttribute::OperState(State::Unknown),
                LinkAttribute::Address(vec![0; 6]),
                LinkAttribute::Mtu(65536),
            ],
        );
        let ipip = message(
            5,
            LinkFlags::Up,
            vec![
                LinkAttribute::IfName("tunl0".to_string()),
                LinkAttribute::OperState(State::Unknown),
                LinkAttribute::Address(vec![0; 4]),
                LinkAttribute::Mtu(1480),
            ],
        );
        for link in [lo, ipip] {
            let observed = link_state(&link).unwrap();
            assert_eq!(observed.mac, None, "{link:?}");
        }
    }

    #[test]
    fn a_link_without_a_valid_index_is_not_observed() {
        let name = || LinkAttribute::IfName("Eth0".to_string());
        assert!(matches!(
            link_state(&message(0, LinkFlags::Up, vec![name()])),
            Err(NotObserved::Index(_))
        ));
    }

    /// Linux takes names an `InterfaceName` does not (`port+blue`; a rename keeps the index). The
    /// link is still there under its index, and the rest of its state is observed all the same.
    #[test]
    fn a_link_with_a_name_the_router_cannot_take_is_observed_without_one() {
        let up = LinkFlags::Up | LinkFlags::Running;
        let attributes = |name: Option<&str>| {
            let mut attributes = vec![
                LinkAttribute::OperState(State::Up),
                LinkAttribute::Address(mac("02:0a:0b:0c:0d:01")),
                LinkAttribute::Mtu(9100),
            ];
            attributes.extend(name.map(|name| LinkAttribute::IfName(name.to_string())));
            attributes
        };
        for name in [Some("port+blue"), Some("eth0:1"), None] {
            let observed = link_state(&message(10, up, attributes(name))).unwrap();
            assert_eq!(
                observed,
                LinkState {
                    ifindex: InterfaceIndex::try_new(10).unwrap(),
                    name: None,
                    mac: Some(SourceMac::try_from("02:0a:0b:0c:0d:01").unwrap()),
                    mtu: Some(Mtu::try_from(9100u32).unwrap()),
                    admin_state: IfState::Up,
                    oper_state: IfState::Up,
                },
                "{name:?}"
            );
        }
    }

    /// An MTU outside the range of an `Mtu` is no MTU (Linux takes 1200 on a port).
    #[test]
    fn an_mtu_out_of_range_is_no_mtu() {
        let link = message(
            10,
            LinkFlags::Up,
            vec![
                LinkAttribute::IfName("Eth0".to_string()),
                LinkAttribute::Mtu(1200),
            ],
        );
        assert!(
            Mtu::try_from(1200u32).is_err(),
            "1200 is in range now; pick another"
        );
        assert_eq!(link_state(&link).unwrap().mtu, None);
    }

    fn dump_message(
        flags: u16,
        payload: NetlinkPayload<RouteNetlinkMessage>,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut message = NetlinkMessage::new(NetlinkHeader::default(), payload);
        message.header.flags = flags;
        message
    }

    fn new_link(index: u32, name: &str) -> NetlinkPayload<RouteNetlinkMessage> {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(message(
            index,
            LinkFlags::Up,
            vec![LinkAttribute::IfName(name.to_string())],
        )))
    }

    fn done(code: i32) -> NetlinkMessage<RouteNetlinkMessage> {
        let mut done = DoneMessage::default();
        done.code = code;
        dump_message(NLM_F_MULTIPART, NetlinkPayload::Done(done))
    }

    fn read_all(
        messages: Vec<NetlinkMessage<RouteNetlinkMessage>>,
    ) -> Result<LinkStates, ObserveError> {
        let mut dump = LinkDump::default();
        for message in messages {
            dump.read(message)?;
        }
        dump.finish()
    }

    fn links() -> Vec<NetlinkMessage<RouteNetlinkMessage>> {
        vec![
            dump_message(NLM_F_MULTIPART, new_link(1, "lo")),
            dump_message(NLM_F_MULTIPART, new_link(10, "Eth0")),
        ]
    }

    #[test]
    fn a_dump_is_the_links_it_lists() {
        let mut messages = links();
        messages.push(done(0));
        let links = read_all(messages).unwrap();
        assert_eq!(links.len(), 2);
        assert!(links.get(InterfaceIndex::try_new(10).unwrap()).is_some());
    }

    /// A dump only ends with its `NLMSG_DONE`. Without one (the connection went away mid-dump,
    /// which ends the response stream like a dump that is over), or with an error in it, the dump
    /// may leave links out, and the router would take those as gone.
    #[test]
    fn a_dump_without_a_successful_done_is_no_observation() {
        assert!(matches!(read_all(links()), Err(ObserveError::Incomplete)));
        let mut messages = links();
        messages.push(done(-16)); // EBUSY
        assert!(matches!(read_all(messages), Err(ObserveError::Incomplete)));
    }

    /// A dump links changed during may leave links out: an interface it left out would then be
    /// taken as gone, so it is no observation at all. The kernel may flag any of the dump's
    /// messages, the final `NLMSG_DONE` included.
    #[test]
    fn an_interrupted_dump_is_no_observation() {
        for flagged in 0..3 {
            let mut messages = links();
            messages.push(done(0));
            messages[flagged].header.flags |= NLM_F_DUMP_INTR;
            assert!(
                matches!(read_all(messages), Err(ObserveError::Interrupted)),
                "flag on message {flagged}"
            );
        }
    }

    #[test]
    fn an_error_fails_the_dump() {
        let mut error = ErrorMessage::default();
        error.code = std::num::NonZeroI32::new(-16); // EBUSY
        assert!(matches!(
            read_all(vec![dump_message(0, NetlinkPayload::Error(error))]),
            Err(ObserveError::Netlink(_))
        ));
    }

    /// The dump against a real kernel and netlink-proto: it ends with its `NLMSG_DONE` (or
    /// `observe` would fail), every link is in it, the loopback included, and changes are in the
    /// next one, a rename to a name the router cannot take included.
    #[n_vm::test]
    async fn observe_sees_the_kernels_links_and_their_changes() {
        use super::observe;
        use interface_manager::interface::TapDevice;
        use rtnetlink::LinkUnspec;

        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);
        let name = |raw: &str| Some(InterfaceName::try_from(raw).unwrap());

        let lo = InterfaceIndex::try_new(1).unwrap();
        let tap = TapDevice::open(&InterfaceName::try_from("observe-tap").unwrap()).unwrap();
        let links = observe().await.unwrap();
        assert_eq!(links.get(lo).unwrap().name, name("lo"));
        let observed = links.get(tap.index()).unwrap();
        assert_eq!(observed.name, name("observe-tap"));
        assert_eq!(observed.admin_state, IfState::Down);

        let mac = SourceMac::try_from("02:0a:0b:0c:0d:0e").unwrap();
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(tap.index().to_u32())
                    .address(mac.inner().0.to_vec())
                    .up()
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        let links = observe().await.unwrap();
        let observed = links.get(tap.index()).unwrap();
        assert_eq!(observed.mac, Some(mac));
        assert_eq!(observed.admin_state, IfState::Up);

        handle
            .link()
            .set(
                LinkUnspec::new_with_index(tap.index().to_u32())
                    .down()
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        handle
            .link()
            .set(
                LinkUnspec::new_with_index(tap.index().to_u32())
                    .name("observe+tap".to_string())
                    .up()
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        let links = observe().await.unwrap();
        let observed = links
            .get(tap.index())
            .expect("a link renamed to a name the router cannot take is still observed");
        assert_eq!(observed.name, None);
        assert_eq!(observed.mac, Some(mac));
        assert_eq!(observed.admin_state, IfState::Up);
    }
}
