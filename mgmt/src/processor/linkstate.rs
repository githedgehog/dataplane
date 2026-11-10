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
use futures::TryStreamExt;
use net::eth::mac::SourceMac;
use net::interface::{
    IllegalInterfaceName, InterfaceIndex, InterfaceIndexError, InterfaceName, Mtu,
};
use routing::{IfState, LinkState, LinkStates, RouterCtlSender};
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage, State};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tracing::{debug, error, warn};

/// How long to wait before observing again after an observation failed.
const RETRY: Duration = Duration::from_millis(100);

/// Why a link was left out of an observation.
///
/// Leaving such a link out loses nothing: a router configuration cannot name an interface without
/// a valid index and name (an [`InterfaceName`] is stricter than the kernel's names).
#[derive(Debug, thiserror::Error)]
enum NotObserved {
    #[error("invalid interface index: {0}")]
    Index(#[from] InterfaceIndexError),
    #[error("no name")]
    NoName,
    #[error("invalid name: {0:?}")]
    Name(#[from] IllegalInterfaceName),
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
/// observed as no MAC; the router only takes a MAC for interface types that have one anyway.
fn link_state(message: &LinkMessage) -> Result<LinkState, NotObserved> {
    let ifindex = InterfaceIndex::try_new(message.header.index)?;
    let mut name = None;
    let mut mac = None;
    let mut mtu = None;
    let mut kernel_oper_state = None;
    for attribute in &message.attributes {
        match attribute {
            LinkAttribute::IfName(raw) => name = Some(InterfaceName::try_from(raw.as_str())?),
            LinkAttribute::Address(raw) => mac = SourceMac::try_from(raw).ok(),
            LinkAttribute::Mtu(raw) => mtu = Mtu::try_from(*raw).ok(),
            LinkAttribute::OperState(state) => kernel_oper_state = Some(*state),
            _ => {}
        }
    }
    let flags = message.header.flags;
    Ok(LinkState {
        ifindex,
        name: name.ok_or(NotObserved::NoName)?,
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

/// Observe all of the kernel's links.
async fn observe(handle: &rtnetlink::Handle) -> Result<LinkStates, rtnetlink::Error> {
    let mut messages = handle.link().get().execute();
    let mut links = vec![];
    while let Some(message) = messages.try_next().await? {
        match link_state(&message) {
            Ok(link) => links.push(link),
            Err(e) => debug!("Not observing link {}: {e}", message.header.index),
        }
    }
    Ok(links.into_iter().collect())
}

/// Hand the router a fresh observation of the kernel's links whenever they change.
pub(crate) async fn sync_link_state(monitor: Arc<InterfaceMonitor>, router: RouterCtlSender) {
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(connection) => connection,
        Err(e) => {
            error!("Failed to open a netlink connection to observe links: {e}");
            return;
        }
    };
    tokio::spawn(connection);

    // Watch first, then look: a change after the monitor is listening is a cue for another
    // observation, and the first observation is taken after that, so it covers every change
    // before.
    let mut changes = monitor.subscribe();
    monitor.wait_ready().await;
    loop {
        match observe(&handle).await {
            Ok(links) => {
                debug!("Observed the state of {} links", links.len());
                if router.send_link_state(links).await.is_err() {
                    warn!("Failed to hand the router the state of the links");
                }
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
    use super::{NotObserved, link_state};
    use interface_manager::interface::TryFromLinkMessage;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::{Interface, InterfaceIndex, InterfaceName, Mtu};
    use routing::{IfState, LinkState};
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
                    name: InterfaceName::try_from("Eth0").unwrap(),
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
    fn a_link_without_a_valid_index_or_name_is_not_observed() {
        let name = || LinkAttribute::IfName("Eth0".to_string());
        assert!(matches!(
            link_state(&message(0, LinkFlags::Up, vec![name()])),
            Err(NotObserved::Index(_))
        ));
        assert!(matches!(
            link_state(&message(10, LinkFlags::Up, vec![])),
            Err(NotObserved::NoName)
        ));
        assert!(matches!(
            link_state(&message(
                10,
                LinkFlags::Up,
                vec![LinkAttribute::IfName("eth0:1".to_string())]
            )),
            Err(NotObserved::Name(_))
        ));
    }
}
