// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control channel for the router

use concurrency::sync::Arc;
use config::{GwConfigMeta, ValidatedGwConfig};
use mio::{Interest, Waker};
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Sender as AsyncSender;
use tokio::task;
#[allow(unused)]
use tracing::{debug, error, info, warn};

use crate::RouterError;
use crate::bmp::bmp_render::BgpNeighEvent;
use crate::config::RouterConfig;
use crate::frr::frrmi::FrrAppliedConfig;
use crate::interfaces::linkstate::LinkStates;
use crate::router::revent::{ROUTER_EVENTS, RouterEvent, revent};
use crate::router::rio::{CPSOCK, Rio};
use crate::routingdb::RoutingDb;

type RouterCtlReplyTx = AsyncSender<RouterCtlReply>;

#[derive(Debug)]
pub(crate) enum RouterCtlReply {
    Result(Result<(), RouterError>),
    FrrConfig(Option<FrrAppliedConfig>),
}

pub struct LockGuard {
    tx: Option<Sender<RouterCtlMsg>>,
    waker: Arc<Waker>,
}
impl Drop for LockGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let waker = Arc::clone(&self.waker);
            task::spawn(async move {
                if let Err(e) = tx.send(RouterCtlMsg::GuardedUnlock).await {
                    error!("Fatal: could not send unlock request!!: {e}");
                } else {
                    let _ = waker.wake();
                }
            });
        }
    }
}

pub(crate) enum RouterCtlMsg {
    Lock(RouterCtlReplyTx),
    Unlock(RouterCtlReplyTx),
    GuardedUnlock,
    Configure(RouterConfig, RouterCtlReplyTx),
    GetFrrAppliedConfig(RouterCtlReplyTx),
    Config(Arc<ValidatedGwConfig>),
    ConfigHistory(Arc<Vec<GwConfigMeta>>),
    LinkState(LinkStates),
    BgpNeighStatus(BgpNeighEvent),
}

/// Object to send control messages to the router
#[derive(Clone)]
pub struct RouterCtlSender {
    tx: tokio::sync::mpsc::Sender<RouterCtlMsg>,
    waker: Arc<Waker>,
}
impl RouterCtlSender {
    #[must_use]
    pub(crate) fn new(tx: Sender<RouterCtlMsg>, waker: Arc<Waker>) -> Self {
        Self { tx, waker }
    }

    #[must_use]
    pub(crate) fn as_lock_guard(&self) -> LockGuard {
        LockGuard {
            tx: Some(self.tx.clone()),
            waker: Arc::clone(&self.waker),
        }
    }
    async fn send_and_wake(&self, msg: RouterCtlMsg) -> Result<(), RouterError> {
        self.tx
            .send(msg)
            .await
            .map_err(|_| RouterError::Internal("Failed to send router ctl request"))?;

        // wake up poller
        self.waker
            .wake()
            .map_err(|_| RouterError::Internal("Failed to wake RIO"))?;
        Ok(())
    }

    pub async fn lock(&self) -> Result<LockGuard, RouterError> {
        debug!("Requesting CPI lock...");
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RouterCtlMsg::Lock(reply_tx);
        self.send_and_wake(msg).await?;
        let reply = reply_rx
            .await
            .map_err(|_| RouterError::Internal("Failed to receive lock reply"))?;

        let RouterCtlReply::Result(result) = reply else {
            unreachable!()
        };
        result?;
        Ok(self.as_lock_guard())
    }
    #[allow(unused)]
    pub async fn unlock(&self) -> Result<(), RouterError> {
        debug!("Requesting CPI unlock...");
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RouterCtlMsg::Unlock(reply_tx);
        self.send_and_wake(msg).await?;

        let reply = reply_rx
            .await
            .map_err(|_| RouterError::Internal("Failed to receive unlock reply"))?;
        let RouterCtlReply::Result(result) = reply else {
            unreachable!()
        };
        result
    }
    pub async fn configure(&self, config: RouterConfig) -> Result<(), RouterError> {
        let genid = config.genid();
        debug!("Requesting router to apply config for gen {genid}...");
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RouterCtlMsg::Configure(config, reply_tx);
        self.send_and_wake(msg).await?;

        let reply = reply_rx
            .await
            .map_err(|_| RouterError::Internal("Failed to receive configure reply"))?;

        let RouterCtlReply::Result(result) = reply else {
            unreachable!()
        };
        result
    }
    pub async fn get_frr_applied_config(&self) -> Result<Option<FrrAppliedConfig>, RouterError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let msg = RouterCtlMsg::GetFrrAppliedConfig(reply_tx);
        self.send_and_wake(msg).await?;

        let reply = reply_rx
            .await
            .map_err(|_| RouterError::Internal("Failed to receive reply for get FRR config"))?;
        let RouterCtlReply::FrrConfig(frr_cfg) = reply else {
            unreachable!()
        };
        Ok(frr_cfg)
    }
    pub async fn send_config(&self, config: Arc<ValidatedGwConfig>) -> Result<(), RouterError> {
        let msg = RouterCtlMsg::Config(config);
        self.send_and_wake(msg).await
    }
    pub async fn send_config_history(
        &self,
        history: Arc<Vec<GwConfigMeta>>,
    ) -> Result<(), RouterError> {
        let msg = RouterCtlMsg::ConfigHistory(history);
        self.send_and_wake(msg).await
    }
    /// Hand the router a complete observation of the kernel's links, replacing the last one.
    pub async fn send_link_state(&self, links: LinkStates) -> Result<(), RouterError> {
        let msg = RouterCtlMsg::LinkState(links);
        self.send_and_wake(msg).await
    }
    pub async fn send_bgp_neigh_change(&self, ev: BgpNeighEvent) -> Result<(), RouterError> {
        let msg = RouterCtlMsg::BgpNeighStatus(ev);
        self.send_and_wake(msg).await
    }
}

/// Handle a lock request for the indicated CPI
fn handle_lock(rio: &mut Rio, lock: bool, reply_to: Option<RouterCtlReplyTx>) {
    let action = if lock { "lock" } else { "unlock" };
    let interests = if lock {
        rio.frozen = true;
        Interest::WRITABLE
    } else {
        rio.frozen = false;
        Interest::WRITABLE | Interest::READABLE
    };
    let result = rio.reregister(CPSOCK, rio.cpi_sock.get_raw_fd(), interests);
    if result.is_ok() {
        debug!("The CPI is now {action}ed");
    } else {
        error!("Failed to {action} CPI");
    }

    if let Some(reply_to) = reply_to {
        if let Err(e) = reply_to.send(RouterCtlReply::Result(result)) {
            error!("Fatal: could not reply to lock/unlock request: {e:?}");
        }
    }
}

/// Handle a configure request. This function applies the configuration that
/// pertains to the router and that of FRR if provided.
fn handle_configure(
    rio: &mut Rio,
    config: RouterConfig,
    db: &mut RoutingDb,
    reply_to: RouterCtlReplyTx,
) {
    revent!(RouterEvent::GotConfigRequest(config.genid()));

    /* apply router config */
    let result = config.apply(db);
    if result.is_err() {
        revent!(RouterEvent::ConfigFailed(config.genid()));
        let _ = reply_to.send(RouterCtlReply::Result(result)).map_err(|e| {
            error!("Fatal: could not reply to configure request: {e:?}");
        });
        return;
    }

    /* request application of frr config. This is infallible */
    if let Some(frr_config) = config.get_frr_config() {
        rio.request_frr_config(config.genid(), frr_config.clone());
    }

    /* generate event: we successfully applied the router config and FRR's is on its way  */
    revent!(RouterEvent::ConfigSuceeded(config.genid()));

    /* reply */
    let _ = reply_to.send(RouterCtlReply::Result(result)).map_err(|e| {
        error!("Fatal: could not reply to configure request: {e:?}");
    });

    /* store the config */
    db.set_config(config);
}

/// Handle get applied FRR config
fn handle_get_frr_applied_config(rio: &Rio, reply_to: RouterCtlReplyTx) {
    let frr_cfg = rio.frrmi.get_applied_cfg();
    let _ = reply_to
        .send(RouterCtlReply::FrrConfig(frr_cfg.cloned()))
        .map_err(|e| {
            error!("Fatal: could not reply to get applied FRR config request: {e:?}");
        });
}

fn handle_config(rio: &mut Rio, config: Arc<ValidatedGwConfig>) {
    rio.gwconfig = Some(config);
}
fn handle_config_history(rio: &mut Rio, history: Arc<Vec<GwConfigMeta>>) {
    rio.cfg_history = history;
}

/// Take `links` as the router's view of the kernel's links, and bring the configured interfaces to
/// it.
///
/// The observation is kept whether or not there is a configuration yet: the first configuration
/// takes its link state from it, rather than from whatever the kernel showed when that
/// configuration was built.
fn handle_link_state(db: &mut RoutingDb, links: LinkStates) {
    revent!(RouterEvent::LinkStateObserved(links.len()));
    db.links = links;
    if let Some(config) = db.config.take() {
        if let Err(e) = config.apply_link_state(db) {
            warn!("Failed to apply link state: {e}");
        }
        db.config = Some(config);
    }
}

fn handle_bgp_peer_status_change(bgp_ev: BgpNeighEvent) {
    info!(
        "BGP session with {} (id:{} ASN:{}) changed {} -> {}",
        bgp_ev.peer_key, bgp_ev.peer_router_id, bgp_ev.peer_asn, bgp_ev.prev, bgp_ev.new
    );
    revent!(RouterEvent::BgpNeighStateChange(bgp_ev));
}

/// Handle requests from the control channel. Since the channel is integrated with the poll loop via a `Waker`
/// and the `Waker` coalesce multiple readiness events, we drain completely on each call with a loop.
pub(crate) fn handle_ctl_msg(rio: &mut Rio, db: &mut RoutingDb) {
    loop {
        match rio.ctl_rx.try_recv() {
            Ok(RouterCtlMsg::Lock(reply_to)) => handle_lock(rio, true, Some(reply_to)),
            Ok(RouterCtlMsg::Unlock(reply_to)) => handle_lock(rio, false, Some(reply_to)),
            Ok(RouterCtlMsg::GuardedUnlock) => handle_lock(rio, false, None),
            Ok(RouterCtlMsg::Configure(config, reply_to)) => {
                handle_configure(rio, config, db, reply_to);
            }
            Ok(RouterCtlMsg::GetFrrAppliedConfig(reply_to)) => {
                handle_get_frr_applied_config(rio, reply_to);
            }
            Ok(RouterCtlMsg::Config(config)) => handle_config(rio, config),
            Ok(RouterCtlMsg::ConfigHistory(history)) => handle_config_history(rio, history),
            Ok(RouterCtlMsg::LinkState(links)) => handle_link_state(db, links),
            Ok(RouterCtlMsg::BgpNeighStatus(bgp_ev)) => handle_bgp_peer_status_change(bgp_ev),
            Err(TryRecvError::Empty) => break,
            Err(e) => {
                error!("Error receiving from ctl channel {e:?}");
                break;
            }
        }
    }
}

#[cfg(test)]
/// The router's interfaces must end up with the link state of the latest observation, whatever
/// order observations and configurations arrive in.
mod link_state {
    use super::handle_link_state;
    use crate::config::RouterConfig;
    use crate::config::tests::{build_router_config, create_routing_database};
    use crate::interfaces::interface::IfState;
    use crate::interfaces::linkstate::{LinkState, LinkStates};
    use crate::routingdb::RoutingDb;
    use interface_manager::interface::TryFromLinkMessage;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::{Interface, InterfaceIndex, InterfaceName, Mtu};
    use rtnetlink::packet_route::link::State;
    use rtnetlink::packet_route::link::{
        InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
    };

    /// Ethernet interfaces of `build_router_config`, and an index it does not configure.
    const CONFIGURED: [u32; 2] = [10, 11];
    const UNCONFIGURED: u32 = 99;

    fn ifindex(raw: u32) -> InterfaceIndex {
        InterfaceIndex::try_new(raw).unwrap()
    }

    /// What `handle_configure` does to the routing database.
    fn configure(db: &mut RoutingDb) {
        let config = build_router_config();
        config.apply(db).unwrap();
        db.set_config(config);
    }

    fn interface(db: &RoutingDb, ifindex: InterfaceIndex) -> crate::Interface {
        let iftable = db.iftw.enter().unwrap();
        iftable.get_interface(ifindex).unwrap().clone()
    }

    /// The link state the kernel would report for a configured interface, with `mac`.
    fn link(config: &RouterConfig, raw: u32, mac: SourceMac) -> LinkState {
        let ifindex = ifindex(raw);
        LinkState {
            ifindex,
            name: config.get_interface(ifindex).unwrap().name.clone(),
            mac: Some(mac),
            mtu: None,
            admin_state: IfState::Up,
            oper_state: IfState::Up,
        }
    }

    /// githedgehog/fabricator#2268: the driver gave a tap its port's MAC after the first
    /// configuration had read the tap's random one, and before the router had that configuration.
    #[test]
    fn a_link_state_observed_before_the_first_config_replaces_the_one_it_was_built_with() {
        let mut db = create_routing_database();
        let config = build_router_config();
        let port = ifindex(CONFIGURED[1]);
        let stale = config
            .get_interface(port)
            .unwrap()
            .iftype
            .get_mac()
            .unwrap();
        let real = SourceMac::try_from("0c:20:12:fe:01:02").unwrap();
        assert_ne!(stale, real);

        handle_link_state(
            &mut db,
            LinkStates::from_iter([link(&config, CONFIGURED[1], real)]),
        );
        configure(&mut db);

        assert_eq!(interface(&db, port).get_mac(), Some(real));
    }

    /// The same, the other way around: the observation comes after the configuration.
    #[test]
    fn a_link_state_observed_after_the_config_replaces_the_one_it_was_built_with() {
        let mut db = create_routing_database();
        let config = build_router_config();
        let port = ifindex(CONFIGURED[1]);
        let real = SourceMac::try_from("0c:20:12:fe:01:02").unwrap();

        configure(&mut db);
        handle_link_state(
            &mut db,
            LinkStates::from_iter([link(&config, CONFIGURED[1], real)]),
        );

        assert_eq!(interface(&db, port).get_mac(), Some(real));
    }

    /// One generated link: which interface, whether it is up, its MAC, and which MTU if any.
    type GenLink = (u8, bool, [u8; 6], u8);

    fn generated_link(config: &RouterConfig, &(which, up, raw, mtu): &GenLink) -> LinkState {
        let raw_ifindex = match which % 3 {
            0 => CONFIGURED[0],
            1 => CONFIGURED[1],
            _ => UNCONFIGURED,
        };
        let mut raw = raw;
        raw[0] = (raw[0] & 0xfc) | 0x02;
        let ifindex = ifindex(raw_ifindex);
        let name = config.get_interface(ifindex).map_or_else(
            || InterfaceName::try_from("unconfigured").unwrap(),
            |ifconfig| ifconfig.name.clone(),
        );
        LinkState {
            ifindex,
            name,
            mac: Some(SourceMac::new(Mac::from(raw)).unwrap()),
            mtu: match mtu % 3 {
                0 => None,
                1 => Some(Mtu::try_from(1500u32).unwrap()),
                _ => Some(Mtu::try_from(9100u32).unwrap()),
            },
            admin_state: IfState::from(up),
            oper_state: IfState::from(up),
        }
    }

    #[test]
    fn the_latest_observation_wins_wherever_the_configs_fall() {
        bolero::check!()
            .with_type::<(Vec<Vec<GenLink>>, u8, u8)>()
            .for_each(|(observations, first, second)| {
                let config = build_router_config();
                let observations: Vec<LinkStates> = observations
                    .iter()
                    .map(|links| links.iter().map(|l| generated_link(&config, l)).collect())
                    .collect();
                let at_first = usize::from(*first) % (observations.len() + 1);
                let at_second = at_first.max(usize::from(*second) % (observations.len() + 1));

                let mut db = create_routing_database();
                for (i, links) in observations.iter().enumerate() {
                    if i == at_first {
                        configure(&mut db);
                    }
                    if i == at_second {
                        configure(&mut db);
                    }
                    handle_link_state(&mut db, links.clone());
                }
                if at_first == observations.len() {
                    configure(&mut db);
                }
                if at_second == observations.len() {
                    configure(&mut db);
                }

                // an interface the latest observation leaves out has its configuration's state
                let latest = observations.last().cloned().unwrap_or_default();
                for raw in CONFIGURED {
                    let port = ifindex(raw);
                    let configured = config.get_interface(port).unwrap();
                    let got = interface(&db, port);
                    let (mac, mtu, admin) = match latest.get(port) {
                        Some(link) => (link.mac, link.mtu.or(configured.mtu), link.admin_state),
                        None => (
                            configured.iftype.get_mac(),
                            configured.mtu,
                            configured.admin_state,
                        ),
                    };
                    assert_eq!(got.get_mac(), mac, "mac of ifindex {port}");
                    assert_eq!(got.mtu, mtu, "mtu of ifindex {port}");
                    assert_eq!(got.admin_state, admin, "admin state of ifindex {port}");
                    if let Some(link) = latest.get(port) {
                        assert_eq!(got.oper_state, link.oper_state, "oper state of {port}");
                    }
                }
            });
    }

    /// A `RTM_NEWLINK` for a tap, as the kernel sends it.
    fn tap_message(
        ifindex: InterfaceIndex,
        name: &str,
        flags: LinkFlags,
        oper_state: State,
        mac: &str,
    ) -> LinkMessage {
        let mut message = LinkMessage::default();
        message.header.index = ifindex.to_u32();
        message.header.flags = flags;
        message.attributes = vec![
            LinkAttribute::IfName(name.to_string()),
            LinkAttribute::OperState(oper_state),
            LinkAttribute::Address(Mac::try_from(mac).unwrap().as_ref().to_vec()),
            LinkAttribute::Mtu(9100),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Tun)]),
        ];
        message
    }

    /// Link messages, parsed as the link state observer parses them, land in the interface table.
    #[test]
    fn a_parsed_link_message_reaches_the_interface_table() {
        let mut db = create_routing_database();
        configure(&mut db);
        let port = ifindex(CONFIGURED[0]);

        // (flags, oper state, name, mac) -> (admin, oper)
        let cases = [
            (
                LinkFlags::Up | LinkFlags::Running,
                State::Up,
                "Eth0",
                "02:0a:0b:0c:0d:01",
                IfState::Up,
                IfState::Up,
            ),
            (
                LinkFlags::empty(),
                State::Down,
                "Eth0",
                "02:0a:0b:0c:0d:02",
                IfState::Down,
                IfState::Down,
            ),
            (
                LinkFlags::Up,
                State::Dormant,
                "mod-Eth0",
                "02:0a:0b:0c:0d:03",
                IfState::Up,
                IfState::Down,
            ),
            (
                LinkFlags::Up,
                State::Unknown,
                "mod-Eth0",
                "02:0a:0b:0c:0d:04",
                IfState::Up,
                IfState::Unknown,
            ),
        ];
        for (flags, oper, name, mac, admin_state, oper_state) in cases {
            let message = tap_message(port, name, flags, oper, mac);
            let parsed = Interface::try_from_link_message(&message).unwrap();
            handle_link_state(&mut db, LinkStates::from_iter([LinkState::from(&parsed)]));

            let got = interface(&db, port);
            assert_eq!(got.name.as_ref(), name);
            assert_eq!(got.get_mac(), Some(SourceMac::try_from(mac).unwrap()));
            assert_eq!(got.mtu, Some(Mtu::try_from(9100u32).unwrap()));
            assert_eq!(got.admin_state, admin_state, "{flags:?} {oper:?}");
            assert_eq!(got.oper_state, oper_state, "{flags:?} {oper:?}");
        }
    }
}
