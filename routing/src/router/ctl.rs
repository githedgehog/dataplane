// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control channel for the router

use concurrency::sync::Arc;
use config::{GwConfigMeta, ValidatedGwConfig};
use interface_manager::monitor::EthEvent;
use mio::{Interest, Waker};
use rtnetlink::packet_route::link::State;
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
use crate::interfaces::iftablerw::IfTableWriter;
use crate::interfaces::interface::IfState;
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
    IfEvent(EthEvent),
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
    pub async fn send_ifevent(&self, ev: EthEvent) -> Result<(), RouterError> {
        let msg = RouterCtlMsg::IfEvent(ev);
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
    let result = apply_config(&config, db);
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

/// Apply `config` to the routing database, and the latest link state to the interfaces it names.
fn apply_config(config: &RouterConfig, db: &mut RoutingDb) -> Result<(), RouterError> {
    config.apply(db)?;
    // after `apply`, not in it: `apply` verifies the result against `config`, and the link state
    // can differ from what `config` says
    replay_link_events(config, db);
    Ok(())
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

fn determine_oper_state(ev: &EthEvent) -> IfState {
    match ev.oper_state() {
        Some(State::Up) => IfState::Up,
        Some(State::Down | State::LowerLayerDown | State::Dormant | State::NotPresent) => {
            IfState::Down
        }
        Some(_) | None => {
            // kernel oper state may not always be reported (None case)
            // and the other states don't actually tell us. So, fallback
            // to the ifrunning flag. We don't consider iflowerup flag nor carrier here.
            IfState::from(ev.ifrunning())
        }
    }
}
pub(crate) fn handle_ifevent(ev: &EthEvent, iftw: &mut IfTableWriter) -> Result<(), RouterError> {
    let ifindex = ev.ifindex();

    // register event
    revent!(RouterEvent::IfEvent(ev.clone()));

    // determine reported oper and admin state
    let adm_state = IfState::from(ev.ifup());
    let oper_state = determine_oper_state(ev);

    // did admin state change ?
    let update = iftw.set_iface_admin_state(ifindex, adm_state)?;
    if let Some(state) = update.adm_state {
        revent!(RouterEvent::IfAdmChange(update.ifname, state));
    }

    // did oper state change ?
    let update = iftw.set_iface_oper_state(ifindex, oper_state)?;
    if let Some(state) = update.oper_state {
        revent!(RouterEvent::IfOperChange(update.ifname, state));
    }

    // did interface name change?
    if let Some(ifname) = ev.name() {
        let update = iftw.update_name(ifindex, ifname)?;
        if let Some(name) = update.name_change {
            revent!(RouterEvent::IfNameChange(update.ifname, name));
        }
    }

    // did mac change ?
    if let Some(mac) = ev.mac() {
        let update = iftw.update_mac(ifindex, mac)?;
        if let Some(mac) = update.mac {
            revent!(RouterEvent::IfMacChange(update.ifname, mac));
        }
    }
    Ok(())
}

/// Handle a link event from the interface monitor.
///
/// The event is remembered even when no interface is configured with its index, so that
/// [`replay_link_events`] can apply it once a configuration adds one.
fn handle_link_event(db: &mut RoutingDb, ev: &EthEvent) {
    debug!("Got interface event: {ev}");
    db.link_events.record(ev);

    let ifconfig = db
        .config
        .as_ref()
        .and_then(|c| c.get_interface(ev.ifindex()));
    if let Some(config) = ifconfig {
        debug!("Ifindex matches configured interface {}", config.name);
        if let Err(e) = handle_ifevent(ev, &mut db.iftw) {
            warn!("Failed to process event {ev}: {e}");
        }
    } else {
        debug!(
            "No interface is configured with ifindex {}; keeping the event until one is",
            ev.ifindex()
        );
    }
}

/// Bring the interfaces in `config`, just applied, to the link state the kernel last reported.
///
/// A configuration describes each interface as the kernel showed it when the configuration was
/// built. A link event may have been newer than that, and dropped because the interface was not
/// configured yet; without this, the interface keeps the stale state until the next configuration.
/// Re-applying an event that is older than the configuration is harmless: whatever changed since
/// produced an event of its own, which the router handles after this.
fn replay_link_events(config: &RouterConfig, db: &mut RoutingDb) {
    for ev in db.link_events.configured_in(config) {
        debug!(
            "Applying the last link event for ifindex {}: {ev}",
            ev.ifindex()
        );
        if let Err(e) = handle_ifevent(ev, &mut db.iftw) {
            warn!("Failed to apply the last link event {ev}: {e}");
        }
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
            Ok(RouterCtlMsg::IfEvent(ev)) => handle_link_event(db, &ev),
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
/// The router must end up with the link state the kernel reported last, whether the report came
/// before or after the configuration that names the interface.
mod link_event_replay {
    use super::{apply_config, handle_link_event};
    use crate::config::tests::{build_router_config, create_routing_database};
    use crate::interfaces::interface::IfState;
    use crate::routingdb::RoutingDb;
    use interface_manager::monitor::EthEvent;
    use net::eth::mac::{Mac, SourceMac};
    use net::interface::InterfaceIndex;
    use std::collections::HashMap;

    /// Ethernet interfaces of `build_router_config`, and an index it does not configure.
    const CONFIGURED: [u32; 2] = [10, 11];
    const UNCONFIGURED: u32 = 99;

    fn ifindex(raw: u32) -> InterfaceIndex {
        InterfaceIndex::try_new(raw).unwrap()
    }

    /// A unicast, locally administered MAC from arbitrary bytes.
    fn mac(mut raw: [u8; 6]) -> SourceMac {
        raw[0] = (raw[0] & 0xfc) | 0x02;
        SourceMac::new(Mac::from(raw)).unwrap()
    }

    fn link_event(ifindex: InterfaceIndex, up: bool, mac: SourceMac) -> EthEvent {
        EthEvent::new(ifindex, up, up, up).set_mac(Some(mac))
    }

    /// What `handle_configure` does to the routing database.
    fn configure(db: &mut RoutingDb) {
        let config = build_router_config();
        apply_config(&config, db).unwrap();
        db.set_config(config);
    }

    fn mac_of(db: &RoutingDb, ifindex: InterfaceIndex) -> SourceMac {
        let iftable = db.iftw.enter().unwrap();
        iftable.get_interface(ifindex).unwrap().get_mac().unwrap()
    }

    fn admin_state_of(db: &RoutingDb, ifindex: InterfaceIndex) -> IfState {
        let iftable = db.iftw.enter().unwrap();
        iftable.get_interface(ifindex).unwrap().admin_state
    }

    /// githedgehog/fabricator#2268: the driver gave a tap its port's MAC after the first
    /// configuration had read the tap's random one, and before the router had that configuration.
    #[test]
    fn a_mac_reported_before_the_first_config_replaces_the_one_it_was_built_with() {
        let mut db = create_routing_database();
        let port = ifindex(CONFIGURED[1]);
        let stale = build_router_config()
            .get_interface(port)
            .unwrap()
            .iftype
            .get_mac()
            .unwrap();
        let real = SourceMac::try_from("0c:20:12:fe:01:02").unwrap();
        assert_ne!(stale, real);

        handle_link_event(&mut db, &link_event(port, true, real));
        configure(&mut db);

        assert_eq!(mac_of(&db, port), real);
    }

    #[test]
    fn the_last_reported_link_state_wins_wherever_the_configs_fall() {
        bolero::check!()
            .with_type::<(Vec<(u8, bool, [u8; 6])>, u8, u8)>()
            .for_each(|(events, first, second)| {
                let at_first = usize::from(*first) % (events.len() + 1);
                let at_second = at_first.max(usize::from(*second) % (events.len() + 1));
                let events: Vec<EthEvent> = events
                    .iter()
                    .map(|&(which, up, raw)| {
                        let raw_ifindex = match which % 3 {
                            0 => CONFIGURED[0],
                            1 => CONFIGURED[1],
                            _ => UNCONFIGURED,
                        };
                        link_event(ifindex(raw_ifindex), up, mac(raw))
                    })
                    .collect();

                // the router hears every event, with a configuration arriving between any two of
                // them; the second one is built from the same stale view as the first
                let mut db = create_routing_database();
                for (i, event) in events.iter().enumerate() {
                    if i == at_first {
                        configure(&mut db);
                    }
                    if i == at_second {
                        configure(&mut db);
                    }
                    handle_link_event(&mut db, event);
                }
                if at_first == events.len() {
                    configure(&mut db);
                }
                if at_second == events.len() {
                    configure(&mut db);
                }

                let last: HashMap<InterfaceIndex, &EthEvent> =
                    events.iter().map(|ev| (ev.ifindex(), ev)).collect();
                let config = build_router_config();
                for raw in CONFIGURED {
                    let port = ifindex(raw);
                    let configured = config.get_interface(port).unwrap();
                    let (want_mac, want_admin) = match last.get(&port) {
                        Some(ev) => (ev.mac().unwrap(), IfState::from(ev.ifup())),
                        None => (configured.iftype.get_mac().unwrap(), configured.admin_state),
                    };
                    assert_eq!(mac_of(&db, port), want_mac, "mac of ifindex {port}");
                    assert_eq!(
                        admin_state_of(&db, port),
                        want_admin,
                        "admin of ifindex {port}"
                    );
                }
            });
    }
}
