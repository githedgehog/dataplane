// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{
    ImpliedBridge, ImpliedInformationBase, ImpliedVrf, ImpliedVtep, NetworkDiscriminant,
    ObservedBridge, ObservedInformationBase, ObservedInterface, ObservedVrf, ObservedVtep,
    RouteTableId, Vpc,
};
use bitflags::bitflags;
use futures::channel::mpsc::UnboundedReceiver;
use futures::{StreamExt, TryStreamExt};
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    Handle, LinkAddRequest, LinkBridge, LinkDelRequest, LinkSetRequest, LinkVrf, LinkVxlan,
    new_connection,
};
use serde::{Deserialize, Serialize};
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, error, info, trace, warn};

type Watch<T> = tokio::sync::watch::Receiver<T>;
type Notify<T> = tokio::sync::watch::Sender<T>;
type Sender<T> = tokio::sync::mpsc::Sender<T>;
type Broadcaster<T> = tokio::sync::broadcast::Sender<T>;
type Broadcasted<T> = tokio::sync::broadcast::Receiver<T>;
type Receiver<T> = tokio::sync::mpsc::Receiver<T>;

type Message<T> = <T as Actor>::Message;

pub trait Actor {
    type Message;
    async fn process(&mut self, message: Self::Message);
}

pub enum BridgeMessage {
    ObjectiveUpdate(Option<Rc<ImpliedBridge>>),
    ObservationUpdate(Option<Rc<ObservedBridge>>),
}
pub enum VrfMessage {
    ObjectiveUpdate(Option<Rc<ImpliedVrf>>),
    ObservationUpdate(Option<Rc<ObservedVrf>>),
}

pub enum VtepMessage {
    ObjectiveUpdate(Option<Rc<ImpliedVtep>>),
    ObservationUpdate(Option<Rc<ObservedVtep>>),
}

#[allow(clippy::enum_variant_names)]
pub enum NetlinkAgentMessage {
    LinkAdd(LinkAddRequest),
    LinkDel(LinkDelRequest),
    LinkSet(LinkSetRequest),
}

impl From<LinkAddRequest> for NetlinkAgentMessage {
    fn from(value: LinkAddRequest) -> Self {
        NetlinkAgentMessage::LinkAdd(value)
    }
}

impl From<LinkDelRequest> for NetlinkAgentMessage {
    fn from(value: LinkDelRequest) -> Self {
        NetlinkAgentMessage::LinkDel(value)
    }
}

impl From<LinkSetRequest> for NetlinkAgentMessage {
    fn from(value: LinkSetRequest) -> Self {
        NetlinkAgentMessage::LinkSet(value)
    }
}

pub struct VtepManager {
    handle: Arc<Handle>,
    objective: Option<Rc<ImpliedVtep>>,
    observation: Option<Rc<ObservedVtep>>,
    agent: tokio::sync::mpsc::Sender<NetlinkAgentMessage>,
}

impl VtepManager {
    fn new(
        handle: Arc<Handle>,
        agent: tokio::sync::mpsc::Sender<NetlinkAgentMessage>,
    ) -> VtepManager {
        VtepManager {
            handle,
            agent,
            objective: None,
            observation: None,
        }
    }
}

pub struct VrfManager {
    handle: Arc<Handle>,
    objective: Option<Rc<ImpliedVrf>>,
    observation: Option<Rc<ObservedVrf>>,
    agent: tokio::sync::mpsc::Sender<NetlinkAgentMessage>,
}

impl VrfManager {
    fn new(
        handle: Arc<Handle>,
        agent: tokio::sync::mpsc::Sender<NetlinkAgentMessage>,
    ) -> VrfManager {
        VrfManager {
            handle,
            agent,
            objective: None,
            observation: None,
        }
    }
}

#[non_exhaustive]
pub struct BridgeManager {
    handle: Arc<Handle>,
    objective: Option<Rc<ImpliedBridge>>,
    observation: Option<Rc<ObservedBridge>>,
    agent: tokio::sync::mpsc::Sender<NetlinkAgentMessage>,
}

impl BridgeManager {
    fn new(
        handle: Arc<Handle>,
        agent: tokio::sync::mpsc::Sender<NetlinkAgentMessage>,
    ) -> BridgeManager {
        BridgeManager {
            handle,
            agent,
            objective: None,
            observation: None,
        }
    }
}

impl ImpliedBridge {
    fn create_message(&self) -> LinkMessage {
        let mut message = LinkBridge::new(self.name.as_ref()).build();
        for attr in &mut message.attributes {
            if let LinkAttribute::LinkInfo(infos) = attr {
                infos.push(LinkInfo::Data(InfoData::Bridge(vec![
                    InfoBridge::VlanFiltering(self.vlan_filtering),
                    InfoBridge::VlanProtocol(self.vlan_protocol.as_u16()),
                ])));
            }
        }
        message
    }
}

impl ImpliedVrf {
    fn create_message(&self) -> LinkMessage {
        LinkVrf::new(self.name.as_ref(), self.route_table.into()).build()
    }
}

impl ImpliedVtep {
    fn create_message(&self) -> LinkMessage {
        LinkVxlan::new(self.name.as_ref(), self.vni.as_u32())
            .local(self.local)
            .build()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("can not generate set message: no observed state")]
pub struct ObservationMissing;

impl BridgeManager {
    async fn reconcile(&self) {
        let message;
        match (&self.objective, &self.observation) {
            (None, None) => {
                return;
            }
            (Some(objective), None) => {
                message = self.handle.link().add(objective.create_message()).into();
            }
            (None, Some(observation)) => {
                message = self.handle.link().del(observation.index.to_u32()).into();
            }
            (Some(objective), Some(observation)) => {
                if *objective.as_ref() == observation.to_implied() {
                    return;
                }
                let mut link_message = objective.create_message();
                link_message.header.index = observation.index.to_u32();
                message = self.handle.link().add(link_message).replace().into();
            }
        }
        self.agent
            .send(message)
            .await
            .expect("netlink agent hung up");
    }
}

impl VrfManager {
    async fn reconcile(&self) {
        let message;
        match (&self.objective, &self.observation) {
            (None, None) => {
                return;
            }
            (Some(objective), None) => {
                message = self.handle.link().add(objective.create_message()).into();
            }
            (None, Some(observation)) => {
                message = self.handle.link().del(observation.index.to_u32()).into();
            }
            (Some(objective), Some(observation)) => {
                if *objective.as_ref() == observation.to_implied() {
                    return;
                }
                let mut link_message = objective.create_message();
                link_message.header.index = observation.index.to_u32();
                message = self.handle.link().add(link_message).replace().into();
            }
        }
        self.agent
            .send(message)
            .await
            .expect("netlink agent hung up");
    }
}

impl VtepManager {
    async fn reconcile(&self) {
        let message;
        match (&self.objective, &self.observation) {
            (None, None) => {
                return;
            }
            (Some(objective), None) => {
                message = self.handle.link().add(objective.create_message()).into();
            }
            (None, Some(observation)) => {
                message = self.handle.link().del(observation.index.to_u32()).into();
            }
            (Some(objective), Some(observation)) => {
                if *objective.as_ref() == observation.to_implied() {
                    return;
                }
                let mut link_message = objective.create_message();
                link_message.header.index = observation.index.to_u32();
                message = self.handle.link().add(link_message).replace().into();
            }
        }
        self.agent
            .send(message)
            .await
            .expect("netlink agent hung up");
    }
}

impl Actor for BridgeManager {
    type Message = BridgeMessage;

    async fn process(&mut self, message: Self::Message) {
        match message {
            BridgeMessage::ObjectiveUpdate(implied) => {
                self.objective = implied;
            }
            BridgeMessage::ObservationUpdate(observed) => {
                self.observation = observed;
            }
        }
        self.reconcile().await;
    }
}

impl Actor for VrfManager {
    type Message = VrfMessage;

    async fn process(&mut self, message: Self::Message) {
        match message {
            Self::Message::ObjectiveUpdate(implied) => {
                self.objective = implied;
            }
            Self::Message::ObservationUpdate(observed) => {
                self.observation = observed;
            }
        }
        self.reconcile().await;
    }
}

impl Actor for VtepManager {
    type Message = VtepMessage;

    async fn process(&mut self, message: Self::Message) {
        match message {
            Self::Message::ObjectiveUpdate(implied) => {
                self.objective = implied;
            }
            Self::Message::ObservationUpdate(observed) => {
                self.observation = observed;
            }
        }
        self.reconcile().await;
    }
}

pub struct NetlinkAgent {
    handle: Arc<Handle>,
}

impl Actor for NetlinkAgent {
    type Message = NetlinkAgentMessage;

    async fn process(&mut self, message: Self::Message) {
        match message {
            NetlinkAgentMessage::LinkAdd(request) => match request.execute().await {
                Ok(()) => {}
                Err(err) => {
                    eprintln!("err: {err}");
                }
            },
            NetlinkAgentMessage::LinkDel(request) => {
                request.execute().await.unwrap();
            }
            NetlinkAgentMessage::LinkSet(request) => {
                request.execute().await.unwrap();
            }
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
    #[non_exhaustive]
    pub struct NetlinkNotificationGroups: u32 {
        const Link = rtnetlink::constants::RTMGRP_LINK;
        const Notify = rtnetlink::constants::RTMGRP_NOTIFY;
        const Neighbor = rtnetlink::constants::RTMGRP_NEIGH;
        const Tc = rtnetlink::constants::RTMGRP_TC;
        const Ipv4Address = rtnetlink::constants::RTMGRP_IPV4_IFADDR;
        const Ipv4MRoute = rtnetlink::constants::RTMGRP_IPV4_MROUTE;
        const Ipv4Route = rtnetlink::constants::RTMGRP_IPV4_ROUTE;
        const Ipv4Rule = rtnetlink::constants::RTMGRP_IPV4_RULE;
        const Ipv6Address = rtnetlink::constants::RTMGRP_IPV6_IFADDR;
        const Ipv6MRoute = rtnetlink::constants::RTMGRP_IPV6_MROUTE;
        const Ipv6Route = rtnetlink::constants::RTMGRP_IPV6_ROUTE;
        const Ipv6IfInfo = rtnetlink::constants::RTMGRP_IPV6_IFINFO;
        const DecNetIfAddr = rtnetlink::constants::RTMGRP_DECNET_IFADDR;
        const DecNetRoute = rtnetlink::constants::RTMGRP_DECNET_ROUTE;
        const Ipv6Prefix = rtnetlink::constants::RTMGRP_IPV6_PREFIX;
        const _ = !0;
    }
}

#[derive(Debug)]
pub enum LinkMonitorMessage {
    Update(NetlinkMessage<RouteNetlinkMessage>),
    Refresh(Vec<LinkMessage>),
}

#[derive(Debug)]
pub struct LinkMonitor {
    handle: Arc<Handle>,
    recv: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>,
    queue: Sender<LinkMonitorMessage>,
}

impl LinkMonitor {
    /// The depth of the tx channel
    const QUEUE_DEPTH: usize = 1024;

    /// NOTE: this method requires an already spawned async context
    fn new() -> (Self, Receiver<LinkMonitorMessage>) {
        let (tx, rx) = tokio::sync::mpsc::channel(Self::QUEUE_DEPTH);
        let subscribe_to = { NetlinkNotificationGroups::Link | NetlinkNotificationGroups::all() };
        let addr = SocketAddr::new(0, subscribe_to.bits());
        let Ok((mut connection, handle, recv)) = new_connection() else {
            panic!("failed to create connection");
        };
        // this is the default max value on my machine.  Make this a proper const later.
        // sock.set_rx_buf_sz(212_992).unwrap();
        connection
            .socket_mut()
            .socket_mut()
            .set_rx_buf_sz(212_992)
            .unwrap();
        connection
            .socket_mut()
            .socket_mut()
            .set_non_blocking(true)
            .unwrap();
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(NetlinkNotificationGroups::Link.bits())
            .unwrap();
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(NetlinkNotificationGroups::Link.bits())
            .unwrap();
        connection
            .socket_mut()
            .socket_mut()
            .add_membership(NetlinkNotificationGroups::Notify.bits())
            .unwrap();
        connection
            .socket_mut()
            .socket_mut()
            .set_ext_ack(true)
            .unwrap();
        connection.socket_mut().socket_mut().bind(&addr).unwrap();
        tokio::spawn(connection);
        let this = Self {
            handle: Arc::new(handle),
            recv,
            queue: tx,
        };
        (this, rx)
    }

    async fn refresh(&self) {
        const MAX_CHUNK_SIZE: usize = 16 * LinkMonitor::QUEUE_DEPTH;
        let messages = self
            .handle
            .link()
            .get()
            .execute()
            .try_ready_chunks(MAX_CHUNK_SIZE)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<_>>();
        self.queue
            .send(LinkMonitorMessage::Refresh(messages))
            .await
            .expect("NetlinkMonitor message queue disconnected");
    }

    async fn check_for_updates(&mut self) {
        match self.recv.try_next() {
            Ok(Some((message, _))) => {
                match self.queue.try_send(LinkMonitorMessage::Update(message)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(message)) => {
                        warn!("NetlinkMonitor transmit queue full, triggering refresh");
                        self.queue
                            .send(message)
                            .await
                            .expect("NetlinkMonitor message queue disconnected");
                    }
                    Err(TrySendError::Closed(_)) => {
                        error!("NetlinkMonitor message queue disconnected");
                        panic!("NetlinkMonitor message queue disconnected");
                    }
                }
            }
            Err(_) => {
                trace!("consumed monitor backlog, refreshing system state");
                self.refresh().await;
                let Some((message, _)) = self.recv.next().await else {
                    info!("netlink monitor recv channel closed");
                    return;
                };
                match self.queue.try_send(LinkMonitorMessage::Update(message)) {
                    Ok(()) => {}
                    Err(TrySendError::Full(message)) => {
                        warn!("NetlinkMonitor transmit queue full");
                        self.queue
                            .send(message)
                            .await
                            .expect("NetlinkMonitor message queue disconnected");
                    }
                    Err(TrySendError::Closed(_)) => {
                        error!("NetlinkMonitor message queue disconnected");
                        panic!("NetlinkMonitor message queue disconnected");
                    }
                }
            }
            Ok(None) => {
                error!("netlink monitor recv channel closed");
            }
        }
    }

    #[tracing::instrument(level = "info")]
    async fn run(&mut self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
        loop {
            tokio::select! {
                instant = interval.tick() => {
                    trace!("refreshing link monitor at {instant:?}");
                    self.refresh().await;
                }
                () = self.check_for_updates() => { /* ok */ }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct AddVpc(pub RouteTableId, pub NetworkDiscriminant);

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub enum DelVpcBy {
    RouteTableId(RouteTableId),
}

pub enum ConfigurationUpdate {
    AddVpc(AddVpc),
    DelVpc(DelVpcBy),
}

pub struct ConfigurationMonitor {
    instruction: Receiver<ConfigurationUpdate>,
    information_base: Arc<ImpliedInformationBase>,
    queue: Notify<Arc<ImpliedInformationBase>>,
}

impl ConfigurationMonitor {
    fn new(
        channel: Receiver<ConfigurationUpdate>,
    ) -> (ConfigurationMonitor, Watch<Arc<ImpliedInformationBase>>) {
        let information_base = Arc::new(ImpliedInformationBase::default());
        let (queue, watch) = tokio::sync::watch::channel(information_base.clone());
        let this = ConfigurationMonitor {
            information_base,
            queue,
            instruction: channel,
        };
        (this, watch)
    }

    fn get_information_base(&self) -> Arc<ImpliedInformationBase> {
        self.information_base.clone()
    }

    async fn run(&mut self) {
        while let Some(update) = self.instruction.recv().await {
            match update {
                ConfigurationUpdate::AddVpc(AddVpc(route_table, discriminant)) => {
                    let vpc = Vpc::new(route_table, discriminant);
                    Arc::make_mut(&mut self.information_base).try_add_vpc(&vpc);
                    self.queue.send(self.information_base.clone()).unwrap();
                }
                ConfigurationUpdate::DelVpc(DelVpcBy::RouteTableId(id)) => {
                    Arc::make_mut(&mut self.information_base).try_remove_vpc_by_route_table_id(id);
                    self.queue.send(self.information_base.clone()).unwrap();
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum Update<T> {
    New(T),
    Del(T),
    Set(T),
}

#[derive(Debug, Clone)]
pub enum Observation {
    Update(Arc<Vec<Update<ObservedInterface>>>),
    Refresh(Arc<ObservedInformationBase>),
}

#[derive(Debug)]
pub struct ObservedLinks {
    monitor: Receiver<LinkMonitorMessage>,
    observed: Arc<ObservedInformationBase>,
    notify: Sender<Observation>,
    log: Arc<Vec<Update<ObservedInterface>>>,
}

impl ObservedLinks {
    fn new(channel: Receiver<LinkMonitorMessage>) -> (Self, Receiver<Observation>) {
        let observed = Arc::new(ObservedInformationBase::default());
        let (notify, watch) = tokio::sync::mpsc::channel(512);
        let this = Self {
            monitor: channel,
            observed,
            notify,
            log: Arc::new(Vec::with_capacity(128)),
        };
        (this, watch)
    }

    #[allow(clippy::too_many_lines)]
    async fn run(&mut self) {
        loop {
            let mut buffer = Vec::with_capacity(LinkMonitor::QUEUE_DEPTH);
            self.monitor
                .recv_many(&mut buffer, LinkMonitor::QUEUE_DEPTH)
                .await;
            for message in buffer {
                match message {
                    LinkMonitorMessage::Update(update) => {
                        let update = match update.payload {
                            NetlinkPayload::InnerMessage(x) => match x {
                                RouteNetlinkMessage::NewLink(link) => Update::New(link),
                                RouteNetlinkMessage::DelLink(link) => Update::Del(link),
                                RouteNetlinkMessage::SetLink(link) => Update::Set(link),
                                _ => continue,
                            },
                            NetlinkPayload::Done(done) => {
                                debug!("{done:?}");
                                continue;
                            }
                            NetlinkPayload::Error(e) => {
                                error!("{e:?}");
                                continue;
                            }
                            NetlinkPayload::Overrun(_) => {
                                warn!("netlink message overrun");
                                continue;
                            }
                            _ => {
                                continue;
                            }
                        };
                        match update {
                            Update::New(message) => {
                                let update = ObservedInterface::try_from(message);
                                match update {
                                    Ok(ObservedInterface::Vrf(vrf)) => {
                                        match Arc::make_mut(&mut self.observed).try_add_vrf(vrf) {
                                            Ok(vrf) => Arc::make_mut(&mut self.log).push(
                                                Update::New(ObservedInterface::Vrf(vrf.clone())),
                                            ),
                                            Err(err) => {
                                                error!("{err:?}");
                                            }
                                        }
                                    }
                                    Ok(ObservedInterface::Bridge(bridge)) => {
                                        match Arc::make_mut(&mut self.observed)
                                            .try_add_bridge(bridge)
                                        {
                                            Ok(bridge) => {
                                                Arc::make_mut(&mut self.log).push(Update::New(
                                                    ObservedInterface::Bridge(bridge.clone()),
                                                ));
                                            }
                                            Err(err) => {
                                                error!("{err:?}");
                                            }
                                        }
                                    }
                                    Ok(ObservedInterface::Vtep(vtep)) => {
                                        match Arc::make_mut(&mut self.observed).try_add_vtep(vtep) {
                                            Ok(vtep) => Arc::make_mut(&mut self.log).push(
                                                Update::New(ObservedInterface::Vtep(vtep.clone())),
                                            ),
                                            Err(err) => {
                                                error!("{err:?}");
                                            }
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                            Update::Del(message) => match ObservedInterface::try_from(message) {
                                Ok(ObservedInterface::Vrf(vrf)) => {
                                    match Arc::make_mut(&mut self.observed)
                                        .try_remove_vrf(vrf.index)
                                    {
                                        None => {
                                            debug!(
                                                "failed to remove vrf {vrf:?} from observation base: no such interface"
                                            );
                                        }
                                        Some(observed) => {
                                            debug!(
                                                "removed vrf {observed:?} from observation base"
                                            );
                                        }
                                    }
                                }
                                Ok(ObservedInterface::Bridge(bridge)) => {
                                    match Arc::make_mut(&mut self.observed)
                                        .try_remove_bridge(bridge.index)
                                    {
                                        None => {
                                            debug!(
                                                "failed to remove bridge {bridge:?} from observation base: no such interface"
                                            );
                                        }
                                        Some(observed) => {
                                            debug!(
                                                "removed bridge {observed:?} from observation base"
                                            );
                                        }
                                    }
                                }
                                Ok(ObservedInterface::Vtep(vtep)) => {
                                    match Arc::make_mut(&mut self.observed)
                                        .try_remove_vtep(vtep.index)
                                    {
                                        None => {
                                            debug!(
                                                "failed to remove btep {vtep:?} from observation base: no such interface"
                                            );
                                        }
                                        Some(observed) => {
                                            debug!(
                                                "removed vtep {observed:?} from observation base"
                                            );
                                        }
                                    }
                                }
                                Err(_) => {}
                            },
                            Update::Set(message) => {
                                warn!("not yet handled set message: {message:?}");
                            }
                        }
                    }
                    LinkMonitorMessage::Refresh(messages) => {
                        // TODO: this is much too basic of a refresh.
                        // We loose all out mutation info with this approach
                        let mut ib = Arc::new(ObservedInformationBase::default());
                        for message in messages {
                            if let Ok(interface) = ObservedInterface::try_from(message) {
                                match Arc::make_mut(&mut ib).try_add_interface(interface) {
                                    Ok(()) => {}
                                    Err(e) => {
                                        error!("failed to add observed interface: {e:?}");
                                    }
                                }
                            }
                        }
                        self.observed = ib;
                        self.notify
                            .send(Observation::Refresh(self.observed.clone()))
                            .await
                            .expect("channel closed");
                    }
                }
            }
            if !self.log.is_empty() {
                match self.notify.try_send(Observation::Update(self.log.clone())) {
                    Ok(()) => {}
                    Err(TrySendError::Full(log)) => match self.notify.send(log).await {
                        Ok(()) => {}
                        Err(e) => {
                            error!("failed to send message: {e:?}");
                            panic!("failed to send message: {e:?}");
                        }
                    },
                    Err(TrySendError::Closed(_)) => {
                        error!("channel closed");
                        panic!("channel closed");
                    }
                }
                self.log = Arc::new(Vec::with_capacity(128));
            }
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::actor::{
        AddVpc, ConfigurationMonitor, ConfigurationUpdate, DelVpcBy, LinkMonitor,
        LinkMonitorMessage, Observation, ObservedLinks,
    };
    use crate::resource::NetworkDiscriminant;
    use rtnetlink::LinkBridge;
    use std::io::Write;

    #[tokio::test(flavor = "current_thread")]
    async fn observed_links() {
        let mut log_file = std::fs::File::create("/tmp/observed_links.log").unwrap();
        let (mut monitor, rx) = LinkMonitor::new();
        let (mut observed_links, mut rx) = ObservedLinks::new(rx);
        tokio::spawn(async move { monitor.run().await });
        tokio::spawn(async move {
            loop {
                observed_links.run().await;
            }
        });
        while let Some(x) = rx.recv().await {
            match x {
                Observation::Update(update) => {
                    log_file
                        .write_all(format!("{update:?}\n").as_bytes())
                        .unwrap();
                }
                Observation::Refresh(_) => {
                    log_file.write_all("\nrefresh\n".as_bytes()).unwrap();
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_remove_vpc() {
        let mut log_file = std::fs::File::create("/tmp/vpc_monitor.yml").unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let (mut configuration_monitor, mut watch) = ConfigurationMonitor::new(rx);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            tx.send(ConfigurationUpdate::AddVpc(AddVpc(
                18.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 18.try_into().unwrap(),
                },
            )))
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            tx.send(ConfigurationUpdate::AddVpc(AddVpc(
                19.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 19.try_into().unwrap(),
                },
            )))
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            tx.send(ConfigurationUpdate::DelVpc(DelVpcBy::RouteTableId(
                18.into(),
            )))
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            tx.send(ConfigurationUpdate::AddVpc(AddVpc(
                29.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 29.try_into().unwrap(),
                },
            )))
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            tx.send(ConfigurationUpdate::AddVpc(AddVpc(
                39.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 99.try_into().unwrap(),
                },
            )))
            .await
            .unwrap();
            tx.send(ConfigurationUpdate::AddVpc(AddVpc(
                49.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 199.try_into().unwrap(),
                },
            )))
            .await
            .unwrap();
        });
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            configuration_monitor.run().await;
        });
        loop {
            {
                let config = watch.borrow_and_update();
                let status = serde_yml::to_string(&*config).unwrap();
                log_file.write_all("---\n".as_bytes()).unwrap();
                log_file.write_all(status.as_bytes()).unwrap();
            }
            watch.changed().await.unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn link_monitor() {
        let mut log_file = std::fs::File::create("/tmp/link_monitor.log").unwrap();
        let (monitor, mut recv) = LinkMonitor::new();
        let mut monitor = Box::new(monitor);
        let handle = monitor.handle.clone();
        let mut counter = 0;
        tokio::spawn(async move {
            loop {
                match recv.recv().await {
                    None => {
                        panic!("link monitor recv channel closed");
                    }
                    Some(message) => {
                        counter += 1;
                        match message {
                            LinkMonitorMessage::Update(_) => {
                                log_file
                                    .write_all(format!("{counter:>4}: update\n").as_bytes())
                                    .expect("unable to write to log file");
                            }
                            LinkMonitorMessage::Refresh(_) => {
                                log_file
                                    .write_all(format!("{counter:>4}: refresh\n").as_bytes())
                                    .expect("unable to write to log file");
                            }
                        }
                    }
                }
            }
        });
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            for i in 1..100 {
                handle
                    .link()
                    .add(LinkBridge::new(format!("potato{i}").as_ref()).build())
                    .execute()
                    .await
                    .unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        });
        monitor.run().await;
    }
}
