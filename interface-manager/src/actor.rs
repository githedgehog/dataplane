// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{ImpliedBridge, ObservedBridge, ObservedInformationBase};
use bitflags::bitflags;
use futures::channel::mpsc::{TryRecvError, UnboundedReceiver};
use futures::{StreamExt, TryStreamExt};
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::proto::Connection;
use rtnetlink::sys::{AsyncSocket, SocketAddr};
use rtnetlink::{
    Handle, LinkAddRequest, LinkBridge, LinkDelRequest, LinkSetRequest, new_connection,
};
use std::rc::Rc;
use std::sync::Arc;
use std::thread::JoinHandle;
use tokio::sync::mpsc::error::{SendError, TrySendError};
use tracing::{error, info, span, trace, warn};

type Watch<T> = tokio::sync::watch::Receiver<T>;
type Notify<T> = tokio::sync::watch::Sender<T>;
type Sender<T> = tokio::sync::mpsc::Sender<T>;
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

#[non_exhaustive]
pub struct BridgeManager2 {
    handle: Arc<Handle>,
    objective: Option<Rc<ImpliedBridge>>,
    observation: Option<Rc<ObservedBridge>>,
    agent: tokio::sync::mpsc::Sender<NetlinkAgentMessage>,
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
                    InfoBridge::NfCallArpTables(0),
                    InfoBridge::NfCallIpTables(0),
                    InfoBridge::NfCallIp6Tables(0),
                ])));
            }
        }
        message
        // LinkBridge::new(self.name.as_ref())
        //     .append_extra_attribute(LinkAttribute::LinkInfo(vec![
        //         LinkInfo::Kind(InfoKind::Bridge),
        //         LinkInfo::Data(InfoData::Bridge(vec![
        //             InfoBridge::VlanFiltering(self.vlan_protocol.is_some()),
        //             InfoBridge::VlanProtocol(self.vlan_protocol.unwrap_or(EthType::VLAN).raw()),
        //             InfoBridge::NfCallArpTables(0),
        //             InfoBridge::NfCallIpTables(0),
        //             InfoBridge::NfCallIp6Tables(0),
        //         ])),
        //     ]))
        //     .build()
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
                message = self.handle.link().del(observation.if_index.to_u32()).into();
            }
            (Some(objective), Some(observation)) => {
                if *objective.as_ref() == observation.to_implied() {
                    return;
                }
                let mut link_message = objective.create_message();
                link_message.header.index = observation.if_index.to_u32();
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
        let Ok((mut connection, handle, recv)) = new_connection() else {
            panic!("failed to create connection");
        };
        let subscribe_to = { NetlinkNotificationGroups::Link | NetlinkNotificationGroups::Notify };
        let addr = SocketAddr::new(0, subscribe_to.bits());

        let sock = connection.socket_mut().socket_mut();
        // this is the default max value on my machine.  Make this a proper const later.
        sock.set_rx_buf_sz(212_992).unwrap();
        sock.bind(&addr).expect("failed to bind to netlink socket");
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
                        self.refresh().await;
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
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
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

#[cfg(test)]
pub mod test {
    use crate::actor::{LinkMonitor, LinkMonitorMessage, NetlinkNotificationGroups};
    use futures::StreamExt;
    use rtnetlink::sys::{AsyncSocket, SocketAddr};
    use rtnetlink::{LinkBridge, new_connection};
    use std::io::Write;
    use std::rc::Rc;

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
                            LinkMonitorMessage::Update(update) => {
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
            for i in 1..1000 {
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

    #[tokio::test(flavor = "current_thread")]
    async fn subscribe_and_save() {
        let Ok((mut connection, handle, mut recv)) = new_connection() else {
            panic!("failed to create connection");
        };
        let subscribe_to = { NetlinkNotificationGroups::Link };
        let addr = SocketAddr::new(0, subscribe_to.bits());

        let sock = connection.socket_mut().socket_mut();
        sock.set_rx_buf_sz(212_992).unwrap();
        sock.bind(&addr).expect("failed to bind to netlink socket");

        tokio::spawn(connection);
        let handle = Rc::new(handle);

        let mut counter = 0;

        loop {
            println!("looping");
            match recv.next().await {
                None => {}
                Some((message, sock)) => {
                    println!("{message:?}");
                    counter += 1;
                }
            }

            if counter >= 3 {
                break;
            }
        }
    }

    // #[tokio::test(flavor = "current_thread")]
    // async fn check_me() {
    //     let Ok((mut connection, handle, mut recv)) = new_connection() else {
    //         panic!("failed to create connection");
    //     };
    //     let subscribe_to = { NetlinkNotificationGroups::Link };
    //     let addr = SocketAddr::new(0, subscribe_to.bits());
    //
    //     let mut sock = connection.socket_mut().socket_mut();
    //     sock.set_rx_buf_sz(212_992).unwrap();
    //     sock.bind(&addr).expect("failed to bind to netlink socket");
    //
    //     tokio::spawn(connection);
    //
    //     let handle = Arc::new(handle);
    //     let implied_bridge = Rc::new(ImpliedBridge {
    //         name: "potato".to_string().try_into().unwrap(),
    //         vlan_filtering: true,
    //         vlan_protocol: EthType::VLAN,
    //     });
    //     let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    //     let mut bridge_actor = BridgeManager::new(handle.clone(), tx);
    //     let mut agent = NetlinkAgent {
    //         handle: handle.clone(),
    //     };
    //     tokio::spawn(async move {
    //         while let Some(message) = rx.recv().await {
    //             agent.process(message).await;
    //         }
    //     });
    //     let implication = BridgeMessage::ObjectiveUpdate(Some(implied_bridge.clone()));
    //     bridge_actor.process(implication).await;
    //     let mut resp = handle
    //         .link()
    //         .get()
    //         .match_name("potato".to_string())
    //         .execute();
    //     let Ok(Some(resp)) = resp.try_next().await else {
    //         let message = BridgeMessage::ObservationUpdate(None);
    //         bridge_actor.process(message).await;
    //     };
    //     loop {
    //         let mut observation_builder = ObservedBridgeBuilder::default();
    //         observation_builder.if_index(resp.header.index.try_into().unwrap());
    //         for attr in &resp.attributes {
    //             match attr {
    //                 LinkAttribute::LinkInfo(infos) => {
    //                     for info in infos {
    //                         if let LinkInfo::Data(InfoData::Bridge(bridge_info)) = info {
    //                             for info in bridge_info {
    //                                 if let InfoBridge::VlanFiltering(filtering) = info {
    //                                     observation_builder.vlan_filtering(*filtering);
    //                                 }
    //                                 if let InfoBridge::VlanProtocol(raw) = info {
    //                                     observation_builder.vlan_protocol(EthType::from(*raw));
    //                                 }
    //                             }
    //                         }
    //                     }
    //                 }
    //                 LinkAttribute::IfName(name) => {
    //                     observation_builder.name(name.to_string().try_into().unwrap());
    //                 }
    //                 _ => {}
    //             }
    //         }
    //         let observed_bridge = Some(Rc::new(observation_builder.build().unwrap()));
    //         let message = BridgeMessage::ObservationUpdate(observed_bridge);
    //         bridge_actor.process(message).await;
    //         tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    //     }
    // }
}
