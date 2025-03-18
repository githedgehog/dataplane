// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{ImpliedBridge, ObservedBridge};
use bitflags::bitflags;
use futures::channel::mpsc::UnboundedReceiver;
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

type Watch<T> = tokio::sync::watch::Receiver<T>;
type Notify<T> = tokio::sync::watch::Sender<T>;

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

pub struct NetlinkLinkMonitor {
    handle: Arc<Handle>,
    watch: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>,
}

impl NetlinkLinkMonitor {
    fn new() -> (Self, Connection<RouteNetlinkMessage>, Arc<Handle>) {
        let Ok((mut connection, handle, watch)) = new_connection() else {
            panic!("failed to create connection");
        };
        let subscribe_to = { NetlinkNotificationGroups::Link };
        let addr = SocketAddr::new(0, subscribe_to.bits());

        let mut sock = connection.socket_mut().socket_mut();
        sock.set_rx_buf_sz(212_992).unwrap();
        sock.bind(&addr).expect("failed to bind to netlink socket");

        let handle = Arc::new(handle);

        (
            Self {
                handle: handle.clone(),
                watch,
            },
            connection,
            handle,
        )
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

#[cfg(test)]
pub mod test {
    use crate::actor::{
        Actor, BridgeManager, BridgeMessage, NetlinkAgent, NetlinkAgentMessage,
        NetlinkNotificationGroups,
    };
    use crate::resource::{ImpliedBridge, ObservedBridgeBuilder};
    use futures::{StreamExt, TryStreamExt};
    use net::eth::ethtype::EthType;
    use rtnetlink::new_connection;
    use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo};
    use rtnetlink::sys::{AsyncSocket, SocketAddr};
    use std::rc::Rc;
    use std::sync::Arc;

    #[tokio::test(flavor = "current_thread")]
    async fn subscribe_and_save() {
        let Ok((mut connection, handle, mut recv)) = new_connection() else {
            panic!("failed to create connection");
        };
        let subscribe_to = { NetlinkNotificationGroups::Link };
        let addr = SocketAddr::new(0, subscribe_to.bits());

        let mut sock = connection.socket_mut().socket_mut();
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

    #[tokio::test(flavor = "current_thread")]
    async fn check_me() {
        let Ok((mut connection, handle, mut recv)) = new_connection() else {
            panic!("failed to create connection");
        };
        let subscribe_to = { NetlinkNotificationGroups::Link };
        let addr = SocketAddr::new(0, subscribe_to.bits());

        let mut sock = connection.socket_mut().socket_mut();
        sock.set_rx_buf_sz(212_992).unwrap();
        sock.bind(&addr).expect("failed to bind to netlink socket");

        tokio::spawn(connection);

        let handle = Arc::new(handle);
        let implied_bridge = Rc::new(ImpliedBridge {
            name: "potato".to_string().try_into().unwrap(),
            vlan_filtering: true,
            vlan_protocol: EthType::VLAN,
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        let mut bridge_actor = BridgeManager::new(handle.clone(), tx);
        let mut agent = NetlinkAgent {
            handle: handle.clone(),
        };
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                agent.process(message).await;
            }
        });
        let implication = BridgeMessage::ObjectiveUpdate(Some(implied_bridge.clone()));
        bridge_actor.process(implication).await;
        let mut resp = handle
            .link()
            .get()
            .match_name("potato".to_string())
            .execute();
        let Ok(Some(resp)) = resp.try_next().await else {
            let message = BridgeMessage::ObservationUpdate(None);
            bridge_actor.process(message).await;
            continue;
        };
        loop {
            let mut observation_builder = ObservedBridgeBuilder::default();
            observation_builder.if_index(resp.header.index.try_into().unwrap());
            for attr in &resp.attributes {
                match attr {
                    LinkAttribute::LinkInfo(infos) => {
                        for info in infos {
                            if let LinkInfo::Data(InfoData::Bridge(bridge_info)) = info {
                                for info in bridge_info {
                                    if let InfoBridge::VlanFiltering(filtering) = info {
                                        observation_builder.vlan_filtering(*filtering);
                                    }
                                    if let InfoBridge::VlanProtocol(raw) = info {
                                        observation_builder.vlan_protocol(EthType::from(*raw));
                                    }
                                }
                            }
                        }
                    }
                    LinkAttribute::IfName(name) => {
                        observation_builder.name(name.to_string().try_into().unwrap());
                    }
                    _ => {}
                }
            }
            let observed_bridge = Some(Rc::new(observation_builder.build().unwrap()));
            let message = BridgeMessage::ObservationUpdate(observed_bridge);
            bridge_actor.process(message).await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
