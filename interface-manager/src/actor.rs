// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{ImpliedBridge, ObservedBridge};
use bitflags::bitflags;
use net::eth::ethtype::EthType;
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::{Handle, LinkBridge};
use std::rc::Rc;
use tracing::info;

type Watch<T> = tokio::sync::watch::Receiver<T>;
type Notify<T> = tokio::sync::watch::Sender<T>;

pub trait Actor {
    type Message;
    type Error;
    async fn process(&mut self, message: &Self::Message) -> Result<(), Self::Error>;

    fn retired(&self) -> bool;
}

pub enum BridgeMessage {
    Remove,
    ObjectiveUpdate(Rc<ImpliedBridge>),
    ObservationUpdate(Option<Rc<ObservedBridge>>),
}

#[non_exhaustive]
pub struct BridgeActor {
    objective: Rc<ImpliedBridge>,
    observation: Option<Rc<ObservedBridge>>,
    handle: Rc<Handle>,
    retired: bool,
}

impl BridgeActor {
    fn new(handle: Rc<Handle>, objective: Rc<ImpliedBridge>) -> BridgeActor {
        BridgeActor {
            objective,
            observation: None,
            handle,
            retired: false,
        }
    }
}

impl ImpliedBridge {
    fn create_message(&self) -> LinkMessage {
        LinkBridge::new(self.name.as_ref())
            .append_extra_attribute(LinkAttribute::LinkInfo(vec![LinkInfo::Data(
                InfoData::Bridge(vec![
                    InfoBridge::VlanProtocol(self.vlan_protocol.unwrap_or(EthType::VLAN).raw()),
                    InfoBridge::VlanFiltering(self.vlan_protocol.is_some()),
                    InfoBridge::NfCallArpTables(0),
                    InfoBridge::NfCallIpTables(0),
                    InfoBridge::NfCallIp6Tables(0),
                ]),
            )]))
            .build()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("can not generate set message: no observed state")]
pub struct ObservationMissing;

impl BridgeActor {
    async fn reconcile(&self) -> Result<(), rtnetlink::Error> {
        match self.observation.clone() {
            None => {
                self.handle
                    .link()
                    .add(self.objective.create_message())
                    .execute()
                    .await
            }
            Some(observation) => {
                let current = observation.to_implied();
                if self.objective.as_ref() == &current {
                    return Ok(());
                }
                let mut update_message = LinkMessage::default();
                update_message.header.index = observation.if_index.to_u32();
                update_message.attributes = vec![
                    LinkAttribute::IfName(self.objective.name.to_string()),
                    LinkAttribute::LinkInfo(vec![LinkInfo::Data(InfoData::Bridge(vec![
                        InfoBridge::VlanFiltering(self.objective.vlan_protocol.is_some()),
                        InfoBridge::VlanProtocol(
                            self.objective.vlan_protocol.unwrap_or(EthType::VLAN).raw(),
                        ),
                        InfoBridge::NfCallIpTables(0),
                        InfoBridge::NfCallIp6Tables(0),
                        InfoBridge::NfCallArpTables(0),
                    ]))]),
                ];
                self.handle.link().set(update_message).execute().await
            }
        }
    }
}

impl Actor for BridgeActor {
    type Message = BridgeMessage;
    type Error = rtnetlink::Error;

    async fn process(&mut self, message: &Self::Message) -> Result<(), rtnetlink::Error> {
        match message {
            BridgeMessage::ObjectiveUpdate(implied) => {
                self.objective.clone_from(implied);
                self.reconcile().await
            }
            BridgeMessage::ObservationUpdate(observed) => {
                self.observation.clone_from(observed);
                self.reconcile().await
            }
            BridgeMessage::Remove => match self.observation.clone() {
                None => {
                    info!("converged on none, none for bridge: actor should close");
                    Ok(())
                }
                Some(observation) => {
                    let ret = self
                        .handle
                        .link()
                        .del(observation.if_index.to_u32())
                        .execute()
                        .await;
                    self.retired = true;
                    ret
                }
            },
        }
    }

    fn retired(&self) -> bool {
        self.retired
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
    use crate::actor::{Actor, BridgeActor, BridgeMessage, NetlinkNotificationGroups};
    use crate::resource::{ImpliedBridge, ObservedBridgeBuilder};
    use futures::{StreamExt, TryStreamExt};
    use net::eth::ethtype::EthType;
    use rtnetlink::new_connection;
    use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo};
    use rtnetlink::sys::{AsyncSocket, SocketAddr};
    use std::rc::Rc;

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
        let Ok((mut connection, handle, _recv)) = new_connection() else {
            panic!("failed to create connection");
        };
        connection
            .socket_mut()
            .socket_mut()
            .set_rx_buf_sz(212_992)
            .unwrap();

        tokio::spawn(connection);
        let handle = Rc::new(handle);
        let implied_bridge = Rc::new(ImpliedBridge {
            name: "potato".to_string().try_into().unwrap(),
            vlan_protocol: Some(EthType::VLAN),
        });
        let mut bridge_actor = BridgeActor::new(handle.clone(), implied_bridge);
        loop {
            let mut resp = handle
                .link()
                .get()
                .match_name("potato".to_string())
                .execute();
            let Ok(Some(resp)) = resp.try_next().await else {
                let message = BridgeMessage::ObservationUpdate(None);
                bridge_actor.process(&message).await.unwrap();
                continue;
            };
            let mut observation_builder = ObservedBridgeBuilder::default();
            observation_builder.if_index(resp.header.index.try_into().unwrap());
            for attr in &resp.attributes {
                match attr {
                    LinkAttribute::LinkInfo(infos) => {
                        for info in infos {
                            if let LinkInfo::Data(InfoData::Bridge(bridge_info)) = info {
                                for info in bridge_info {
                                    if let InfoBridge::VlanProtocol(raw) = info {
                                        observation_builder
                                            .vlan_protocol(Some(EthType::from(*raw)));
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
            bridge_actor.process(&message).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
