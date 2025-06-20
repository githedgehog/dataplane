// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use derive_builder::Builder;
use futures::TryStreamExt;
use multi_index_map::MultiIndexMap;
use net::interface::InterfaceIndex;
use net::udp::port::UdpPort;
use net::vxlan::Vni;
use rekon::Create;
use rtnetlink::packet_route::tc::{
    TcAction, TcActionAttribute, TcActionOption, TcActionTunnelKeyOption, TcTunnelKey,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Action {
    details: ActionDetails,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ActionDetails {
    Redirect(Redirect),
    DropFrame(DropFrame),
    VxlanEncap(VxlanEncap),
    VxlanDecap(VxlanDecap),
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub struct ActionIndex<T: ?Sized>(u64, PhantomData<T>);

#[derive(
    Builder,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[builder(derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Copy))]
pub struct Redirect {
    #[multi_index(hashed_unique)]
    index: ActionIndex<Redirect>,
    #[multi_index(ordered_non_unique)]
    to: InterfaceIndex,
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Builder)]
pub struct DropFrame {
    index: ActionIndex<DropFrame>,
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Builder)]
pub struct VxlanEncap {
    index: ActionIndex<VxlanEncap>,
    id: Vni,
    dstport: UdpPort,
    srcport: Option<UdpPort>,
    ttl: Option<u8>,
    tos: Option<u8>,
    checksum: bool,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Builder)]
pub struct VxlanDecap {
    index: ActionIndex<VxlanDecap>,
}

impl From<Redirect> for Action {
    fn from(action: Redirect) -> Self {
        Action {
            details: ActionDetails::Redirect(action),
        }
    }
}

impl Create for Manager<Action> {
    type Requirement<'a>
        = ()
    where
        Self: 'a;
    type Outcome<'a>
        = ()
    where
        Self: 'a;

    async fn create<'a>(&self, _requirement: Self::Requirement<'a>)
    where
        Self: 'a,
    {
        let add = self.handle.traffic_action().add();
        let mut act = TcAction::default();
        act.tab = 1;
        act.attributes
            .push(TcActionAttribute::Kind("tunnel_key".into()));
        let tunnel_key_params = TcTunnelKey {
            t_action: 1, // tunnel key set
            ..Default::default()
        };
        act.attributes.push(TcActionAttribute::Options(vec![
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncDstPort(4789)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::NoCsum(true)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncTtl(64)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncIpv4Dst(Ipv4Addr::new(
                169, 254, 32, 53,
            ))),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncKeyId(1)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncIpv4Src(Ipv4Addr::new(
                169, 254, 0, 2,
            ))),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(tunnel_key_params)),
        ]));
        let mut resp = add.action(act).execute();
        while let Ok(Some(r)) = resp.try_next().await {
            println!("{r:?}");
        }
    }
}
