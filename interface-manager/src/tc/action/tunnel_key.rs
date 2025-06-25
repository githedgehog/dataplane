// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use crate::tc::action::{ActionIndex, ActionKind};
use derive_builder::Builder;
use futures::TryStreamExt;
use multi_index_map::MultiIndexMap;
use net::ipv4::UnicastIpv4Addr;
use net::udp::port::UdpPort;
use net::vxlan::Vni;
use net::vxlan::Vxlan;
use rekon::{AsRequirement, Create, Observe, Reconcile, Remove, Update};
use rtnetlink::packet_route::tc::{
    TcAction, TcActionAttribute, TcActionGeneric, TcActionMessageAttribute, TcActionOption,
    TcActionTunnelKeyOption, TcActionType, TcTunnelKey,
};
use std::fmt::{Debug, Display, Formatter};
use tracing::{trace, warn};

/// An observed `tunnel_key` action.
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Builder, MultiIndexMap)]
#[multi_index_derive(Clone, Debug)]
pub struct TunnelKey {
    #[multi_index(ordered_unique)]
    pub index: ActionIndex<TunnelKey>,
    pub details: TunnelKeyDetails,
}

impl PartialOrd for TunnelKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TunnelKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

impl ActionKind for TunnelKey {
    const KIND: &'static str = "tunnel_key";
}

/// The specification for a `tunnel_key` action.
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Builder, MultiIndexMap)]
#[builder(derive(Debug, PartialEq, Eq, Hash, Copy))]
#[multi_index_derive(Clone, Debug)]
pub struct TunnelKeySpec {
    pub index: ActionIndex<TunnelKey>,
    pub details: TunnelKeyDetails,
}

/// The details of a `tunnel_key` action.
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone)]
pub enum TunnelKeyDetails {
    /// Encap
    Set(TunnelKeySet),
    /// Decap
    Unset,
}

#[derive(PartialEq, Eq, Hash, Copy, Clone)]
pub enum TunnelChecksum {
    Compute,
    Zero,
}

impl Display for TunnelChecksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelChecksum::Compute => write!(f, "compute"),
            TunnelChecksum::Zero => write!(f, "zero"),
        }
    }
}

impl Debug for TunnelChecksum {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// The details of a `tunnel_key` set action.
#[derive(Debug, PartialEq, Eq, Hash, Copy, Clone, Builder)]
#[builder(setter(into))]
pub struct TunnelKeySet {
    pub src: UnicastIpv4Addr,
    pub dst: UnicastIpv4Addr, // we can't currently support multicast due to linux limitations
    pub id: Vni,
    #[builder(default = Vxlan::PORT)]
    pub dst_port: UdpPort,
    #[builder(default)]
    pub checksum: Option<TunnelChecksum>,
    #[builder(default)]
    pub ttl: Option<u8>,
    #[builder(default)]
    pub tos: Option<u8>,
}

impl From<TunnelKeySpec> for TcAction {
    fn from(value: TunnelKeySpec) -> TcAction {
        let mut act = TcAction::default();
        act.tab = 1;
        act.attributes
            .push(TcActionAttribute::Kind(TunnelKey::KIND.to_string()));
        let mut tunnel_key_params = TcTunnelKey {
            generic: {
                let mut gact = TcActionGeneric::default();
                gact.index = value.index.into();
                // if we leave refcnt at 0, the kernel will auto clean up our action
                gact.refcnt = 1;
                gact.action = TcActionType::Pipe;
                gact
            },
            t_action: 0, // need to set to encap or decap in the next step
        };
        let options = match value.details {
            TunnelKeyDetails::Set(encap) => {
                tunnel_key_params.t_action = 1; // tunnel key set (encap)
                let mut tunnel_key_options = vec![
                    TcActionTunnelKeyOption::Parms(tunnel_key_params),
                    TcActionTunnelKeyOption::EncKeyId(encap.id.as_u32()),
                    TcActionTunnelKeyOption::EncIpv4Src(encap.src.into()),
                    TcActionTunnelKeyOption::EncIpv4Dst(encap.dst.into()),
                    TcActionTunnelKeyOption::EncDstPort(encap.dst_port.into()),
                ];
                if let Some(tos) = encap.tos {
                    tunnel_key_options.push(TcActionTunnelKeyOption::EncTos(tos));
                }
                if let Some(ttl) = encap.ttl {
                    tunnel_key_options.push(TcActionTunnelKeyOption::EncTtl(ttl));
                }
                match encap.checksum {
                    None => {}
                    Some(TunnelChecksum::Compute) => {
                        tunnel_key_options.push(TcActionTunnelKeyOption::NoCsum(false));
                    }
                    Some(TunnelChecksum::Zero) => {
                        tunnel_key_options.push(TcActionTunnelKeyOption::NoCsum(true));
                    }
                }
                tunnel_key_options
            }
            TunnelKeyDetails::Unset => {
                tunnel_key_params.t_action = 2; // tunnel key unset (decap)
                vec![TcActionTunnelKeyOption::Parms(tunnel_key_params)]
            }
        };
        let opts = options.into_iter().map(TcActionOption::TunnelKey).collect();
        act.attributes.push(TcActionAttribute::Options(opts));
        act
    }
}

impl Create for Manager<TunnelKey> {
    type Requirement<'a>
        = &'a TunnelKeySpec
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn create<'a>(&self, requirement: Self::Requirement<'a>) -> Self::Outcome<'a> {
        let mut resp = self
            .handle
            .traffic_action()
            .add()
            .action(TcAction::from(*requirement))
            .execute();
        loop {
            let message = resp.try_next().await;
            match message {
                Ok(Some(netlink_message)) => {
                    trace!("created action: {netlink_message:#?}");
                }
                Ok(None) => {
                    break;
                }
                Err(err) => {
                    warn!("failed to create action: {err:#?}");
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

impl Remove for Manager<TunnelKey> {
    type Observation<'a>
        = ActionIndex<TunnelKey>
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn remove<'a>(&self, observation: Self::Observation<'a>) -> Self::Outcome<'a> {
        let mut act = TcAction::default();
        act.tab = 1;
        act.attributes = vec![
            TcActionAttribute::Kind("tunnel_key".into()),
            TcActionAttribute::Index(observation.into()),
        ];
        self.handle
            .traffic_action()
            .del()
            .action(act)
            .execute()
            .await
    }
}

impl Update for Manager<TunnelKey> {
    type Requirement<'a>
        = &'a TunnelKeySpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a TunnelKey
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a> {
        // TODO: this is quite crude and will obscure stats and disrupt service.
        // It is possible to update actions in-place under some circumstances and we should explore
        // that.
        self.remove(observation.index).await?;
        self.create(requirement).await
    }
}

impl Observe for Manager<TunnelKey> {
    type Observation<'a>
        = Vec<TunnelKey>
    where
        Self: 'a;

    async fn observe<'a>(&self) -> Self::Observation<'a> {
        let mut resp = self
            .handle
            .traffic_action()
            .get()
            .kind("tunnel_key")
            .execute();
        let mut ret = vec![];
        while let Ok(Some(r)) = resp.try_next().await {
            for attr in &r.attributes {
                if let TcActionMessageAttribute::Actions(actions) = attr {
                    ret.extend(
                        actions
                            .iter()
                            .filter_map(helper::try_tunnel_key_from_tc_action),
                    );
                }
            }
        }
        ret
    }
}

impl AsRequirement<TunnelKeySpec> for TunnelKey {
    type Requirement<'a>
        = TunnelKeySpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a,
    {
        TunnelKeySpec {
            index: self.index,
            details: self.details,
        }
    }
}

impl AsRequirement<MultiIndexTunnelKeySpecMap> for MultiIndexTunnelKeyMap {
    type Requirement<'a>
        = MultiIndexTunnelKeySpecMap
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        let mut ret = MultiIndexTunnelKeySpecMap::default();
        for (_, spec) in self.iter() {
            ret.insert(spec.as_requirement());
        }
        ret
    }
}

impl Reconcile for Manager<TunnelKey> {
    type Requirement<'a>
        = Option<&'a TunnelKeySpec>
    where
        Self: 'a;
    type Observation<'a>
        = Option<&'a TunnelKey>
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn reconcile<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        match (requirement, observation) {
            (Some(requirement), Some(observation)) => {
                if observation.as_requirement() == *requirement {
                    return Ok(());
                }
                self.update(requirement, observation).await
            }
            (None, Some(observation)) => self.remove(observation.index).await,
            (Some(requirement), None) => self.create(requirement).await,
            (None, None) => Ok(()),
        }
    }
}

mod helper {
    use crate::tc::action::tunnel_key::{
        TunnelChecksum, TunnelKey, TunnelKeyBuilder, TunnelKeyDetails, TunnelKeySetBuilder,
    };
    use crate::tc::action::{ActionIndex, ActionKind};
    use net::ipv4::UnicastIpv4Addr;
    use net::udp::port::UdpPort;
    use net::vxlan::Vni;
    use rtnetlink::packet_route::tc::{
        TcAction, TcActionAttribute, TcActionOption, TcActionTunnelKeyOption,
    };
    use tracing::{debug, trace, warn};

    pub(super) fn try_tunnel_key_from_tc_action(action: &TcAction) -> Option<TunnelKey> {
        let mut tunnel_key = TunnelKeyBuilder::create_empty();
        let mut set_builder = TunnelKeySetBuilder::create_empty();
        let mut is_correct_kind = false;
        for attr in &action.attributes {
            match attr {
                TcActionAttribute::Kind(kind) => {
                    if kind == TunnelKey::KIND {
                        is_correct_kind = true;
                    } else {
                        return None;
                    }
                }
                TcActionAttribute::Options(options) => {
                    match try_tunnel_key_set_from_tc_action_options_vec(&mut set_builder, options) {
                        Some(index) => {
                            tunnel_key.index(index);
                        }
                        None => {
                            return None;
                        }
                    }
                }
                TcActionAttribute::Index(index) => {
                    let index = match ActionIndex::<TunnelKey>::try_new(*index) {
                        Ok(index) => index,
                        Err(err) => {
                            warn!("failed to parse action index: {err:#?}");
                            continue;
                        }
                    };
                    tunnel_key.index(index);
                }
                _ => {}
            }
        }
        if !is_correct_kind {
            debug!("action {action:#?} is not a tunnel key");
            return None;
        }
        if let Ok(set) = set_builder.build() {
            tunnel_key.details(TunnelKeyDetails::Set(set));
        } else {
            tunnel_key.details(TunnelKeyDetails::Unset);
        }
        match tunnel_key.build() {
            Ok(spec) => Some(spec),
            Err(err) => {
                debug!("failed to build tunnel key: {err:#?}");
                None
            }
        }
    }

    fn try_tunnel_key_set_from_tc_action_options_vec(
        builder: &mut TunnelKeySetBuilder,
        options: &Vec<TcActionOption>,
    ) -> Option<ActionIndex<TunnelKey>> {
        let mut index: Option<ActionIndex<TunnelKey>> = None;
        for option in options {
            if let TcActionOption::TunnelKey(option) = option {
                match option {
                    TcActionTunnelKeyOption::Tm(_stats) => {}
                    TcActionTunnelKeyOption::Parms(params) => {
                        if params.t_action != 1 && params.t_action != 2 {
                            trace!("tunnel key set action is not encap or decap");
                            return None;
                        }
                        match ActionIndex::<TunnelKey>::try_new(params.generic.index) {
                            Ok(idx) => {
                                index = Some(idx);
                            }
                            Err(err) => {
                                warn!("failed to parse action index: {err:#?}");
                                return None;
                            }
                        }
                    }
                    TcActionTunnelKeyOption::EncIpv4Src(ip) => {
                        match UnicastIpv4Addr::try_from(*ip) {
                            Ok(ip) => {
                                builder.src(ip);
                            }
                            Err(err) => {
                                warn!("tunnel key ipv4 src is not unicast: {err:#?}");
                            }
                        }
                    }
                    TcActionTunnelKeyOption::EncIpv4Dst(ip) => {
                        match UnicastIpv4Addr::try_from(*ip) {
                            Ok(ip) => {
                                builder.dst(ip);
                            }
                            Err(err) => {
                                warn!("tunnel key ipv4 dst is not unicast: {err:#?}");
                            }
                        }
                    }
                    TcActionTunnelKeyOption::EncIpv6Src(ip) => {
                        warn!("ipv6 is not currently supported for tunnels: {ip} found");
                    }
                    TcActionTunnelKeyOption::EncIpv6Dst(ip) => {
                        warn!("ipv6 is not currently supported for tunnels: {ip} found");
                    }
                    TcActionTunnelKeyOption::EncKeyId(key) => match Vni::try_from(*key) {
                        Ok(vni) => {
                            builder.id(vni);
                        }
                        Err(err) => {
                            warn!("tunnel key key id is not a vni: {err:#?}");
                        }
                    },
                    TcActionTunnelKeyOption::EncDstPort(port) => {
                        match UdpPort::new_checked(*port) {
                            Ok(port) => {
                                builder.dst_port(port);
                            }
                            Err(err) => {
                                warn!("tunnel key dst port is not a valid port: {err:#?}");
                            }
                        }
                    }
                    TcActionTunnelKeyOption::EncTos(tos) => {
                        builder.tos(*tos);
                    }
                    TcActionTunnelKeyOption::EncTtl(ttl) => {
                        builder.ttl(*ttl);
                    }
                    TcActionTunnelKeyOption::NoCsum(no_csum) => {
                        builder.checksum(if *no_csum {
                            TunnelChecksum::Zero
                        } else {
                            TunnelChecksum::Compute
                        });
                    }
                    other => {
                        trace!("unknown tunnel key option: {other:#?}");
                    }
                }
            }
        }
        index
    }
}
