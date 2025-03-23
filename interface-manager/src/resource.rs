#![allow(clippy::ref_option)] // generated code :shrug:
#![allow(clippy::unsafe_derive_deserialize)] // trusting multi index map but could use a review

use crate::message::MessageContains;
use crate::reconcile::ScheduledConstraintAction;
use crate::{InterfaceIndex, InterfaceName};
use derive_builder::Builder;
use futures::StreamExt;
use futures::TryStreamExt;
use futures::future::join_all;
use id::Id;
use multi_index_map::{MultiIndexMap, UniquenessError};
use net::eth::ethtype::EthType;
use net::vxlan::Vni;
use rtnetlink::packet_route::link::{
    InfoBridge, InfoData, InfoKind, InfoVrf, InfoVxlan, LinkAttribute, LinkFlags, LinkInfo,
    LinkMessage, State,
};
use rtnetlink::{Handle, LinkBridge, LinkVrf};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{debug, error, info};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(from = "u32", into = "u32")]
#[repr(transparent)]
pub struct RouteTableId(u32);

impl Debug for RouteTableId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl From<u32> for RouteTableId {
    fn from(value: u32) -> Self {
        RouteTableId(value)
    }
}

impl From<RouteTableId> for u32 {
    fn from(value: RouteTableId) -> Self {
        value.0
    }
}

impl Display for RouteTableId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum NetworkDiscriminant {
    EvpnVxlan { vni: Vni },
}

#[derive(
    Builder,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Vpc {
    #[multi_index(hashed_unique)]
    id: Id<Vpc>,
    #[multi_index(ordered_unique)]
    route_table: RouteTableId,
    #[multi_index(ordered_unique)]
    discriminant: NetworkDiscriminant,
}

impl Vpc {
    pub fn new(route_table: RouteTableId, discriminant: NetworkDiscriminant) -> Self {
        Self {
            id: Id::new(),
            route_table,
            discriminant,
        }
    }
}

#[derive(
    Builder,
    Clone,
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
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredVrf {
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    #[multi_index(ordered_unique)]
    pub route_table: RouteTableId,
}

impl RequiredVrf {
    fn from_vpc(vpc: &Vpc) -> RequiredVrf {
        let name = InterfaceName::try_from(format!("vrf{}", vpc.route_table)).unwrap();
        RequiredVrf {
            route_table: vpc.route_table,
            name,
        }
    }
}

#[derive(Builder, Clone, Debug, Eq, MultiIndexMap, PartialEq, Serialize, Deserialize)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservedVrf {
    #[builder(private)]
    #[multi_index(ordered_unique)]
    pub name: InterfaceName,
    #[builder(private)]
    #[multi_index(ordered_non_unique)]
    pub route_table: RouteTableId,
    #[builder(private)]
    #[multi_index(ordered_unique)]
    pub index: InterfaceIndex, // TODO: make private
}

impl PartialEq<ObservedVrf> for RequiredVrf {
    fn eq(&self, other: &ObservedVrf) -> bool {
        self.name == other.name && self.route_table == other.route_table
    }
}

impl PartialEq<MultiIndexObservedVrfMap> for MultiIndexRequiredVrfMap {
    fn eq(&self, other: &MultiIndexObservedVrfMap) -> bool {
        if self.iter().len() != other.iter().len() {
            return false;
        }
        for (_, observed) in other.iter() {
            let Some(vtep) = self.get_by_name(&observed.name) else {
                return false;
            };
            if vtep != &observed.to_implied() {
                return false;
            }
        }
        true
    }
}

#[derive(
    Builder,
    Clone,
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
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredVtep {
    #[multi_index(ordered_unique)]
    pub name: InterfaceName,
    #[multi_index(ordered_unique)]
    pub vni: Vni,
    pub local: Ipv4Addr,
}

impl RequiredVtep {
    fn from_vpc(vpc: &Vpc) -> RequiredVtep {
        let name = InterfaceName::try_from(format!("vtep{}", vpc.route_table)).unwrap();
        let NetworkDiscriminant::EvpnVxlan { vni } = vpc.discriminant;
        RequiredVtep {
            name,
            vni,
            // TODO: needs real ip
            local: Ipv4Addr::new(169, 254, 0, 1),
        }
    }
}

#[derive(
    Builder,
    Clone,
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
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservedVtep {
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    #[multi_index(ordered_unique)]
    pub index: InterfaceIndex,
    #[multi_index(ordered_unique)]
    pub vni: Vni,
    pub local: Ipv4Addr,
    pub ttl: u8,
}

impl PartialEq<ObservedVtep> for RequiredVtep {
    fn eq(&self, other: &ObservedVtep) -> bool {
        self.vni == other.vni && self.local == other.local && self.name == other.name
    }
}

impl PartialEq<MultiIndexObservedVtepMap> for MultiIndexRequiredVtepMap {
    fn eq(&self, other: &MultiIndexObservedVtepMap) -> bool {
        if self.iter().len() != other.iter().len() {
            return false;
        }
        for (_, observed) in other.iter() {
            let Some(vrf) = self.get_by_name(&observed.name) else {
                return false;
            };
            if vrf != &observed.to_requirement() {
                return false;
            }
        }
        true
    }
}

#[derive(
    Builder,
    Clone,
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
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredBridge {
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    pub vlan_filtering: bool,
    pub vlan_protocol: EthType,
}

impl RequiredBridge {
    fn from_vpc(vpc: &Vpc) -> RequiredBridge {
        let name = InterfaceName::try_from(format!("br{}", vpc.route_table)).unwrap();
        RequiredBridge {
            name,
            vlan_protocol: EthType::VLAN,
            vlan_filtering: false,
        }
    }
}

#[derive(
    Builder,
    Clone,
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
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservedBridge {
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    pub vlan_filtering: bool,
    pub vlan_protocol: EthType,
    #[multi_index(hashed_unique)]
    pub index: InterfaceIndex,
    pub controller: Option<InterfaceIndex>,
}

impl PartialEq<ObservedBridge> for RequiredBridge {
    fn eq(&self, other: &ObservedBridge) -> bool {
        self.name == other.name
            && self.vlan_filtering == other.vlan_filtering
            && self.vlan_protocol == other.vlan_protocol
    }
}

impl PartialEq<MultiIndexObservedBridgeMap> for MultiIndexRequiredBridgeMap {
    fn eq(&self, other: &MultiIndexObservedBridgeMap) -> bool {
        if self.iter().len() != other.iter().len() {
            return false;
        }
        for (_, observed) in other.iter() {
            let Some(bridge) = self.get_by_name(&observed.name) else {
                return false;
            };
            if bridge != &observed.to_implied() {
                return false;
            }
        }
        true
    }
}

#[derive(
    Builder,
    Clone,
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
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredVtepBridgeMembership {
    #[multi_index(hashed_unique)]
    bridge: InterfaceName,
    #[multi_index(hashed_unique)]
    vtep: InterfaceName,
}

#[derive(
    Builder,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredVrfMembership {
    #[multi_index(hashed_unique)]
    vrf: InterfaceName,
    #[multi_index(hashed_unique)]
    member: InterfaceName,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RequiredInformationBase {
    pub(crate) vrfs: MultiIndexRequiredVrfMap,
    pub(crate) bridges: MultiIndexRequiredBridgeMap,
    pub(crate) vteps: MultiIndexRequiredVtepMap,
    pub(crate) constraints: RequiredConstraints,
}

impl RequiredInformationBase {
    // TODO: proper error handling
    pub fn try_add_vpc(&mut self, vpc: &Vpc) {
        let vrf = RequiredVrf::from_vpc(vpc);
        let bridge = RequiredBridge::from_vpc(vpc);
        let vtep = RequiredVtep::from_vpc(vpc);
        let constraints = [
            RequiredInterfaceAssociation {
                name: vrf.name.clone(),
                controller_name: None,
                admin_state: AdminState::Up,
            },
            RequiredInterfaceAssociation {
                name: bridge.name.clone(),
                controller_name: Some(vrf.name.clone()),
                admin_state: AdminState::Up,
            },
            RequiredInterfaceAssociation {
                name: vtep.name.clone(),
                controller_name: Some(bridge.name.clone()),
                admin_state: AdminState::Up,
            },
        ];
        self.vrfs.try_insert(vrf).unwrap();
        self.bridges.try_insert(bridge).unwrap();
        self.vteps.try_insert(vtep).unwrap();
        for constraint in constraints {
            self.constraints.interface.try_insert(constraint).unwrap();
        }
    }

    pub fn try_remove_vpc_by_route_table_id(&mut self, route_table_id: RouteTableId) {
        let vrf = self.vrfs.remove_by_route_table(&route_table_id).unwrap();
        for bridge in self
            .constraints
            .interface
            .remove_by_controller_name(&Some(vrf.name))
        {
            for vtep in self
                .constraints
                .interface
                .remove_by_controller_name(&Some(bridge.name))
            {
                self.vteps.remove_by_name(&vtep.name).unwrap();
            }
        }
    }
}

// Kept for constraint tracking
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct RequiredConstraints {
    /* names which we expect to exist or have observed mapped to their controller (if any) */
    pub interface: MultiIndexRequiredInterfaceAssociationMap,
}

#[derive(
    Builder,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredInterfaceAssociation {
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    #[multi_index(ordered_non_unique)]
    pub controller_name: Option<InterfaceName>,
    pub admin_state: AdminState,
}

#[derive(
    Builder,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlannedInterfaceConstraint {
    #[multi_index(ordered_unique)]
    pub name: InterfaceName,
    #[multi_index(ordered_non_unique)]
    pub controller_name: Option<InterfaceName>,
    #[multi_index(hashed_unique)]
    pub index: InterfaceIndex,
    #[multi_index(ordered_non_unique)]
    pub controller_index: Option<InterfaceIndex>,
    pub admin_state: AdminState,
    pub scheduled_action: ScheduledConstraintAction,
}

#[derive(
    Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Default, Serialize, Deserialize,
)]
pub enum AdminState {
    #[default]
    Down,
    Up,
}

#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub enum OperationalState {
    Down,
    Up,
    Unknown,
}

#[derive(
    Builder,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservedInterfaceAssociation {
    #[multi_index(ordered_unique)]
    pub name: InterfaceName,
    #[multi_index(ordered_non_unique)]
    pub controller_name: Option<InterfaceName>,
    #[multi_index(hashed_unique)]
    pub index: InterfaceIndex,
    #[multi_index(ordered_non_unique)]
    pub controller_index: Option<InterfaceIndex>,
    pub admin_state: AdminState,
    pub operational_state: OperationalState,
}

impl ObservedInterfaceAssociation {
    pub fn to_implied(&self) -> RequiredInterfaceAssociation {
        RequiredInterfaceAssociation {
            name: self.name.clone(),
            controller_name: self.controller_name.clone(),
            admin_state: self.admin_state,
        }
    }
}

impl PartialEq<ObservedInterfaceAssociation> for PlannedInterfaceConstraint {
    fn eq(&self, other: &ObservedInterfaceAssociation) -> bool {
        self.name == other.name
            && self.controller_name == other.controller_name
            && self.index == other.index
            && self.controller_index == other.controller_index
            && self.admin_state == other.admin_state
    }
}

impl PartialEq<PlannedInterfaceConstraint> for RequiredInterfaceAssociation {
    fn eq(&self, other: &PlannedInterfaceConstraint) -> bool {
        self.name == other.name
            && self.controller_name == other.controller_name
            && self.admin_state == other.admin_state
    }
}

impl PartialEq<ObservedInterfaceAssociation> for RequiredInterfaceAssociation {
    fn eq(&self, other: &ObservedInterfaceAssociation) -> bool {
        self.name == other.name
            && self.controller_name == other.controller_name
            && self.admin_state == other.admin_state
    }
}
impl PartialEq<RequiredInterfaceAssociation> for ObservedInterfaceAssociation {
    fn eq(&self, other: &RequiredInterfaceAssociation) -> bool {
        other == self
    }
}

impl PartialEq<MultiIndexObservedInterfaceAssociationMap>
    for MultiIndexRequiredInterfaceAssociationMap
{
    fn eq(&self, observed: &MultiIndexObservedInterfaceAssociationMap) -> bool {
        if self.iter().len() != observed.len() {
            return false;
        }
        for (_, observed) in observed.iter() {
            let Some(required) = self.get_by_name(&observed.name) else {
                return false;
            };
            if required != observed {
                return false;
            }
        }
        true
    }
}

impl MultiIndexObservedInterfaceAssociationMap {
    pub async fn get(handle: &Handle) -> Self {
        #[derive(Debug, Builder)]
        struct Relation {
            pub name: InterfaceName,
            pub index: InterfaceIndex,
            pub controller: Option<InterfaceIndex>,
            pub oper_state: State,
            pub state: AdminState,
        }
        let links = handle
            .link()
            .get()
            .execute()
            .try_ready_chunks(1024)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<_>>();
        let mut interface_map: HashMap<InterfaceIndex, Relation> =
            HashMap::with_capacity(links.len());
        for link in links {
            let mut builder = RelationBuilder::default();
            builder.index(link.header.index.into());
            builder.controller(None);
            builder.state(if link.header.flags.contains(LinkFlags::Up) {
                AdminState::Up
            } else {
                AdminState::Down
            });
            for attr in &link.attributes {
                match attr {
                    LinkAttribute::IfName(name) => {
                        builder.name(name.clone().try_into().unwrap());
                    }
                    LinkAttribute::Controller(idx) => {
                        builder.controller(Some((*idx).into()));
                    }
                    LinkAttribute::OperState(state) => {
                        builder.oper_state(*state);
                    }
                    _ => {}
                }
            }
            let Ok(relation) = builder.build() else {
                continue;
            };
            interface_map.insert(relation.index, relation);
        }
        let mut this = MultiIndexObservedInterfaceAssociationMap::default();
        for entry in interface_map.values() {
            let mut builder = ObservedInterfaceAssociationBuilder::default();
            builder.index(entry.index);
            builder.name(entry.name.clone());
            builder.controller_index(entry.controller);
            builder.admin_state(entry.state);
            builder.operational_state(match entry.oper_state {
                State::Down => OperationalState::Down,
                State::Up => OperationalState::Up,
                _ => OperationalState::Unknown,
            });
            if let Some(controller_index) = entry.controller {
                if let Some(controller) = interface_map.get(&controller_index) {
                    builder.controller_name(Some(controller.name.clone()));
                } else {
                    error!("missing entry in observation!");
                }
            } else {
                builder.controller_name(None);
            }
            match builder.build() {
                Ok(constraint) => match this.try_insert(constraint) {
                    Ok(_) => {}
                    Err(e) => {
                        error!("{e:?}");
                    }
                },
                Err(e) => {
                    error!("{e:?}");
                }
            }
        }
        this
    }
}

// Kept for constraint tracking
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct InterfaceRelations {
    /* names which we expect to exist or have observed mapped to their controller (if any) */
    pub observed: MultiIndexObservedInterfaceAssociationMap,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ObservedInformationBase {
    pub(crate) vrfs: MultiIndexObservedVrfMap,
    pub(crate) bridges: MultiIndexObservedBridgeMap,
    pub(crate) vteps: MultiIndexObservedVtepMap,
    pub(crate) constraints: InterfaceRelations,
}

impl PartialEq<ObservedInformationBase> for RequiredInformationBase {
    fn eq(&self, other: &ObservedInformationBase) -> bool {
        // TODO: constraints check
        self.bridges == other.bridges && self.vrfs == other.vrfs && self.vteps == other.vteps
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct InformationBase {
    pub implied: Arc<RequiredInformationBase>,
    pub observed: Arc<ObservedInformationBase>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Requirement {
    Vrf(RequiredVrf),
    Bridge(RequiredBridge),
    Interface(RequiredInterfaceAssociation),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Observation {
    Vrf(ObservedVrf),
    Bridge(ObservedBridge),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Change<T> {
    Add(T),
    Remove(T),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Input {
    Requirement(Change<Requirement>),
    Observation(Change<Observation>),
    ReSync(Box<ObservedInformationBase>),
}

#[derive(Debug)]
pub enum InformationBaseUpdateError {
    DuplicateVrf(RequiredVrf),
    DuplicateBridge(RequiredBridge),
    NoSuchVrf(RequiredVrf),
    NoSuchBridge(RequiredBridge),
}

impl ObservedBridge {
    pub fn to_implied(&self) -> RequiredBridge {
        RequiredBridge {
            name: self.name.clone(),
            vlan_filtering: self.vlan_filtering,
            vlan_protocol: self.vlan_protocol,
        }
    }
}

impl ObservedVrf {
    pub fn to_implied(&self) -> RequiredVrf {
        RequiredVrf {
            name: self.name.clone(),
            route_table: self.route_table,
        }
    }
}

impl ObservedVtep {
    pub fn to_requirement(&self) -> RequiredVtep {
        RequiredVtep {
            name: self.name.clone(),
            local: self.local,
            vni: self.vni,
        }
    }
}

impl ObservedInformationBase {
    async fn drive_to(&self, handle: &Handle, target: &RequiredInformationBase) {
        let extant_bridges: HashSet<RequiredBridge> = self
            .bridges
            .iter_by_name()
            .map(ObservedBridge::to_implied)
            .collect();
        let desired_bridges: HashSet<RequiredBridge> =
            target.bridges.iter_by_name().cloned().collect();
        let extant_vrfs: HashSet<RequiredVrf> = self
            .vrfs
            .iter_by_name()
            .map(ObservedVrf::to_implied)
            .collect();
        let desired_vrfs: HashSet<RequiredVrf> = target.vrfs.iter_by_name().cloned().collect();
        let bridges_to_remove = extant_bridges.difference(&desired_bridges);
        let bridge_removal_results = join_all(bridges_to_remove.map(|bridge| {
            let observed = self.bridges.get_by_name(&bridge.name).unwrap();
            handle.link().del(observed.index.to_u32()).execute()
        }))
        .await;
        // todo: this is slop.  Handle errors properly
        bridge_removal_results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let vrfs_to_remove = extant_vrfs.difference(&desired_vrfs);
        let vrf_removal_results = join_all(vrfs_to_remove.map(|vrf| {
            let observed = self.vrfs.get_by_name(&vrf.name).unwrap();
            handle.link().del(observed.index.to_u32()).execute()
        }))
        .await;
        // todo: this is slop.  Handle errors properly
        vrf_removal_results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let bridges_to_create = desired_bridges.difference(&extant_bridges);
        let bridge_create_results = join_all(bridges_to_create.map(|bridge| {
            handle
                .link()
                .add(
                    LinkBridge::new(bridge.name.as_ref())
                        .append_extra_attribute(LinkAttribute::LinkInfo(vec![LinkInfo::Data(
                            InfoData::Bridge(vec![
                                InfoBridge::VlanFiltering(bridge.vlan_filtering),
                                InfoBridge::VlanProtocol(bridge.vlan_protocol.as_u16()),
                            ]),
                        )]))
                        .build(),
                )
                .execute()
        }))
        .await;
        // todo: this is slop.  Handle errors properly
        bridge_create_results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let vrfs_to_create = desired_vrfs.difference(&extant_vrfs);
        let vrf_create_results = join_all(vrfs_to_create.map(|vrf| {
            handle
                .link()
                .add(LinkVrf::new(vrf.name.as_ref(), vrf.route_table.into()).build())
                .execute()
        }))
        .await;
        // todo: this is slop.  Handle errors properly
        vrf_create_results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    }
}

impl InformationBase {
    async fn reconcile(&mut self, handle: &Handle) {
        // TODO: refresh of whole thing is drastic.  Add in monitor
        self.observed = ObservedInformationBase::observe(handle).await;

        let _: HashSet<RequiredBridge> = self
            .observed
            .bridges
            .iter_by_name()
            .map(ObservedBridge::to_implied)
            .collect();
        let desired_bridges: HashSet<RequiredBridge> =
            self.implied.bridges.iter_by_name().cloned().collect();
        let _: HashSet<RequiredVrf> = self
            .observed
            .vrfs
            .iter_by_name()
            .map(ObservedVrf::to_implied)
            .collect();
        let desired_vrfs: HashSet<RequiredVrf> =
            self.implied.vrfs.iter_by_name().cloned().collect();

        let observed_bridge_names = self.observed.bridges.iter_by_name().map(|x| &x.name);
        let observed_vrf_names = self.observed.vrfs.iter_by_name().map(|x| &x.name);
        let observed_interface_names: HashSet<_> =
            observed_bridge_names.chain(observed_vrf_names).collect();
        let implied_interface_names: HashSet<_> = self
            .implied
            .constraints
            .interface
            .iter_by_name()
            .map(|x| &x.name)
            .collect();
        let interfaces_to_create: HashSet<_> = implied_interface_names
            .difference(&observed_interface_names)
            .copied()
            .collect();
        let interfaces_to_remove: HashSet<_> = observed_interface_names
            .difference(&implied_interface_names)
            .copied()
            .collect();
        let interfaces_to_update: HashSet<_> = implied_interface_names
            .difference(
                &interfaces_to_create
                    .union(&interfaces_to_remove)
                    .copied()
                    .collect(),
            )
            .copied()
            .collect();

        let _: HashSet<_> = desired_bridges.iter().map(|x| &x.name).collect();
        let _: HashSet<_> = desired_vrfs.iter().map(|x| &x.name).collect();

        for name in interfaces_to_remove {
            if self.observed.bridges.get_by_name(name).is_some() {
                // remove bridge as the controller of any needed interfaces
                // schedule bridge removal
                continue;
            }
            let Some(_) = self.observed.vrfs.get_by_name(name) else {
                unreachable!("logic error on removal of interface {name}", name = name);
            };
            // schedule vrf for removal
        }

        for name in interfaces_to_create {
            if self.implied.bridges.get_by_name(name).is_some() {
                // schedule bridge creation
                continue;
            }
            let Some(_) = self.implied.vrfs.get_by_name(name) else {
                unreachable!("logic error on creation of interface {name}", name = name);
            };
            // schedule vrf for creation
        }

        for name in interfaces_to_update {
            if self.observed.bridges.get_by_name(name).is_some() {
                let Some(_) = self.implied.bridges.get_by_name(name) else {
                    unreachable!("logic error on update of interface {name}", name = name);
                };
                // compare observed with desired and schedule update
                continue;
            }
            if self.observed.vrfs.get_by_name(name).is_some() {
                let Some(_) = self.implied.vrfs.get_by_name(name) else {
                    unreachable!("logic error on update of interface {name}", name = name);
                };
                // compare observed with desired and schedule update
            }
        }
    }
}

impl ObservedInformationBase {
    async fn observe(handle: &Handle) -> Arc<ObservedInformationBase> {
        let mut this = Arc::new(ObservedInformationBase::default());
        let mut req = handle.link().get().execute();
        while let Ok(Some(resp)) = req.try_next().await {
            if resp.message_contains(InfoKind::Bridge) {
                let mut builder = ObservedBridgeBuilder::default();
                builder.index(resp.header.index.into());
                for attr in &resp.attributes {
                    match attr {
                        LinkAttribute::LinkInfo(infos) => {
                            for info in infos {
                                if let LinkInfo::Data(InfoData::Bridge(bridge_info)) = info {
                                    for info in bridge_info {
                                        if let InfoBridge::VlanFiltering(filtering) = info {
                                            builder.vlan_filtering(*filtering);
                                        }
                                        if let InfoBridge::VlanProtocol(raw_eth_type) = info {
                                            builder.vlan_protocol(EthType::new(*raw_eth_type));
                                        }
                                    }
                                }
                            }
                        }
                        LinkAttribute::IfName(name) => {
                            builder.name(name.clone().try_into().unwrap());
                        }
                        _ => { /* no op */ }
                    }
                }
                let bridge = builder.build().unwrap();

                match Arc::make_mut(&mut this).bridges.try_insert(bridge) {
                    Ok(_) => {}
                    Err(err) => {
                        info!("{err:?}");
                    }
                }
            }
            if resp.message_contains(InfoKind::Vrf) {
                let mut builder = ObservedVrfBuilder::default();
                builder.index(resp.header.index.into());
                for attr in &resp.attributes {
                    match attr {
                        LinkAttribute::LinkInfo(infos) => {
                            for info in infos {
                                if let LinkInfo::Data(InfoData::Vrf(vrf_info)) = info {
                                    for info in vrf_info {
                                        if let InfoVrf::TableId(id) = info {
                                            builder.route_table((*id).into());
                                        }
                                    }
                                }
                            }
                        }
                        LinkAttribute::IfName(name) => {
                            builder.name(name.clone().try_into().unwrap());
                        }
                        _ => { /* no op */ }
                    }
                }
                let vrf = builder.build().unwrap();

                match Arc::make_mut(&mut this).vrfs.try_insert(vrf) {
                    Ok(_) => {}
                    Err(err) => {
                        info!("{err:?}");
                    }
                }
            }
        }
        this
    }
}

#[derive(Debug, Clone)]
pub enum ObservedInterface {
    Bridge(ObservedBridge),
    Vrf(ObservedVrf),
    Vtep(ObservedVtep),
}

impl TryFrom<LinkMessage> for ObservedBridge {
    type Error = LinkMessage;

    fn try_from(message: LinkMessage) -> Result<Self, Self::Error> {
        if !message.message_contains(InfoKind::Bridge) {
            return Err(message);
        }
        let mut builder = ObservedBridgeBuilder::default();
        builder.index(message.header.index.into());
        for attr in &message.attributes {
            match attr {
                LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        if let LinkInfo::Data(InfoData::Bridge(datas)) = info {
                            for data in datas {
                                match data {
                                    InfoBridge::VlanProtocol(raw) => {
                                        builder.vlan_protocol(EthType::new(*raw));
                                    }
                                    InfoBridge::VlanFiltering(filtering) => {
                                        builder.vlan_filtering(*filtering);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                LinkAttribute::IfName(name) => match InterfaceName::try_from(name.clone()) {
                    Ok(name) => {
                        builder.name(name);
                    }
                    Err(illegal_name) => {
                        error!("{illegal_name:?}");
                        return Err(message);
                    }
                },
                _ => {}
            }
        }
        builder.build().map_err(|err| {
            error!("{err:?}");
            message
        })
    }
}

impl TryFrom<LinkMessage> for ObservedVrf {
    type Error = LinkMessage;

    fn try_from(message: LinkMessage) -> Result<Self, Self::Error> {
        if !message.message_contains(InfoKind::Vrf) {
            return Err(message);
        }
        let mut builder = ObservedVrfBuilder::default();
        builder.index(message.header.index.into());
        for attr in &message.attributes {
            match attr {
                LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        if let LinkInfo::Data(InfoData::Vrf(datas)) = info {
                            for data in datas {
                                if let InfoVrf::TableId(raw) = data {
                                    builder.route_table(RouteTableId::from(*raw));
                                }
                            }
                        }
                    }
                }
                LinkAttribute::IfName(name) => match InterfaceName::try_from(name.clone()) {
                    Ok(name) => {
                        builder.name(name);
                    }
                    Err(illegal_name) => {
                        error!("{illegal_name:?}");
                        return Err(message);
                    }
                },
                _ => {}
            }
        }
        builder.build().map_err(|err| {
            error!("{err:?}");
            message
        })
    }
}

impl TryFrom<LinkMessage> for ObservedVtep {
    type Error = LinkMessage;

    fn try_from(message: LinkMessage) -> Result<Self, Self::Error> {
        if !message.message_contains(InfoKind::Vxlan) {
            return Err(message);
        }
        let mut builder = ObservedVtepBuilder::default();
        builder.index(message.header.index.into());
        for attr in &message.attributes {
            match attr {
                LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        if let LinkInfo::Data(InfoData::Vxlan(datas)) = info {
                            for data in datas {
                                match data {
                                    InfoVxlan::Id(id) => match Vni::new_checked(*id) {
                                        Ok(vni) => {
                                            builder.vni(vni);
                                        }
                                        Err(invalid_vni) => {
                                            error!("{invalid_vni:?}");
                                            return Err(message);
                                        }
                                    },
                                    InfoVxlan::Local(ip) => {
                                        builder.local(*ip);
                                    }
                                    InfoVxlan::Ttl(ttl) => {
                                        builder.ttl(*ttl);
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                LinkAttribute::IfName(name) => match InterfaceName::try_from(name.clone()) {
                    Ok(name) => {
                        builder.name(name);
                    }
                    Err(illegal_name) => {
                        error!("{illegal_name:?}");
                        return Err(message);
                    }
                },
                _ => {}
            }
        }
        builder.build().map_err(|err| {
            error!("{err:?}");
            message
        })
    }
}

impl TryFrom<LinkMessage> for ObservedInterface {
    type Error = LinkMessage;

    fn try_from(message: LinkMessage) -> Result<Self, Self::Error> {
        let message = match ObservedBridge::try_from(message) {
            Ok(x) => return Ok(ObservedInterface::Bridge(x)),
            Err(message) => message,
        };
        let message = match ObservedVrf::try_from(message) {
            Ok(x) => return Ok(ObservedInterface::Vrf(x)),
            Err(message) => message,
        };
        Ok(ObservedInterface::Vtep(ObservedVtep::try_from(message)?))
    }
}

impl ObservedInformationBase {
    pub fn try_add_bridge(
        &mut self,
        bridge: ObservedBridge,
    ) -> Result<&ObservedBridge, UniquenessError<ObservedBridge>> {
        self.bridges.try_insert(bridge).map_err(|err| {
            debug!("{err:?}");
            err
        })
    }

    pub fn try_add_vrf(
        &mut self,
        vrf: ObservedVrf,
    ) -> Result<&ObservedVrf, UniquenessError<ObservedVrf>> {
        self.vrfs.try_insert(vrf).map_err(|err| {
            debug!("{err:?}");
            err
        })
    }

    pub fn try_add_vtep(
        &mut self,
        vtep: ObservedVtep,
    ) -> Result<&ObservedVtep, UniquenessError<ObservedVtep>> {
        self.vteps.try_insert(vtep).map_err(|err| {
            debug!("{err:?}");
            err
        })
    }
    pub fn try_add_interface(
        &mut self,
        interface: ObservedInterface,
    ) -> Result<(), ObservedInterface> {
        match interface {
            ObservedInterface::Bridge(bridge) => self
                .try_add_bridge(bridge)
                .map(|_| ())
                .map_err(|e| ObservedInterface::Bridge(e.0)),
            ObservedInterface::Vrf(vrf) => self
                .try_add_vrf(vrf)
                .map(|_| ())
                .map_err(|e| ObservedInterface::Vrf(e.0)),
            ObservedInterface::Vtep(vtep) => self
                .try_add_vtep(vtep)
                .map(|_| ())
                .map_err(|e| ObservedInterface::Vtep(e.0)),
        }
    }

    pub fn try_remove_bridge(&mut self, index: InterfaceIndex) -> Option<ObservedBridge> {
        self.bridges.remove_by_index(&index)
    }

    pub fn try_remove_vrf(&mut self, index: InterfaceIndex) -> Option<ObservedVrf> {
        self.vrfs.remove_by_index(&index)
    }

    pub fn try_remove_vtep(&mut self, index: InterfaceIndex) -> Option<ObservedVtep> {
        self.vteps.remove_by_index(&index)
    }

    pub fn try_remove_interface(&mut self, index: InterfaceIndex) -> Option<ObservedInterface> {
        match self.try_remove_bridge(index).map(ObservedInterface::Bridge) {
            None => {}
            Some(x) => return Some(x),
        }
        match self.try_remove_vrf(index).map(ObservedInterface::Vrf) {
            None => {}
            Some(x) => return Some(x),
        }
        match self.try_remove_vtep(index).map(ObservedInterface::Vtep) {
            None => {}
            Some(x) => return Some(x),
        }
        None
    }

    pub fn try_add_association(
        &mut self,
        association: ObservedInterfaceAssociation,
    ) -> Result<&ObservedInterfaceAssociation, UniquenessError<ObservedInterfaceAssociation>> {
        self.constraints
            .observed
            .try_insert(association)
            .map_err(|err| {
                debug!("{err:?}");
                err
            })
    }

    pub fn try_remove_association(
        &mut self,
        index: InterfaceIndex,
    ) -> Option<ObservedInterfaceAssociation> {
        self.constraints.observed.remove_by_index(&index)
    }
}
