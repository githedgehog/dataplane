#![allow(clippy::ref_option)] // generated code :shrug:
#![allow(clippy::unsafe_derive_deserialize)] // trusting multi index map but could use a review

use crate::message::{MessageContains, message_is_of_kind};
use crate::{IfIndex, InterfaceName};
use arc_swap::ArcSwap;
use crossbeam::epoch;
use crossbeam::epoch::Atomic;
use derive_builder::Builder;
use diff::Diff;
use futures::TryStreamExt;
use futures::future::join_all;
use id::Id;
use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle};
use multi_index_map::{MultiIndexMap, UniquenessError};
use net::eth::ethtype::EthType;
use net::vlan::Vid;
use net::vxlan::Vni;
use rtnetlink::packet_route::link::LinkInfo::PortData;
use rtnetlink::packet_route::link::{
    InfoBridge, InfoData, InfoKind, InfoVrf, LinkAttribute, LinkInfo,
};
use rtnetlink::sys::AsyncSocket;
use rtnetlink::{Handle, LinkBridge, LinkVrf, new_connection};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};
use tracing::{debug, error, info};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Diff)]
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

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
enum NetworkDiscriminant {
    EvpnVxlan { vni: Vni },
}

#[derive(
    Clone, Debug, Eq, Hash, MultiIndexMap, Ord, PartialEq, PartialOrd, Deserialize, Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Vpc {
    #[multi_index(hashed_unique)]
    id: Id<Vpc>,
    #[multi_index(ordered_unique)]
    route_table: RouteTableId,
    #[multi_index(ordered_non_unique)]
    discriminant: NetworkDiscriminant,
}

impl Vpc {
    fn new(route_table: RouteTableId, discriminant: NetworkDiscriminant) -> Self {
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
pub struct ImpliedVrf {
    #[multi_index(hashed_unique)]
    name: InterfaceName,
    #[multi_index(hashed_unique)]
    route_table: RouteTableId,
}

#[derive(Builder, Clone, Debug, Eq, MultiIndexMap, PartialEq, Serialize, Deserialize)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservedVrf {
    #[builder(private)]
    #[multi_index(ordered_unique)]
    name: InterfaceName,
    #[builder(private)]
    #[multi_index(ordered_unique)]
    route_table: RouteTableId,
    #[builder(private)]
    #[multi_index(ordered_unique)]
    if_index: IfIndex,
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
pub struct ImpliedVtep {
    #[multi_index(ordered_unique)]
    name: InterfaceName,
    #[multi_index(ordered_unique)]
    vni: Vni,
    local: IpAddr,
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
    #[multi_index(ordered_unique)]
    if_index: IfIndex,
    #[multi_index(ordered_unique)]
    vni: Vni,
    local: IpAddr,
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
pub struct ImpliedBridge {
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    pub vlan_filtering: bool,
    pub vlan_protocol: EthType,
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
    pub if_index: IfIndex,
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
pub struct ImpliedVtepBridgeMembership {
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
pub struct ImpliedVrfMembership {
    #[multi_index(hashed_unique)]
    vrf: InterfaceName,
    #[multi_index(hashed_unique)]
    member: InterfaceName,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ImpliedInformationBase {
    vrfs: MultiIndexImpliedVrfMap,
    bridges: MultiIndexImpliedBridgeMap,
    constraints: InformationBaseConstraints,
}

// Kept for constraint tracking
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
struct InformationBaseConstraints {
    /* names which we expect to exist or have observed mapped to their controller (if any)*/
    interface: MultiIndexInterfaceConstraintMap,
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
pub struct InterfaceConstraint {
    #[multi_index(hashed_unique)]
    name: InterfaceName,
    #[multi_index(ordered_non_unique)]
    controller_name: Option<InterfaceName>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct ObservedInformationBase {
    vrfs: MultiIndexObservedVrfMap,
    bridges: MultiIndexObservedBridgeMap,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct InformationBase {
    implied: ImpliedInformationBase,
    observed: ObservedInformationBase,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct InformationBase2 {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Requirement {
    Vrf(ImpliedVrf),
    Bridge(ImpliedBridge),
    Interface(InterfaceConstraint),
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

// #[allow(clippy::unnecessary_semicolon, clippy::too_many_lines)]
// impl Absorb<Input> for InformationBase {
//     fn absorb_first(&mut self, operation: &mut Input, _other: &Self) {
//         match operation {
//             Input::Requirement(operation) => match operation {
//                 Change::Add(Requirement::Vrf(vrf)) => {
//                     let mut constraint_builder = InterfaceConstraintBuilder::default();
//                     // TODO: we can't use left-right this way if panic is the best we can do here
//                     constraint_builder.name(vrf.name.clone());
//                     constraint_builder.controller_name(None);
//                     let constraint = constraint_builder.build().unwrap();
//                     if let Err(err) = self.implied.constraints.interface.try_insert(constraint) {
//                         // roll back when we remove this panic
//                         // self.implied.constraints.name.insert(vrf.name.clone(), old);
//                         let err = format!("duplicate interface name: {err:?} for {vrf:?}");
//                         error!("{err}");
//                         panic!("{err}");
//                     }
//                     match self.implied.vrfs.try_insert(vrf.clone()) {
//                         Ok(_) => {}
//                         Err(err) => {
//                             error!("{err}");
//                             panic!("{err}");
//                         }
//                     }
//                 }
//                 Change::Remove(Requirement::Vrf(vrf)) => {
//                     if let Some(removed) = self.implied.vrfs.remove_by_route_table(&vrf.route_table)
//                     {
//                         if &removed != vrf {
//                             let err = format!(
//                                 "programmer error: intent removal conflict. Found: {removed:?}, Expected: {vrf:?}"
//                             );
//                             error!("{err}");
//                             panic!("{err}");
//                         }
//
//                         for mut constraint in self
//                             .implied
//                             .constraints
//                             .interface
//                             .remove_by_controller_name(&Some(vrf.name.clone()))
//                         {
//                             constraint.controller_name = None;
//                             self.implied
//                                 .constraints
//                                 .interface
//                                 .try_insert(constraint)
//                                 .unwrap();
//                         }
//                         if self
//                             .implied
//                             .constraints
//                             .interface
//                             .remove_by_name(&vrf.name)
//                             .is_none()
//                         {
//                             let err = format!(
//                                 "programmer error: route table removal conflict. Missing interface name {vrf:?}"
//                             );
//                             error!("{err}");
//                             panic!("{err}");
//                         };
//                     }
//                 }
//                 Change::Add(Requirement::Bridge(interface)) => {
//                     let constraint = InterfaceConstraint {
//                         name: interface.name.clone(),
//                         controller_name: None,
//                     };
//                     // TODO: replace with non-panic version
//                     self.implied.constraints.interface.insert(constraint);
//                     match self.implied.bridges.try_insert(interface.clone()) {
//                         Ok(_) => {}
//                         Err(err) => {
//                             error!("{err}");
//                             panic!("{err}");
//                         }
//                     }
//                 }
//                 Change::Remove(Requirement::Bridge(interface)) => {
//                     if let Some(removed) = self.implied.bridges.remove_by_name(&interface.name) {
//                         if &removed != interface {
//                             let err = format!("found: {removed:?}, expected: {interface:?}");
//                             error!("{err}");
//                             panic!("{err}");
//                         }
//                     }
//                     for mut constraint in self
//                         .implied
//                         .constraints
//                         .interface
//                         .remove_by_controller_name(&Some(interface.name.clone()))
//                     {
//                         constraint.controller_name = None;
//                         self.implied
//                             .constraints
//                             .interface
//                             .try_insert(constraint)
//                             .unwrap();
//                     }
//                     if self
//                         .implied
//                         .constraints
//                         .interface
//                         .remove_by_name(&interface.name)
//                         .is_none()
//                     {
//                         let err = format!("missing interface name {interface:?}");
//                         error!("{err}");
//                         panic!("{err}");
//                     };
//                 }
//                 Change::Add(Requirement::Interface(_)) => {}
//             },
//             // This is a big todo.
//             // Uniqueness error could mean a lot of things here and they all need to be
//             // checked.
//             // It is even possible that the observation requires us to drop
//             // all previous observations and resync.
//             Input::Observation(operation) => match operation {
//                 Change::Add(Observation::Vrf(vrf)) => {
//                     match self.observed.vrfs.try_insert(vrf.clone()) {
//                         Ok(_) => {}
//                         Err(err) => {
//                             info!("duplicate observation: {err}");
//                         }
//                     }
//                 }
//                 Change::Add(Observation::Bridge(bridge)) => {
//                     match self.observed.bridges.try_insert(bridge.clone()) {
//                         Ok(_) => {}
//                         Err(err) => {
//                             info!("duplicate observation: {err}");
//                         }
//                     }
//                 }
//                 Change::Remove(Observation::Vrf(vrf)) => {
//                     if let Some(removed) =
//                         self.observed.vrfs.remove_by_route_table(&vrf.route_table)
//                     {
//                         if &removed != vrf {
//                             let err = format!(
//                                 "programmer error: observation removal conflict. Found: {removed:?}, Expected: {vrf:?}"
//                             );
//                             error!("{err}");
//                         }
//                     }
//                 }
//                 Change::Remove(Observation::Bridge(bridge)) => {
//                     if let Some(removed) =
//                         self.observed.bridges.remove_by_if_index(&bridge.if_index)
//                     {
//                         if &removed != bridge {
//                             let err = format!(
//                                 "programmer error: observation removal conflict. Found: {removed:?}, Expected: {bridge:?}"
//                             );
//                             error!("{err}");
//                         }
//                     }
//                 }
//             },
//             Input::ReSync(observations) => {
//                 self.observed = (**observations).clone();
//             }
//         }
//     }
//
//     fn sync_with(&mut self, first: &Self) {
//         self.clone_from(first);
//     }
// }

#[derive(Debug)]
pub enum InformationBaseUpdateError {
    DuplicateVrf(ImpliedVrf),
    DuplicateBridge(ImpliedBridge),
    NoSuchVrf(ImpliedVrf),
    NoSuchBridge(ImpliedBridge),
}

// impl InformationBase {
//     fn submit(&mut self, operation: Input) -> Result<(), InformationBaseUpdateError> {
//         match operation {
//             Input::Requirement(change) => match change {
//                 Change::Add(req) => match req {
//                     Requirement::Vrf(vrf) => {
//                         self.implied
//                             .vrfs
//                             .try_insert(vrf)
//                             .map_err(|e| InformationBaseUpdateError::DuplicateVrf(e.0))?;
//                     }
//                     Requirement::Bridge(bridge) => {
//                         self.implied
//                             .bridges
//                             .try_insert(bridge)
//                             .map_err(|e| InformationBaseUpdateError::DuplicateBridge(e.0))?;
//                     }
//                 },
//                 Change::Remove(req) => match req {
//                     Requirement::Vrf(vrf) => {
//                         if self
//                             .implied
//                             .vrfs
//                             .remove_by_route_table(&vrf.route_table)
//                             .is_none()
//                         {
//                             Err(InformationBaseUpdateError::NoSuchVrf(vrf))?;
//                         }
//                     }
//                     Requirement::Bridge(bridge) => {
//                         if self.implied.bridges.remove_by_name(&bridge.name).is_none() {
//                             Err(InformationBaseUpdateError::NoSuchBridge(bridge))?;
//                         }
//                     }
//                 },
//             },
//             Input::Observation(_) => {
//                 todo!()
//             }
//             Input::ReSync(_) => {}
//         }
//         Ok(())
//     }
// }

// pub struct InformationBaseWriter(WriteHandle<InformationBase, Input>);
// pub struct InformationBaseReader(ReadHandle<InformationBase>);

// impl InformationBaseWriter {
//     fn submit(&mut self, operation: Input) {
//         self.0.append(operation);
//     }
//
//     fn publish(&mut self) {
//         self.0.publish();
//     }
// }
//
// impl InformationBaseReader {
//     fn inner(&self) -> Option<ReadGuard<'_, InformationBase>> {
//         self.0.enter()
//     }
// }

// #[test]
// fn biscuit() {
//     let (write, read) = left_right::new::<InformationBase, Input>();
//     let mut write = InformationBaseWriter(write);
//     write.publish();
//     let read = InformationBaseReader(read);
//     println!("{:?}", read.inner().unwrap().observed);
//     write.submit(Input::Observation(Change::Add(Observation::Bridge(
//         ObservedBridge {
//             name: InterfaceName::try_from("science".to_string()).unwrap(),
//             vlan_protocol: None,
//             if_index: 18.try_into().unwrap(),
//         },
//     ))));
//     println!("{:?}", read.inner().unwrap().observed);
//     write.publish();
//     println!("{:?}", read.inner().unwrap().observed);
//     write.submit(Input::Observation(Change::Add(Observation::Bridge(
//         ObservedBridge {
//             name: InterfaceName::try_from("science2".to_string()).unwrap(),
//             vlan_protocol: None,
//             if_index: 19.try_into().unwrap(),
//         },
//     ))));
//     write.publish();
//     println!("{:?}", read.inner().unwrap().observed);
//     write.submit(Input::Requirement(Change::Add(Requirement::Vrf(
//         ImpliedVrf {
//             name: InterfaceName::try_from("vrf1".to_string()).unwrap(),
//             route_table: 1.into(),
//         },
//     ))));
//     write.submit(Input::Requirement(Change::Add(Requirement::Vrf(
//         ImpliedVrf {
//             name: InterfaceName::try_from("vrf2".to_string()).unwrap(),
//             route_table: 2.into(),
//         },
//     ))));
//     write.submit(Input::Requirement(Change::Add(Requirement::Vrf(
//         ImpliedVrf {
//             name: InterfaceName::try_from("vrf3".to_string()).unwrap(),
//             route_table: 3.into(),
//         },
//     ))));
//     // write.publish();
//     println!("{:?}", read.inner().unwrap());
// }

impl ObservedBridge {
    pub fn to_implied(&self) -> ImpliedBridge {
        ImpliedBridge {
            name: self.name.clone(),
            vlan_filtering: self.vlan_filtering,
            vlan_protocol: self.vlan_protocol,
        }
    }
}

impl ObservedVrf {
    pub fn to_implied(&self) -> ImpliedVrf {
        ImpliedVrf {
            name: self.name.clone(),
            route_table: self.route_table.clone(),
        }
    }
}

impl ObservedInformationBase {
    async fn drive_to(&self, handle: &Handle, target: &ImpliedInformationBase) {
        let extant_bridges: HashSet<ImpliedBridge> = self
            .bridges
            .iter_by_name()
            .map(ObservedBridge::to_implied)
            .collect();
        let desired_bridges: HashSet<ImpliedBridge> =
            target.bridges.iter_by_name().cloned().collect();
        let extant_vrfs: HashSet<ImpliedVrf> = self
            .vrfs
            .iter_by_name()
            .map(ObservedVrf::to_implied)
            .collect();
        let desired_vrfs: HashSet<ImpliedVrf> = target.vrfs.iter_by_name().cloned().collect();
        let bridges_to_remove = extant_bridges.difference(&desired_bridges);
        let bridge_removal_results = join_all(bridges_to_remove.map(|bridge| {
            let observed = self.bridges.get_by_name(&bridge.name).unwrap();
            handle.link().del(observed.if_index.to_u32()).execute()
        }))
        .await;
        // todo: this is slop.  Handle errors properly
        bridge_removal_results
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let vrfs_to_remove = extant_vrfs.difference(&desired_vrfs);
        let vrf_removal_results = join_all(vrfs_to_remove.map(|vrf| {
            let observed = self.vrfs.get_by_route_table(&vrf.route_table).unwrap();
            handle.link().del(observed.if_index.to_u32()).execute()
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
                .add(LinkVrf::new(vrf.name.as_ref(), vrf.route_table.clone().into()).build())
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

pub struct Reconcile {
    ib: InformationBase,
    schedule: Vec<Input>,
}

impl Reconcile {
    fn new(ib: InformationBase) -> Self {
        Self {
            ib,
            schedule: Vec::new(),
        }
    }
}

impl InformationBase {
    async fn reconcile(&mut self, handle: &Handle) {
        // TODO: refresh of whole thing is drastic.  Add in monitor
        self.observed = *ObservedInformationBase::observe(handle).await;

        let extant_bridges: HashSet<ImpliedBridge> = self
            .observed
            .bridges
            .iter_by_name()
            .map(ObservedBridge::to_implied)
            .collect();
        let desired_bridges: HashSet<ImpliedBridge> =
            self.implied.bridges.iter_by_name().cloned().collect();
        let observed_vrfs: HashSet<ImpliedVrf> = self
            .observed
            .vrfs
            .iter_by_name()
            .map(ObservedVrf::to_implied)
            .collect();
        let desired_vrfs: HashSet<ImpliedVrf> = self.implied.vrfs.iter_by_name().cloned().collect();

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

        let desired_bridge_names: HashSet<_> = desired_bridges.iter().map(|x| &x.name).collect();
        let desired_vrf_names: HashSet<_> = desired_vrfs.iter().map(|x| &x.name).collect();

        for name in interfaces_to_remove {
            if let Some(bridge) = self.observed.bridges.get_by_name(name) {
                // remove bridge as the controller of any needed interfaces
                // schedule bridge removal
                continue;
            }
            let Some(vrf) = self.observed.vrfs.get_by_name(name) else {
                unreachable!("logic error on removal of interface {name}", name = name);
            };
            // schedule vrf for removal
        }

        for name in interfaces_to_create {
            if let Some(bridge) = self.implied.bridges.get_by_name(name) {
                // schedule bridge creation
                continue;
            }
            let Some(vrf) = self.implied.vrfs.get_by_name(name) else {
                unreachable!("logic error on creation of interface {name}", name = name);
            };
            // schedule vrf for creation
        }

        for name in interfaces_to_update {
            if let Some(observed_bridge) = self.observed.bridges.get_by_name(name) {
                let Some(desired_bridge) = self.implied.bridges.get_by_name(name) else {
                    unreachable!("logic error on update of interface {name}", name = name);
                };
                // compare observed with desired and schedule update
                continue;
            }
            if let Some(observed_vrf) = self.observed.vrfs.get_by_name(name) {
                let Some(desired_vrf) = self.implied.vrfs.get_by_name(name) else {
                    unreachable!("logic error on update of interface {name}", name = name);
                };
                // compare observed with desired and schedule update
            }
        }
    }
}

impl ObservedInformationBase {
    async fn observe(handle: &Handle) -> Box<ObservedInformationBase> {
        let mut this = Box::new(ObservedInformationBase::default());
        let mut req = handle.link().get().execute();
        while let Ok(Some(resp)) = req.try_next().await {
            if resp.message_contains(InfoKind::Bridge) {
                let mut builder = ObservedBridgeBuilder::default();
                builder.if_index(resp.header.index.try_into().unwrap());
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

                match this.bridges.try_insert(bridge) {
                    Ok(_) => {}
                    Err(err) => {
                        info!("{err:?}");
                    }
                }
            }
            if resp.message_contains(InfoKind::Vrf) {
                let mut builder = ObservedVrfBuilder::default();
                builder.if_index(resp.header.index.try_into().unwrap());
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

                match this.vrfs.try_insert(vrf) {
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

// #[tokio::test(flavor = "current_thread")]
// async fn rascal() {
//     let Ok((mut connection, handle, _recv)) = new_connection() else {
//         panic!("failed to create connection");
//     };
//     connection
//         .socket_mut()
//         .socket_mut()
//         .set_rx_buf_sz(212_992)
//         .unwrap();
//
//     tokio::spawn(connection);
//     let (write, read) = left_right::new::<InformationBase, Input>();
//     let mut write = InformationBaseWriter(write);
//     let read = InformationBaseReader(read);
//     write.submit(Input::Requirement(Change::Add(Requirement::Bridge(
//         ImpliedBridge {
//             name: InterfaceName::try_from("brA".to_string()).unwrap(),
//             vlan_protocol: Some(EthType::VLAN),
//         },
//     ))));
//     write.submit(Input::Requirement(Change::Add(Requirement::Bridge(
//         ImpliedBridge {
//             name: InterfaceName::try_from("brB".to_string()).unwrap(),
//             vlan_protocol: Some(EthType::VLAN),
//         },
//     ))));
//     write.submit(Input::Requirement(Change::Add(Requirement::Vrf(
//         ImpliedVrf {
//             name: InterfaceName::try_from("vrf1".to_string()).unwrap(),
//             route_table: 1.into(),
//         },
//     ))));
//     write.submit(Input::Requirement(Change::Add(Requirement::Vrf(
//         ImpliedVrf {
//             name: InterfaceName::try_from("vrf2".to_string()).unwrap(),
//             route_table: 2.into(),
//         },
//     ))));
//     write.submit(Input::Requirement(Change::Add(Requirement::Vrf(
//         ImpliedVrf {
//             name: InterfaceName::try_from("vrf3".to_string()).unwrap(),
//             route_table: 3.into(),
//         },
//     ))));
//     write.publish();
//     println!("{:?}", read.inner().unwrap());
//     write.submit(Input::ReSync(
//         ObservedInformationBase::observe(&handle).await,
//     ));
//     write.publish();
//     write.submit(Input::Requirement(Change::Remove(Requirement::Vrf(
//         ImpliedVrf {
//             name: InterfaceName::try_from("vrf3".to_string()).unwrap(),
//             route_table: 3.into(),
//         },
//     ))));
//     let inner = read.inner().unwrap();
//     inner.observed.drive_to(&handle, &inner.implied).await;
//     write.publish();
//     let inner = read.inner().unwrap();
//     inner.observed.drive_to(&handle, &inner.implied).await;
// }

// #[tokio::test(flavor = "current_thread")]
// async fn rascal2() {
//     let Ok((mut connection, handle, _recv)) = new_connection() else {
//         panic!("failed to create connection");
//     };
//     connection
//         .socket_mut()
//         .socket_mut()
//         .set_rx_buf_sz(212_992)
//         .unwrap();
//
//     tokio::spawn(connection);
//     let (write, read) = left_right::new::<InformationBase, Input>();
//     let mut write = InformationBaseWriter(write);
//     let read = InformationBaseReader(read);
//     write.submit(Input::ReSync(
//         ObservedInformationBase::observe(&handle).await,
//     ));
//     write.publish();
//     let inner = read.inner().unwrap();
//     inner.observed.drive_to(&handle, &inner.implied).await;
//     println!("{:?}", read.0.enter().unwrap().observed);
// }
