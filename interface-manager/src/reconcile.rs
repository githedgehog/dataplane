// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{
    AdminState, ImpliedBridge, ImpliedInformationBase, ImpliedVrf, ImpliedVtep,
    MultiIndexImpliedBridgeMap, MultiIndexImpliedInterfaceConstraintMap, MultiIndexImpliedVrfMap,
    MultiIndexImpliedVtepMap, MultiIndexObservedBridgeMap,
    MultiIndexObservedInterfaceConstraintMap, MultiIndexObservedVrfMap, MultiIndexObservedVtepMap,
    MultiIndexPlannedInterfaceConstraintMap, ObservedBridge, ObservedInformationBase, ObservedVrf,
    ObservedVtep, PlannedInterfaceConstraint,
};
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo};
use rtnetlink::{
    Handle, LinkAddRequest, LinkBridge, LinkDelRequest, LinkSetRequest, LinkUnspec, LinkVrf,
    LinkVxlan,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

pub enum Request<T: Reconcile<Required, Observed>, Required: PartialEq<Observed>, Observed> {
    Create(<T as Reconcile<Required, Observed>>::Create),
    Update(<T as Reconcile<Required, Observed>>::Update),
    Remove(<T as Reconcile<Required, Observed>>::Remove),
}

pub trait Reconcile<Required, Observed>: Sized
where
    Required: PartialEq<Observed>,
{
    type Create;
    type Update;
    type Remove;

    fn request_create(&self, required: &Required) -> Self::Create;
    fn request_remove(&self, observed: &Observed) -> Self::Remove;
    fn request_update(&self, required: &Required, observed: &Observed) -> Self::Update;

    fn request_reconcile(
        &self,
        required: Option<&Required>,
        observed: Option<&Observed>,
    ) -> Option<Request<Self, Required, Observed>> {
        match (required, observed) {
            (Some(required), None) => Some(Request::Create(self.request_create(required))),
            (None, Some(observed)) => Some(Request::Remove(self.request_remove(observed))),
            (Some(required), Some(observed)) => {
                if required == observed {
                    return None;
                }
                Some(Request::Update(self.request_update(required, observed)))
            }
            (None, None) => None,
        }
    }
}

impl Reconcile<ImpliedVrf, ObservedVrf> for Handle {
    type Create = LinkAddRequest;
    type Update = LinkAddRequest;
    type Remove = LinkDelRequest;

    fn request_create(&self, required: &ImpliedVrf) -> Self::Create {
        self.link()
            .add(LinkVrf::new(required.name.as_ref(), required.route_table.into()).build())
    }

    fn request_remove(&self, observed: &ObservedVrf) -> Self::Remove {
        self.link().del(observed.index.to_u32())
    }

    fn request_update(&self, required: &ImpliedVrf, observed: &ObservedVrf) -> Self::Update {
        let mut message = LinkVrf::new(required.name.as_ref(), required.route_table.into()).build();
        message.header.index = observed.index.into();
        self.link().add(message).replace()
    }
}

impl Reconcile<ImpliedVtep, ObservedVtep> for Handle {
    type Create = LinkAddRequest;
    type Update = LinkAddRequest;
    type Remove = LinkDelRequest;

    fn request_create(&self, required: &ImpliedVtep) -> Self::Create {
        self.link().add(
            LinkVxlan::new(required.name.as_ref(), required.vni.as_u32())
                .local(required.local)
                .build(),
        )
    }

    fn request_remove(&self, observed: &ObservedVtep) -> Self::Remove {
        self.link().del(observed.if_index.to_u32())
    }

    fn request_update(&self, required: &ImpliedVtep, observed: &ObservedVtep) -> Self::Update {
        let mut message = LinkVxlan::new(required.name.as_ref(), required.vni.as_u32()).build();
        message.header.index = observed.if_index.into();
        self.link().add(message).replace()
    }
}

impl Reconcile<ImpliedBridge, ObservedBridge> for Handle {
    type Create = LinkAddRequest;
    type Update = LinkAddRequest;
    type Remove = LinkDelRequest;

    fn request_create(&self, required: &ImpliedBridge) -> Self::Create {
        self.link().add(
            LinkBridge::new(required.name.as_ref())
                .append_extra_attribute(LinkAttribute::LinkInfo(vec![LinkInfo::Data(
                    InfoData::Bridge(vec![
                        InfoBridge::VlanFiltering(required.vlan_filtering),
                        InfoBridge::VlanProtocol(required.vlan_protocol.as_u16()),
                    ]),
                )]))
                .build(),
        )
    }

    fn request_remove(&self, observed: &ObservedBridge) -> Self::Remove {
        self.link().del(observed.if_index.to_u32())
    }

    fn request_update(&self, required: &ImpliedBridge, observed: &ObservedBridge) -> Self::Update {
        let mut message = LinkBridge::new(required.name.as_ref())
            .append_extra_attribute(LinkAttribute::LinkInfo(vec![LinkInfo::Data(
                InfoData::Bridge(vec![
                    InfoBridge::VlanFiltering(required.vlan_filtering),
                    InfoBridge::VlanProtocol(required.vlan_protocol.as_u16()),
                ]),
            )]))
            .build();
        message.header.index = observed.if_index.into();
        self.link().add(message).replace()
    }
}

impl Reconcile<MultiIndexImpliedVrfMap, MultiIndexObservedVrfMap> for Handle {
    type Create = Vec<Request<Handle, ImpliedVrf, ObservedVrf>>;
    type Update = Vec<Request<Handle, ImpliedVrf, ObservedVrf>>;
    type Remove = Vec<Request<Handle, ImpliedVrf, ObservedVrf>>;

    fn request_create(&self, required: &MultiIndexImpliedVrfMap) -> Self::Create {
        required
            .iter()
            .map(|(_, vrf)| Request::Create(self.request_create(vrf)))
            .collect()
    }

    fn request_remove(&self, observed: &MultiIndexObservedVrfMap) -> Self::Remove {
        observed
            .iter()
            .map(|(_, vrf)| Request::Remove(self.request_remove(vrf)))
            .collect()
    }

    fn request_update(
        &self,
        required: &MultiIndexImpliedVrfMap,
        observed: &MultiIndexObservedVrfMap,
    ) -> Self::Update {
        let mut to_create = MultiIndexImpliedVrfMap::default();
        let mut to_remove = MultiIndexObservedVrfMap::default();
        for (_, observed) in observed.iter() {
            if required.get_by_name(&observed.name).is_none() {
                match to_remove.try_insert(observed.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate removal scheduled: {err:?}");
                    }
                }
            }
            if required.get_by_route_table(&observed.route_table).is_none() {
                match to_remove.try_insert(observed.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate removal scheduled: {err:?}");
                    }
                }
            }
        }
        for (_, requirement) in required.iter() {
            for observed_with_matching_route_table in
                observed.get_by_route_table(&requirement.route_table)
            {
                if requirement != observed_with_matching_route_table {
                    match to_remove.try_insert(observed_with_matching_route_table.clone()) {
                        Ok(_) => {}
                        Err(err) => {
                            trace!("duplicate removal scheduled: {err:?}");
                        }
                    }
                }
            }
            match observed.get_by_name(&requirement.name) {
                None => match to_create.try_insert(requirement.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate creation scheduled: {err:?}");
                    }
                },
                Some(observed_with_matching_name) => {
                    if requirement == observed_with_matching_name {
                        continue;
                    }
                    match to_remove.try_insert(observed_with_matching_name.clone()) {
                        Ok(_) => {}
                        Err(err) => {
                            trace!("duplicate removal scheduled: {err:?}");
                        }
                    }
                }
            }
        }
        to_remove
            .iter()
            .map(|(_, vrf)| Request::Remove(self.request_remove(vrf)))
            .chain(
                to_create
                    .iter()
                    .map(|(_, vrf)| Request::Create(self.request_create(vrf))),
            )
            .collect()
    }
}

impl Reconcile<MultiIndexImpliedVtepMap, MultiIndexObservedVtepMap> for Handle {
    type Create = Vec<Request<Handle, ImpliedVtep, ObservedVtep>>;
    type Update = Vec<Request<Handle, ImpliedVtep, ObservedVtep>>;
    type Remove = Vec<Request<Handle, ImpliedVtep, ObservedVtep>>;

    fn request_create(&self, required: &MultiIndexImpliedVtepMap) -> Self::Create {
        required
            .iter()
            .map(|(_, vtep)| Request::Create(self.request_create(vtep)))
            .collect()
    }

    fn request_remove(&self, observed: &MultiIndexObservedVtepMap) -> Self::Remove {
        observed
            .iter()
            .map(|(_, vtep)| Request::Remove(self.request_remove(vtep)))
            .collect()
    }

    fn request_update(
        &self,
        required: &MultiIndexImpliedVtepMap,
        observed: &MultiIndexObservedVtepMap,
    ) -> Self::Update {
        let mut to_create = MultiIndexImpliedVtepMap::default();
        let mut to_remove = MultiIndexObservedVtepMap::default();
        for (_, observed) in observed.iter() {
            if required.get_by_name(&observed.name).is_none()
                || required.get_by_vni(&observed.vni).is_none()
            {
                match to_remove.try_insert(observed.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate removal scheduled: {err:?}");
                    }
                }
            }
        }
        for (_, requirement) in required.iter() {
            if let Some(observed_with_matching_name) = observed.get_by_name(&requirement.name) {
                if requirement == observed_with_matching_name {
                    continue;
                }
                match to_remove.try_insert(observed_with_matching_name.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate removal scheduled: {err:?}");
                    }
                }
            } else if let Some(observed_with_matching_vni) = observed.get_by_vni(&requirement.vni) {
                if requirement == observed_with_matching_vni {
                    continue;
                }
                match to_remove.try_insert(observed_with_matching_vni.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate removal scheduled: {err:?}");
                    }
                }
            } else {
                match to_create.try_insert(requirement.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate creation scheduled: {err:?}");
                    }
                }
            }
        }
        to_remove
            .iter()
            .map(|(_, vtep)| Request::Remove(self.request_remove(vtep)))
            .chain(
                to_create
                    .iter()
                    .map(|(_, vtep)| Request::Create(self.request_create(vtep))),
            )
            .collect()
    }
}

impl Reconcile<MultiIndexImpliedBridgeMap, MultiIndexObservedBridgeMap> for Handle {
    type Create = Vec<Request<Handle, ImpliedBridge, ObservedBridge>>;
    type Update = Vec<Request<Handle, ImpliedBridge, ObservedBridge>>;
    type Remove = Vec<Request<Handle, ImpliedBridge, ObservedBridge>>;

    fn request_create(&self, required: &MultiIndexImpliedBridgeMap) -> Self::Create {
        required
            .iter()
            .map(|(_, bridge)| Request::Create(self.request_create(bridge)))
            .collect()
    }

    fn request_remove(&self, observed: &MultiIndexObservedBridgeMap) -> Self::Remove {
        observed
            .iter()
            .map(|(_, bridge)| Request::Remove(self.request_remove(bridge)))
            .collect()
    }

    fn request_update(
        &self,
        required: &MultiIndexImpliedBridgeMap,
        observed: &MultiIndexObservedBridgeMap,
    ) -> Self::Update {
        let mut to_create = MultiIndexImpliedBridgeMap::default();
        let mut to_remove = MultiIndexObservedBridgeMap::default();
        for (_, observed) in observed.iter() {
            if required.get_by_name(&observed.name).is_none() {
                match to_remove.try_insert(observed.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate removal scheduled: {err:?}");
                    }
                }
            }
        }
        for (_, requirement) in required.iter() {
            if let Some(observed_with_matching_name) = observed.get_by_name(&requirement.name) {
                if requirement == observed_with_matching_name {
                    continue;
                }
                match to_remove.try_insert(observed_with_matching_name.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate removal scheduled: {err:?}");
                    }
                }
            } else {
                match to_create.try_insert(requirement.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("duplicate creation scheduled: {err:?}");
                    }
                }
            }
        }
        self.request_remove(&to_remove)
            .into_iter()
            .chain(self.request_create(&to_create))
            .collect()
    }
}

pub enum InterfaceOp {
    Bridge(Request<Handle, ImpliedBridge, ObservedBridge>),
    Vrf(Request<Handle, ImpliedVrf, ObservedVrf>),
    Vtep(Request<Handle, ImpliedVtep, ObservedVtep>),
    Associate(LinkStep),
}

// impl Reconcile<ImpliedInterfaceConstraint, ObservedInterfaceConstraint> for Handle {
//     type Create = Option<LinkSetRequest>;
//     type Update = Option<LinkSetRequest>;
//     type Remove = Option<LinkSetRequest>;
//
//     fn request_create(&self, required: &ImpliedInterfaceConstraint) -> Self::Create {
//         None
//     }
//
//     fn request_remove(&self, observed: &ObservedInterfaceConstraint) -> Self::Remove {
//         observed.controller_if_index.map(|_| {
//             self.link().set(
//                 LinkUnspec::new_with_name(observed.name.as_ref())
//                     .nocontroller()
//                     .down()
//                     .build(),
//             )
//         })
//     }
//
//     fn request_update(
//         &self,
//         required: &ImpliedInterfaceConstraint,
//         observed: &ObservedInterfaceConstraint,
//     ) -> Self::Update {
//         match &required.controller_name {
//             None => self.request_remove(observed),
//             Some(required_controller_name) => match &observed.controller_name {
//                 None => self.request_remove(observed),
//                 Some(observed_controller_name) => {
//                     if required_controller_name == observed_controller_name {
//                         return None;
//                     }
//                     self.link().set(LinkUnspec::new_with_name(required.name.as_ref()).controller())
//                 }
//             },
//         }
//     }
// }

pub enum LinkStep {
    Associate(LinkAddRequest),
    ChangeAdminState(LinkSetRequest),
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ScheduledConstraintAction {
    SetAdminState,
    ReAssociate,
}

impl Reconcile<MultiIndexImpliedInterfaceConstraintMap, MultiIndexObservedInterfaceConstraintMap>
    for Handle
{
    type Create = ();
    type Update = Vec<LinkStep>;
    type Remove = ();

    fn request_create(&self, _required: &MultiIndexImpliedInterfaceConstraintMap) -> Self::Create {}

    fn request_remove(&self, _observed: &MultiIndexObservedInterfaceConstraintMap) -> Self::Remove {
    }

    #[allow(clippy::too_many_lines)]
    fn request_update(
        &self,
        required: &MultiIndexImpliedInterfaceConstraintMap,
        observed: &MultiIndexObservedInterfaceConstraintMap,
    ) -> Self::Update {
        let mut plans = MultiIndexPlannedInterfaceConstraintMap::default();
        for (_, current) in observed.iter() {
            if let Some(desired) = required.get_by_name(&current.name) {
                if current == desired {
                    continue;
                }
                if current.controller_name != desired.controller_name
                    && current.admin_state == AdminState::Up
                {
                    let plan = PlannedInterfaceConstraint {
                        name: desired.name.clone(),
                        controller_name: desired.controller_name.clone(),
                        index: current.if_index,
                        controller_if_index: current.controller_if_index,
                        admin_state: AdminState::Down,
                        scheduled_action: ScheduledConstraintAction::SetAdminState,
                    };
                    match plans.try_insert(plan) {
                        Ok(_) => {}
                        Err(err) => {
                            trace!("duplicate plan scheduled: {err:?}");
                        }
                    }
                    continue;
                }
                if current.controller_name == desired.controller_name
                    && current.admin_state != desired.admin_state
                {
                    let plan = PlannedInterfaceConstraint {
                        name: desired.name.clone(),
                        controller_name: desired.controller_name.clone(),
                        index: current.if_index,
                        controller_if_index: current.controller_if_index,
                        admin_state: desired.admin_state,
                        scheduled_action: ScheduledConstraintAction::SetAdminState,
                    };
                    match plans.try_insert(plan) {
                        Ok(_) => {}
                        Err(err) => {
                            trace!("duplicate plan scheduled: {err:?}");
                        }
                    }
                    continue;
                }
                match &desired.controller_name {
                    None => {
                        let plan = PlannedInterfaceConstraint {
                            name: desired.name.clone(),
                            controller_name: None,
                            index: current.if_index,
                            controller_if_index: None,
                            admin_state: desired.admin_state,
                            scheduled_action: ScheduledConstraintAction::ReAssociate,
                        };
                        match plans.try_insert(plan) {
                            Ok(_) => {}
                            Err(err) => {
                                trace!("duplicate plan scheduled: {err:?}");
                            }
                        }
                    }
                    Some(desired_controller_name) => {
                        match observed.get_by_name(desired_controller_name) {
                            None => {
                                debug!("can't yet satisfy association");
                            }
                            Some(controller) => {
                                let plan = PlannedInterfaceConstraint {
                                    name: current.name.clone(),
                                    controller_name: desired.controller_name.clone(),
                                    controller_if_index: Some(controller.if_index),
                                    index: current.if_index,
                                    admin_state: desired.admin_state,
                                    scheduled_action: ScheduledConstraintAction::ReAssociate,
                                };
                                match plans.try_insert(plan) {
                                    Ok(_) => {}
                                    Err(err) => {
                                        trace!("duplicate plan scheduled: {err:?}");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        plans
            .iter()
            .map(|(_, step)| match step.scheduled_action {
                ScheduledConstraintAction::SetAdminState => {
                    LinkStep::ChangeAdminState(match step.admin_state {
                        AdminState::Down => self.link().set(
                            LinkUnspec::new_with_index(step.index.to_u32())
                                .down()
                                .build(),
                        ),
                        AdminState::Up => self
                            .link()
                            .set(LinkUnspec::new_with_index(step.index.to_u32()).up().build()),
                    })
                }
                ScheduledConstraintAction::ReAssociate => {
                    LinkStep::Associate(match step.controller_if_index {
                        None => self.link().set_port(
                            LinkUnspec::new_with_name(step.name.as_ref())
                                .nocontroller()
                                .build(),
                        ),
                        Some(controller_index) => self.link().set_port(
                            LinkUnspec::new_with_name(step.name.as_ref())
                                .controller(controller_index.to_u32())
                                .build(),
                        ),
                    })
                }
            })
            .collect()
    }
}

impl Reconcile<ImpliedInformationBase, ObservedInformationBase> for Handle {
    type Create = Vec<InterfaceOp>;
    type Update = Vec<InterfaceOp>;
    type Remove = Vec<InterfaceOp>;

    fn request_create(&self, required: &ImpliedInformationBase) -> Self::Create {
        self.request_create(&required.vrfs)
            .into_iter()
            .map(InterfaceOp::Vrf)
            .chain(
                self.request_create(&required.bridges)
                    .into_iter()
                    .map(InterfaceOp::Bridge),
            )
            .chain(
                self.request_create(&required.vteps)
                    .into_iter()
                    .map(InterfaceOp::Vtep),
            )
            .collect()
    }

    fn request_remove(&self, observed: &ObservedInformationBase) -> Self::Remove {
        self.request_remove(&observed.vrfs)
            .into_iter()
            .map(InterfaceOp::Vrf)
            .chain(
                self.request_remove(&observed.bridges)
                    .into_iter()
                    .map(InterfaceOp::Bridge),
            )
            .chain(
                self.request_remove(&observed.vteps)
                    .into_iter()
                    .map(InterfaceOp::Vtep),
            )
            .collect()
    }

    fn request_update(
        &self,
        required: &ImpliedInformationBase,
        observed: &ObservedInformationBase,
    ) -> Self::Update {
        self.request_update(&required.vrfs, &observed.vrfs)
            .into_iter()
            .map(InterfaceOp::Vrf)
            .chain(
                self.request_update(&required.bridges, &observed.bridges)
                    .into_iter()
                    .map(InterfaceOp::Bridge),
            )
            .chain(
                self.request_update(&required.vteps, &observed.vteps)
                    .into_iter()
                    .map(InterfaceOp::Vtep),
            )
            .chain(
                self.request_update(
                    &required.constraints.interface,
                    &observed.constraints.observed,
                )
                .into_iter()
                .map(InterfaceOp::Associate),
            )
            .collect()
    }
}

#[cfg(test)]
mod test {
    use crate::reconcile::{InterfaceOp, LinkStep, Reconcile, Request};
    use crate::resource::{
        ImpliedInformationBase, ImpliedVtep, MultiIndexObservedInterfaceConstraintMap,
        NetworkDiscriminant, ObservedInformationBase, ObservedInterface, ObservedVtep, Vpc,
    };
    use futures::StreamExt;
    use futures::TryStreamExt;
    use rtnetlink::sys::AsyncSocket;
    use tracing::{error, trace};

    #[tokio::test(flavor = "current_thread")]
    async fn biscuit() {
        let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        connection
            .socket_mut()
            .socket_mut()
            .set_rx_buf_sz(212_992)
            .unwrap();
        tokio::spawn(connection);

        let implied_vtep = ImpliedVtep {
            name: "some_vtep".try_into().unwrap(),
            vni: 18.try_into().unwrap(),
            local: "192.168.32.53".parse().unwrap(),
        };

        let observed_vtep = ObservedVtep {
            name: "some_vtep".try_into().unwrap(),
            if_index: 29.into(),
            vni: 18.try_into().unwrap(),
            local: "192.168.32.54".parse().unwrap(),
            ttl: 62,
        };

        match handle.request_reconcile(Some(&implied_vtep), Some(&observed_vtep)) {
            None => {
                println!("no requested");
            }
            Some(request) => {
                println!("requested");
                match request {
                    Request::Create(_) => {
                        println!("create");
                    }
                    Request::Update(_) => {
                        println!("update");
                    }
                    Request::Remove(_) => {
                        println!("remove");
                    }
                }
            }
        }
        match handle.request_reconcile(Some(&implied_vtep), None) {
            None => {
                println!("no requested");
            }
            Some(request) => {
                println!("requested");
                match request {
                    Request::Create(_) => {
                        println!("create");
                    }
                    Request::Update(_) => {
                        println!("update");
                    }
                    Request::Remove(_) => {
                        println!("remove");
                    }
                }
            }
        }
        match handle.request_reconcile(None, Some(&observed_vtep)) {
            None => {
                println!("no requested");
            }
            Some(request) => {
                println!("requested");
                match request {
                    Request::Create(x) => {
                        println!("create");
                    }
                    Request::Update(y) => {
                        println!("update");
                    }
                    Request::Remove(z) => {
                        println!("remove");
                    }
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn potato() {
        let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        connection
            .socket_mut()
            .socket_mut()
            .set_rx_buf_sz(212_992)
            .unwrap();
        tokio::spawn(connection);

        let vpcs = [
            Vpc::new(
                18.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 18.try_into().unwrap(),
                },
            ),
            Vpc::new(
                28.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 28.try_into().unwrap(),
                },
            ),
            Vpc::new(
                38.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 38.try_into().unwrap(),
                },
            ),
            Vpc::new(
                48.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 48.try_into().unwrap(),
                },
            ),
        ];

        let mut ib = ImpliedInformationBase::default();

        for vpc in vpcs {
            ib.try_add_vpc(&vpc);
        }

        loop {
            let mut ob = ObservedInformationBase::default();

            for message in handle
                .link()
                .get()
                .execute()
                .try_ready_chunks(1024)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .flatten()
                .flatten()
                .collect::<Vec<_>>()
            {
                if let Ok(interface) = ObservedInterface::try_from(message) {
                    ob.try_add_interface(interface).unwrap();
                }
            }

            let actions = handle.request_reconcile(Some(&ib.vrfs), Some(&ob.vrfs));

            match actions {
                None => {
                    println!("no actions");
                    break;
                }
                Some(actions) => match actions {
                    Request::Create(create) => {
                        println!("c");
                    }
                    Request::Update(update) => {
                        println!("u");
                        for update in update {
                            match update {
                                Request::Update(x) | Request::Create(x) => {
                                    x.execute().await.unwrap();
                                }
                                Request::Remove(x) => {
                                    x.execute().await.unwrap();
                                }
                            }
                        }
                    }
                    Request::Remove(remove) => {
                        println!("r");
                    }
                },
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "current_thread")]
    async fn cheese() {
        let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        connection
            .socket_mut()
            .socket_mut()
            .set_rx_buf_sz(812_992)
            .unwrap();
        tokio::spawn(connection);

        let vpcs = [
            Vpc::new(
                18.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 18.try_into().unwrap(),
                },
            ),
            Vpc::new(
                28.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 28.try_into().unwrap(),
                },
            ),
            Vpc::new(
                38.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 38.try_into().unwrap(),
                },
            ),
            Vpc::new(
                48.into(),
                NetworkDiscriminant::EvpnVxlan {
                    vni: 48.try_into().unwrap(),
                },
            ),
        ];
        let mut ib = ImpliedInformationBase::default();

        for vpc in vpcs {
            ib.try_add_vpc(&vpc);
        }

        loop {
            let mut ob = ObservedInformationBase::default();

            for message in handle
                .link()
                .get()
                .execute()
                .try_ready_chunks(1024)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .flatten()
                .flatten()
            {
                if let Ok(interface) = ObservedInterface::try_from(message) {
                    ob.try_add_interface(interface).unwrap();
                }
            }
            let x = MultiIndexObservedInterfaceConstraintMap::get(&handle).await;
            for (_, association) in x.iter() {
                match ob.try_add_association(association.clone()) {
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("{err:?}");
                    }
                }
            }
            let Some(actions) = handle.request_reconcile(Some(&ib), Some(&ob)) else {
                tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;
                continue;
            };
            let mut removes = vec![];
            let mut updates = vec![];
            let mut creates = vec![];
            let mut associates = vec![];

            match actions {
                Request::Create(x) | Request::Remove(x) | Request::Update(x) => {
                    x.into_iter().for_each(|y| match y {
                        InterfaceOp::Bridge(z) => match z {
                            Request::Create(z) => creates.push(z),
                            Request::Update(z) => updates.push(z),
                            Request::Remove(z) => removes.push(z),
                        },
                        InterfaceOp::Vrf(z) => match z {
                            Request::Create(z) => creates.push(z),
                            Request::Update(z) => updates.push(z),
                            Request::Remove(z) => removes.push(z),
                        },
                        InterfaceOp::Vtep(z) => match z {
                            Request::Create(z) => creates.push(z),
                            Request::Update(z) => updates.push(z),
                            Request::Remove(z) => removes.push(z),
                        },
                        InterfaceOp::Associate(z) => associates.push(z),
                    });
                }
            }

            if removes.is_empty()
                && updates.is_empty()
                && creates.is_empty()
                && associates.is_empty()
            {
                tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;
                continue;
            }
            let mut tasks = tokio::task::JoinSet::new();

            for x in removes {
                tasks.spawn(x.execute());
            }
            for x in updates {
                tasks.spawn(x.execute());
            }
            for x in creates {
                tasks.spawn(x.execute());
            }
            for x in associates {
                match x {
                    LinkStep::ChangeAdminState(req) => {
                        tasks.spawn(req.execute());
                    }
                    LinkStep::Associate(req) => {
                        tasks.spawn(req.execute());
                    }
                }
            }
            while let Some(task) = tasks.join_next().await {
                match task {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        trace!("{err:?}");
                    }
                    Err(err) => {
                        error!("{err:?}");
                    }
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(225)).await;
        }
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test(flavor = "current_thread")]
    async fn cheese2() {
        let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };

        connection
            .socket_mut()
            .socket_mut()
            .set_rx_buf_sz(212_992)
            .unwrap();
        tokio::spawn(connection);
        let x = MultiIndexObservedInterfaceConstraintMap::get(&handle).await;
        println!("{x:?}");
    }
}
