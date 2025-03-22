// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{
    ImpliedBridge, ImpliedInformationBase, ImpliedVrf, ImpliedVtep, MultiIndexImpliedBridgeMap,
    MultiIndexImpliedVrfMap, MultiIndexImpliedVtepMap, MultiIndexObservedBridgeMap,
    MultiIndexObservedVrfMap, MultiIndexObservedVtepMap, ObservedBridge, ObservedInformationBase,
    ObservedVrf, ObservedVtep,
};
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo};
use rtnetlink::{Handle, LinkAddRequest, LinkBridge, LinkDelRequest, LinkVrf, LinkVxlan};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, trace};

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
        self.link().del(observed.if_index.to_u32())
    }

    fn request_update(&self, required: &ImpliedVrf, observed: &ObservedVrf) -> Self::Update {
        let mut message = LinkVrf::new(required.name.as_ref(), required.route_table.into()).build();
        message.header.index = observed.if_index.into();
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
            .collect()
    }
}

// impl Reconcile<MultiIndexImpliedVtepMap, MultiIndexObservedVtepMap> for Handle {
//     type Create = Vec<Request<Handle, ImpliedVtep, ObservedVtep>>;
//     type Update = Vec<Request<Handle, ImpliedVtep, ObservedVtep>>;
//     type Remove = Vec<Request<Handle, ImpliedVtep, ObservedVtep>>;
//
//     fn request_create(&self, required: &MultiIndexImpliedVtepMap) -> Self::Create {
//         required
//             .iter()
//             .map(|(_, vrf)| Request::Create(self.request_create(vrf)))
//             .collect()
//     }
//
//     fn request_remove(&self, observed: &MultiIndexObservedVtepMap) -> Self::Remove {
//         observed
//             .iter()
//             .map(|(_, vrf)| Request::Remove(self.request_remove(vrf)))
//             .collect()
//     }
//
//     fn request_update(
//         &self,
//         required: &MultiIndexImpliedVrfMap,
//         observed: &MultiIndexObservedVrfMap,
//     ) -> Self::Update {
//         let mut updates = vec![];
//         for implied in required.iter_by_route_table() {
//             let with_matching_route_table = observed.get_by_route_table(&implied.route_table);
//             let with_matching_name = observed.get_by_name(&implied.name);
//             if let Some(with_matching_name) = with_matching_name {
//                 for with_matching_route_table in with_matching_route_table {
//                     if with_matching_name != with_matching_route_table {
//                         updates.push(Request::Remove(
//                             self.request_remove(with_matching_route_table),
//                         ));
//                     }
//                 }
//                 if implied != with_matching_name {
//                     updates.push(Request::Remove(self.request_remove(with_matching_name)));
//                 }
//             } else if with_matching_route_table.is_empty() {
//                 updates.push(Request::Create(self.request_create(implied)));
//             } else {
//                 for matching in with_matching_route_table {
//                     updates.push(Request::Remove(self.request_remove(matching)));
//                 }
//             }
//         }
//         updates
//     }
// }

pub struct VrfSync<'a> {
    vrfs: &'a MultiIndexImpliedVrfMap,
    handle: &'a Handle,
}

impl MultiIndexImpliedVrfMap {
    fn with<'a>(&'a self, handle: &'a Handle) -> VrfSync<'a> {
        VrfSync { vrfs: self, handle }
    }
}

// impl<'a> VrfSync<'a> {
//     fn reconcile_request(
//         &'a self,
//         observed: &'a MultiIndexObservedVrfMap,
//     ) -> impl Iterator<Item = LinkAddRequest> + use<'a> {
//         self.vrfs.iter().map(|(_, objective)| {
//             let interface = VrfInterface {
//                 objective,
//                 handle: self.handle,
//             };
//             match observed.get_by_name(&objective.name) {
//                 None => interface.request_create(),
//                 Some(observed) => interface.request_update(observed),
//             }
//         })
//     }
// }
//
// pub struct BridgeSync<'a> {
//     bridges: &'a MultiIndexImpliedBridgeMap,
//     handle: &'a Handle,
// }
//
// impl MultiIndexImpliedBridgeMap {
//     fn with<'a>(&'a self, handle: &'a Handle) -> BridgeSync<'a> {
//         BridgeSync {
//             bridges: self,
//             handle,
//         }
//     }
// }
//
// impl<'a> BridgeSync<'a> {
//     fn reconcile_request(
//         &'a self,
//         observed: &'a MultiIndexObservedBridgeMap,
//     ) -> impl Iterator<Item = LinkAddRequest> + use<'a> {
//         self.bridges.iter().map(|(_, objective)| {
//             let interface = BridgeInterface {
//                 objective,
//                 handle: self.handle,
//             };
//             match observed.get_by_name(&objective.name) {
//                 None => interface.request_create(),
//                 Some(observed) => interface.request_update(observed),
//             }
//         })
//     }
// }
//
// pub struct VtepSync<'a> {
//     vteps: &'a MultiIndexImpliedVtepMap,
//     handle: &'a Handle,
// }
//
// impl MultiIndexImpliedVtepMap {
//     fn with<'a>(&'a self, handle: &'a Handle) -> VtepSync<'a> {
//         VtepSync {
//             vteps: self,
//             handle,
//         }
//     }
// }
//
// impl<'a> VtepSync<'a> {
//     fn reconcile_request(
//         &'a self,
//         observed: &'a MultiIndexObservedVtepMap,
//     ) -> impl Iterator<Item = LinkAddRequest> + use<'a> {
//         self.vteps.iter().map(|(_, objective)| {
//             let interface = VtepInterface {
//                 objective,
//                 handle: self.handle,
//             };
//             match observed.get_by_name(&objective.name) {
//                 None => interface.request_create(),
//                 Some(observed) => interface.request_update(observed),
//             }
//         })
//     }
// }
//
// pub struct ImpliedInformationBaseSync<'a> {
//     ib: &'a ImpliedInformationBase,
//     handle: &'a Handle,
// }
//
// impl ImpliedInformationBase {
//     fn with<'a>(&'a self, handle: &'a Handle) -> ImpliedInformationBaseSync<'a> {
//         ImpliedInformationBaseSync { ib: self, handle }
//     }
// }
//
// impl<'a> ImpliedInformationBaseSync<'a> {
//     fn reconcile_request(&'a self, observed: &'a ObservedInformationBase) -> Vec<LinkAddRequest> {
//         let vrfs = self.ib.vrfs.with(self.handle);
//         let bridges = self.ib.bridges.with(self.handle);
//         let vteps = self.ib.vteps.with(self.handle);
//         vrfs.reconcile_request(&observed.vrfs)
//             .chain(bridges.reconcile_request(&observed.bridges))
//             .chain(vteps.reconcile_request(&observed.vteps))
//             .collect()
//     }
// }
//
// pub struct InformationBaseSync<'a> {
//     ib: &'a InformationBase,
//     handle: &'a Handle,
// }
//
// impl InformationBase {
//     fn with<'a>(&'a self, handle: &'a Handle) -> InformationBaseSync<'a> {
//         InformationBaseSync { ib: self, handle }
//     }
// }
//
// impl<'a> InformationBaseSync<'a> {
//     fn reconcile_request(&'a self) -> Vec<LinkAddRequest> {
//         self.ib
//             .implied
//             .with(self.handle)
//             .reconcile_request(&self.ib.observed)
//     }
// }

// impl Reconcile<ObservedInformationBase> for ImpliedInformationBase {
//     type Create = ();
//     type Update = ();
//     type Remove = ();
//
//     fn request_create(&self, required: &ObservedInformationBase) -> Self::Create {
//         todo!()
//     }
//
//     fn request_remove(&self, observed: &Observed) -> Self::Remove {
//         todo!()
//     }
//
//     fn request_update(&self, required: &ObservedInformationBase, observed: &Observed) -> Self::Update {
//         todo!()
//     }
// }

#[cfg(test)]
mod test {
    use crate::reconcile::{InterfaceOp, Reconcile, Request};
    use crate::resource::{
        ImpliedInformationBase, ImpliedVtep, MultiIndexObservedInterfaceConstraintMap,
        NetworkDiscriminant, ObservedInformationBase, ObservedInterface, ObservedVtep, Vpc,
    };
    use futures::StreamExt;
    use futures::TryStreamExt;
    use rtnetlink::sys::AsyncSocket;
    use tracing::trace;

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
            if_index: 29.try_into().unwrap(),
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
        match handle.request_reconcile(Some(&implied_vtep), None) {
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
            let Some(actions) = handle.request_reconcile(Some(&ib), Some(&ob)) else {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                continue;
            };
            let mut removes = vec![];
            let mut updates = vec![];
            let mut creates = vec![];

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
                    });
                }
            }

            if removes.is_empty() && updates.is_empty() && creates.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
            for remove in removes {
                match remove.execute().await {
                    Ok(()) => {}
                    Err(err) => trace!("{err:?}"),
                }
            }
            for update in updates {
                match update.execute().await {
                    Ok(()) => {}
                    Err(err) => trace!("{err:?}"),
                }
            }
            for create in creates {
                match create.execute().await {
                    Ok(()) => {}
                    Err(err) => trace!("{err:?}"),
                }
            }
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
