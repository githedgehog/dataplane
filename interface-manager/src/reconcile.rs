// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{
    ImpliedBridge, ImpliedInformationBase, ImpliedVrf, ImpliedVtep, InformationBase,
    MultiIndexImpliedBridgeMap, MultiIndexImpliedVrfMap, MultiIndexImpliedVtepMap,
    MultiIndexObservedBridgeMap, MultiIndexObservedVrfMap, MultiIndexObservedVtepMap,
    ObservedBridge, ObservedInformationBase, ObservedVrf, ObservedVtep,
};
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo};
use rtnetlink::{Handle, LinkAddRequest, LinkBridge, LinkDelRequest, LinkVrf, LinkVxlan};

pub enum Request<T: Reconcile> {
    Create(<T as Reconcile>::RequestCreate),
    Update(<T as Reconcile>::RequestUpdate),
    Remove(<T as Reconcile>::RequestRemove),
}

pub trait Reconcile: Sized {
    type RequestCreate;
    type RequestUpdate;
    type Observed;

    fn request_create(&self) -> Self::RequestCreate;
    fn request_update(&self, observed: &Self::Observed) -> Self::RequestUpdate;
    fn request_reconcile(&self, observed: Option<&Self::Observed>) -> Request<Self> {
        match observed {
            Some(observed) => Request::Update(self.request_update(observed)),
            None => Request::Create(self.request_create()),
        }
    }
}

pub struct VtepInterface<'a> {
    objective: &'a ImpliedVtep,
    handle: &'a Handle,
}

pub struct VrfInterface<'a> {
    objective: &'a ImpliedVrf,
    handle: &'a Handle,
}

pub struct BridgeInterface<'a> {
    objective: &'a ImpliedBridge,
    handle: &'a Handle,
}

pub trait Remove {
    type RequestRemove;
    fn schedule_remove(&self, handle: &Handle) -> Self::RequestRemove;
}

impl Remove for ObservedVtep {
    type RequestRemove = LinkDelRequest;
    fn schedule_remove(&self, handle: &Handle) -> Self::RequestRemove {
        handle.link().del(self.if_index.to_u32())
    }
}

impl Remove for ObservedVrf {
    type RequestRemove = LinkDelRequest;

    fn schedule_remove(&self, handle: &Handle) -> Self::RequestRemove {
        handle.link().del(self.if_index.to_u32())
    }
}

impl Remove for ObservedBridge {
    type RequestRemove = LinkDelRequest;

    fn schedule_remove(&self, handle: &Handle) -> Self::RequestRemove {
        handle.link().del(self.if_index.to_u32())
    }
}

impl Reconcile for VtepInterface<'_> {
    type RequestCreate = LinkAddRequest;
    type RequestUpdate = LinkAddRequest;
    type Observed = ObservedVtep;

    fn request_create(&self) -> Self::RequestCreate {
        self.handle.link().add(
            LinkVxlan::new(self.objective.name.as_ref(), self.objective.vni.as_u32())
                .local(self.objective.local)
                .build(),
        )
    }

    fn request_update(&self, _observed: &Self::Observed) -> Self::RequestUpdate {
        self.request_create().replace()
    }
}

impl Reconcile for VrfInterface<'_> {
    type RequestCreate = LinkAddRequest;
    type RequestUpdate = LinkAddRequest;
    type Observed = ObservedVrf;

    fn request_create(&self) -> Self::RequestCreate {
        self.handle.link().add(
            LinkVrf::new(
                self.objective.name.as_ref(),
                self.objective.route_table.into(),
            )
            .build(),
        )
    }

    fn request_update(&self, observed: &Self::Observed) -> LinkAddRequest {
        let mut message = LinkVrf::new(
            self.objective.name.as_ref(),
            self.objective.route_table.into(),
        )
        .build();
        message.header.index = observed.if_index.into();
        self.handle.link().add(message).replace()
    }
}

impl Reconcile for BridgeInterface<'_> {
    type RequestCreate = LinkAddRequest;
    type RequestUpdate = LinkAddRequest;
    type Observed = ObservedBridge;

    fn request_create(&self) -> Self::RequestCreate {
        self.handle.link().add(
            LinkBridge::new(self.objective.name.as_ref())
                .append_extra_attribute(LinkAttribute::LinkInfo(vec![LinkInfo::Data(
                    InfoData::Bridge(vec![
                        InfoBridge::VlanFiltering(self.objective.vlan_filtering),
                        InfoBridge::VlanProtocol(self.objective.vlan_protocol.as_u16()),
                    ]),
                )]))
                .build(),
        )
    }

    fn request_update(&self, observed: &Self::Observed) -> Self::RequestUpdate {
        let mut message = LinkBridge::new(self.objective.name.as_ref())
            .append_extra_attribute(LinkAttribute::LinkInfo(vec![LinkInfo::Data(
                InfoData::Bridge(vec![
                    InfoBridge::VlanFiltering(self.objective.vlan_filtering),
                    InfoBridge::VlanProtocol(self.objective.vlan_protocol.as_u16()),
                ]),
            )]))
            .build();
        message.header.index = observed.if_index.into();
        self.handle.link().add(message).replace()
    }
}

pub enum Objective<'a, T>
where
    T: Reconcile,
    T::Observed: Remove,
{
    Create(&'a T),
    Remove(&'a T::Observed),
    Update(&'a T, &'a T::Observed),
}

pub struct NetlinkSync<'a, T>
where
    T: Reconcile,
    T::Observed: Remove,
{
    handle: &'a Handle,
    objective: Objective<'a, T>,
}

impl<'a> Reconcile for NetlinkSync<'a, Objective> {}

pub struct VrfSync<'a> {
    vrfs: &'a MultiIndexImpliedVrfMap,
    handle: &'a Handle,
}

impl MultiIndexImpliedVrfMap {
    fn with<'a>(&'a self, handle: &'a Handle) -> VrfSync<'a> {
        VrfSync { vrfs: self, handle }
    }
}

impl<'a> VrfSync<'a> {
    fn reconcile_request(
        &'a self,
        observed: &'a MultiIndexObservedVrfMap,
    ) -> impl Iterator<Item = LinkAddRequest> + use<'a> {
        self.vrfs.iter().map(|(_, objective)| {
            let interface = VrfInterface {
                objective,
                handle: self.handle,
            };
            match observed.get_by_name(&objective.name) {
                None => interface.request_create(),
                Some(observed) => interface.request_update(observed),
            }
        })
    }
}

pub struct BridgeSync<'a> {
    bridges: &'a MultiIndexImpliedBridgeMap,
    handle: &'a Handle,
}

impl MultiIndexImpliedBridgeMap {
    fn with<'a>(&'a self, handle: &'a Handle) -> BridgeSync<'a> {
        BridgeSync {
            bridges: self,
            handle,
        }
    }
}

impl<'a> BridgeSync<'a> {
    fn reconcile_request(
        &'a self,
        observed: &'a MultiIndexObservedBridgeMap,
    ) -> impl Iterator<Item = LinkAddRequest> + use<'a> {
        self.bridges.iter().map(|(_, objective)| {
            let interface = BridgeInterface {
                objective,
                handle: self.handle,
            };
            match observed.get_by_name(&objective.name) {
                None => interface.request_create(),
                Some(observed) => interface.request_update(observed),
            }
        })
    }
}

pub struct VtepSync<'a> {
    vteps: &'a MultiIndexImpliedVtepMap,
    handle: &'a Handle,
}

impl MultiIndexImpliedVtepMap {
    fn with<'a>(&'a self, handle: &'a Handle) -> VtepSync<'a> {
        VtepSync {
            vteps: self,
            handle,
        }
    }
}

impl<'a> VtepSync<'a> {
    fn reconcile_request(
        &'a self,
        observed: &'a MultiIndexObservedVtepMap,
    ) -> impl Iterator<Item = LinkAddRequest> + use<'a> {
        self.vteps.iter().map(|(_, objective)| {
            let interface = VtepInterface {
                objective,
                handle: self.handle,
            };
            match observed.get_by_name(&objective.name) {
                None => interface.request_create(),
                Some(observed) => interface.request_update(observed),
            }
        })
    }
}

pub struct ImpliedInformationBaseSync<'a> {
    ib: &'a ImpliedInformationBase,
    handle: &'a Handle,
}

impl ImpliedInformationBase {
    fn with<'a>(&'a self, handle: &'a Handle) -> ImpliedInformationBaseSync<'a> {
        ImpliedInformationBaseSync { ib: self, handle }
    }
}

impl<'a> ImpliedInformationBaseSync<'a> {
    fn reconcile_request(&'a self, observed: &'a ObservedInformationBase) -> Vec<LinkAddRequest> {
        let vrfs = self.ib.vrfs.with(self.handle);
        let bridges = self.ib.bridges.with(self.handle);
        let vteps = self.ib.vteps.with(self.handle);
        vrfs.reconcile_request(&observed.vrfs)
            .chain(bridges.reconcile_request(&observed.bridges))
            .chain(vteps.reconcile_request(&observed.vteps))
            .collect()
    }
}

pub struct InformationBaseSync<'a> {
    ib: &'a InformationBase,
    handle: &'a Handle,
}

impl InformationBase {
    fn with<'a>(&'a self, handle: &'a Handle) -> InformationBaseSync<'a> {
        InformationBaseSync { ib: self, handle }
    }
}

impl<'a> InformationBaseSync<'a> {
    fn reconcile_request(&'a self) -> Vec<LinkAddRequest> {
        self.ib
            .implied
            .with(self.handle)
            .reconcile_request(&self.ib.observed)
    }
}
