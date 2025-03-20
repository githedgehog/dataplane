// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::IllegalInterfaceName;
use crate::resource::{
    ImpliedBridge, ImpliedVrf, ImpliedVtep, ObservedBridge, ObservedVrf, ObservedVtep,
};
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo, LinkMessage};
use rtnetlink::{
    Handle, LinkAddRequest, LinkBridge, LinkDelRequest, LinkSetRequest, LinkVrf, LinkVxlan,
};

pub enum Request<T: Reconcile> {
    Create(<T as Reconcile>::RequestCreate),
    Update(<T as Reconcile>::RequestUpdate),
}

trait Reconcile: Sized {
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
    fn request_remove(&self, handle: &Handle) -> Self::RequestRemove;
}

impl Remove for ObservedVtep {
    type RequestRemove = LinkDelRequest;
    fn request_remove(&self, handle: &Handle) -> Self::RequestRemove {
        handle.link().del(self.if_index.to_u32())
    }
}

impl Remove for ObservedVrf {
    type RequestRemove = LinkDelRequest;

    fn request_remove(&self, handle: &Handle) -> Self::RequestRemove {
        handle.link().del(self.if_index.to_u32())
    }
}

impl Remove for ObservedBridge {
    type RequestRemove = LinkDelRequest;

    fn request_remove(&self, handle: &Handle) -> Self::RequestRemove {
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
    type Observed = ObservedVtep;

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
