// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{
    ImpliedBridge, ImpliedVrf, ImpliedVtep, MultiIndexImpliedVrfMap, ObservedBridge, ObservedVrf,
    ObservedVtep,
};
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo};
use rtnetlink::{Handle, LinkAddRequest, LinkBridge, LinkDelRequest, LinkVrf, LinkVxlan};

pub enum Request<T: Reconcile<Required, Observed>, Required, Observed> {
    Create(<T as Reconcile<Required, Observed>>::Create),
    Update(<T as Reconcile<Required, Observed>>::Update),
    Remove(<T as Reconcile<Required, Observed>>::Remove),
}

pub trait Reconcile<Required, Observed: Into<Required>>: Sized {
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

#[cfg(test)]
mod test {
    use crate::reconcile::{Reconcile, Request};
    use crate::resource::{ImpliedVtep, ObservedVtep};
    use rtnetlink::sys::AsyncSocket;

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
            local: "192.168.32.53".parse().unwrap(),
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
    }
}
