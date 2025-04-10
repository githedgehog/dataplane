// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use futures::TryStreamExt;
use id::Id;
use interface_manager::Manager;
use interface_manager::interface::{
    MultiIndexInterfaceAssociationSpecMap, MultiIndexInterfaceSpecMap,
    MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap,
};
use multi_index_map::MultiIndexMap;
use net::interface::{
    Interface, InterfaceProperties, MultiIndexInterfaceMap, MultiIndexVrfPropertiesMap,
    MultiIndexVtepPropertiesMap,
};
use net::route::RouteTableId;
use net::vxlan::Vni;
use rekon::{Observe, Op, Reconcile, Remove};
use rtnetlink::Handle;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::sync::Arc;
use tracing::error;

#[derive(Clone, Debug)]
pub struct VpcManager<R> {
    handle: Arc<Handle>,
    _marker: PhantomData<R>,
}

impl<R> VpcManager<R> {
    fn new(handle: Arc<Handle>) -> Self {
        VpcManager {
            handle,
            _marker: PhantomData,
        }
    }
}

impl<T, U> From<&VpcManager<T>> for VpcManager<U> {
    fn from(handle: &VpcManager<T>) -> Self {
        Self::new(handle.handle.clone())
    }
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
    discriminant: VpcDiscriminant,
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum VpcDiscriminant {
    EvpnVxlan { vni: Vni },
}

impl From<Vni> for VpcDiscriminant {
    fn from(value: Vni) -> Self {
        VpcDiscriminant::EvpnVxlan { vni: value }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, Builder)]
pub struct RequiredInformationBase {
    pub(crate) interfaces: MultiIndexInterfaceSpecMap,
    pub(crate) vrfs: MultiIndexVrfPropertiesSpecMap,
    pub(crate) vteps: MultiIndexVtepPropertiesSpecMap,
    pub(crate) associations: MultiIndexInterfaceAssociationSpecMap,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, Builder)]
pub struct ObservedInformationBase {
    pub(crate) interfaces: MultiIndexInterfaceMap,
    pub(crate) vrfs: MultiIndexVrfPropertiesMap,
    pub(crate) vteps: MultiIndexVtepPropertiesMap,
}

impl Observe for VpcManager<RequiredInformationBase> {
    type Observation<'a>
        = Result<ObservedInformationBase, ObservedInformationBaseBuilderError>
    where
        Self: 'a;

    async fn observe<'a>(&self) -> Self::Observation<'a>
    where
        Self: 'a,
    {
        let mut ob = ObservedInformationBaseBuilder::default();
        let mut observations = MultiIndexInterfaceMap::with_capacity(128);
        let mut req = self.handle.link().get().execute();
        while let Ok(Some(message)) = req.try_next().await {
            match Interface::try_from(message) {
                Ok(interface) => match observations.try_insert(interface) {
                    Ok(_) => {}
                    Err(uniqueness_error) => {
                        error!("{uniqueness_error:?}");
                    }
                },
                Err(err) => {
                    error!("{err:?}");
                }
            }
        }
        let mut vtep_properties = MultiIndexVtepPropertiesMap::default();
        let mut vrf_properties = MultiIndexVrfPropertiesMap::default();
        let mut indexes_to_remove = vec![];
        for (_, observation) in observations.iter() {
            match &observation.properties {
                InterfaceProperties::Vtep(properties) => {
                    match vtep_properties.try_insert(properties.clone()) {
                        Ok(_) => {}
                        Err(err) => {
                            error!("{err:?}");
                            indexes_to_remove.push(observation.index);
                        }
                    }
                }
                InterfaceProperties::Vrf(properties) => {
                    match vrf_properties.try_insert(properties.clone()) {
                        Ok(_) => {}
                        Err(err) => {
                            error!("{err:?}");
                            indexes_to_remove.push(observation.index);
                        }
                    }
                }
                InterfaceProperties::Other | InterfaceProperties::Bridge(_) => {
                    /* nothing to index */
                }
            }
        }
        for sliced in indexes_to_remove {
            observations.remove_by_index(&sliced);
        }
        match ob
            .interfaces(observations)
            .vteps(vtep_properties)
            .vrfs(vrf_properties)
            .build()
        {
            Ok(ob) => Ok(ob),
            Err(err) => {
                error!("{err:?}");
                Err(err)
            }
        }
    }
}

impl Reconcile for VpcManager<RequiredInformationBase> {
    type Requirement<'a>
        = &'a mut RequiredInformationBase
    where
        Self: 'a;
    type Observation<'a>
        = &'a ObservedInformationBase
    where
        Self: 'a;
    type Outcome<'a>
        = ()
    where
        Self: 'a;

    async fn reconcile<'a>(
        &self,
        requirement: &'a mut RequiredInformationBase,
        observation: &'a ObservedInformationBase,
    ) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        let iface_handle = Manager::<Interface>::new(self.handle.clone());
        // reconciling the extant interfaces as much as possible
        for (_, interface) in observation.interfaces.iter() {
            match requirement.interfaces.get_by_name(&interface.name) {
                None => match interface.properties {
                    InterfaceProperties::Other => {}
                    _ => match iface_handle.remove(interface).await {
                        Ok(()) => {}
                        Err(err) => error!("{err:?}"),
                    },
                },
                Some(requirement) => {
                    if let Some(
                        Op::Create(Err(err)) | Op::Update(Err(err)) | Op::Remove(Err(err)),
                    ) = iface_handle.reconcile(requirement, Some(interface)).await
                    {
                        error!("{err:?}");
                    }
                }
            }
        }
        // go through the requirement list and create anything missing (and reconcile anything out
        // of sync)
        for (_, interface) in requirement.interfaces.iter() {
            if let Some(Op::Create(Err(err)) | Op::Update(Err(err)) | Op::Remove(Err(err))) =
                iface_handle
                    .reconcile(
                        interface,
                        observation.interfaces.get_by_name(&interface.name),
                    )
                    .await
            {
                error!("{err:?}");
            }
        }

        // update the requirements to reflect which interfaces can be associated with which
        for (_, association) in requirement.associations.iter() {
            requirement
                .interfaces
                .update_by_name(&association.name, |_, _, controller, _| {
                    *controller =
                        association
                            .controller_name
                            .as_ref()
                            .and_then(|controller_name| {
                                observation
                                    .interfaces
                                    .get_by_name(controller_name)
                                    .map(|controller| controller.index)
                            });
                });
        }
    }
}

impl Vpc {
    #[must_use]
    pub fn new(route_table: RouteTableId, discriminant: VpcDiscriminant) -> Self {
        Self {
            id: Id::new(),
            route_table,
            discriminant,
        }
    }

    #[must_use]
    pub fn route_table(&self) -> RouteTableId {
        self.route_table
    }

    #[must_use]
    pub fn discriminant(&self) -> VpcDiscriminant {
        self.discriminant
    }
}

#[cfg(test)]
mod tests {
    use crate::{RequiredInformationBase, RequiredInformationBaseBuilder, VpcManager};
    use interface_manager::interface::{
        BridgePropertiesSpec, InterfaceAssociationSpec, InterfacePropertiesSpec,
        InterfaceSpecBuilder, MultiIndexBridgePropertiesSpecMap,
        MultiIndexInterfaceAssociationSpecMap, MultiIndexInterfaceSpecMap,
        MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap, VrfPropertiesSpec,
        VtepPropertiesSpec,
    };
    use net::eth::ethtype::EthType;
    use net::interface::AdminState;
    use rekon::{Observe, Reconcile};
    use rtnetlink::sys::AsyncSocket;
    use std::sync::Arc;
    use std::time::Duration;

    #[allow(clippy::too_many_lines)] // TEMPORARY: DO NOT MERGE
    #[tokio::test]
    async fn reconcile_test() {
        let mut required_interface_map = MultiIndexInterfaceSpecMap::default();
        let interfaces = [
            InterfaceSpecBuilder::default()
                .name("vrf1".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Vrf(VrfPropertiesSpec {
                    route_table_id: 1.into(),
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("vrf2".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Vrf(VrfPropertiesSpec {
                    route_table_id: 2.into(),
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("vtep1".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Vtep(VtepPropertiesSpec {
                    vni: 1.try_into().unwrap(),
                    local: "192.168.5.155".parse().unwrap(),
                    ttl: 64,
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("vtep2".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Vtep(VtepPropertiesSpec {
                    vni: 2.try_into().unwrap(),
                    local: "192.168.5.155".parse().unwrap(),
                    ttl: 64,
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("br1".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                    vlan_protocol: EthType::VLAN,
                    vlan_filtering: false,
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("br2".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                    vlan_protocol: EthType::VLAN,
                    vlan_filtering: false,
                }))
                .build()
                .unwrap(),
        ];

        for interface in interfaces {
            required_interface_map.try_insert(interface).unwrap();
        }

        let mut vtep_props = MultiIndexVtepPropertiesSpecMap::default();
        let mut bridge_props = MultiIndexBridgePropertiesSpecMap::default();
        let mut vrf_props = MultiIndexVrfPropertiesSpecMap::default();

        for (_, interface) in required_interface_map.iter() {
            match &interface.properties {
                InterfacePropertiesSpec::Vtep(prop) => {
                    vtep_props.try_insert(prop.clone()).unwrap();
                }
                InterfacePropertiesSpec::Bridge(prop) => {
                    bridge_props.try_insert(prop.clone()).unwrap();
                }
                InterfacePropertiesSpec::Vrf(prop) => {
                    vrf_props.try_insert(prop.clone()).unwrap();
                }
            }
        }

        let mut associations = MultiIndexInterfaceAssociationSpecMap::default();
        associations
            .try_insert(InterfaceAssociationSpec {
                name: "vtep1".to_string().try_into().unwrap(),
                controller_name: Some("br1".to_string().try_into().unwrap()),
            })
            .unwrap();
        associations
            .try_insert(InterfaceAssociationSpec {
                name: "vtep2".to_string().try_into().unwrap(),
                controller_name: Some("br2".to_string().try_into().unwrap()),
            })
            .unwrap();
        associations
            .try_insert(InterfaceAssociationSpec {
                name: "br1".to_string().try_into().unwrap(),
                controller_name: Some("vrf1".to_string().try_into().unwrap()),
            })
            .unwrap();
        associations
            .try_insert(InterfaceAssociationSpec {
                name: "br2".to_string().try_into().unwrap(),
                controller_name: Some("vrf2".to_string().try_into().unwrap()),
            })
            .unwrap();

        let mut required = RequiredInformationBaseBuilder::default()
            .interfaces(required_interface_map)
            .vteps(vtep_props)
            .vrfs(vrf_props)
            .associations(associations)
            .build()
            .unwrap();

        let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        connection
            .socket_mut()
            .socket_mut()
            .set_rx_buf_sz(812_992)
            .unwrap();
        tokio::spawn(connection);

        let inject_new_requirements = move |req: &mut RequiredInformationBase| {
            let interfaces = [
                InterfaceSpecBuilder::default()
                    .name("vrf3".try_into().unwrap())
                    .admin_state(AdminState::Up)
                    .controller(None)
                    .properties(InterfacePropertiesSpec::Vrf(VrfPropertiesSpec {
                        route_table_id: 3.into(),
                    }))
                    .build()
                    .unwrap(),
                InterfaceSpecBuilder::default()
                    .name("vtep3".try_into().unwrap())
                    .admin_state(AdminState::Up)
                    .controller(None)
                    .properties(InterfacePropertiesSpec::Vtep(VtepPropertiesSpec {
                        vni: 3.try_into().unwrap(),
                        local: "192.168.5.155".parse().unwrap(),
                        ttl: 64,
                    }))
                    .build()
                    .unwrap(),
                InterfaceSpecBuilder::default()
                    .name("br3".try_into().unwrap())
                    .admin_state(AdminState::Up)
                    .controller(None)
                    .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                        vlan_protocol: EthType::VLAN,
                        vlan_filtering: false,
                    }))
                    .build()
                    .unwrap(),
            ];
            for interface in interfaces {
                match &interface.properties {
                    InterfacePropertiesSpec::Bridge(_) => {}
                    InterfacePropertiesSpec::Vtep(props) => {
                        req.vteps.try_insert(props.clone()).unwrap();
                    }
                    InterfacePropertiesSpec::Vrf(props) => {
                        req.vrfs.try_insert(props.clone()).unwrap();
                    }
                }
                req.interfaces.try_insert(interface).unwrap();
            }
            req.associations
                .try_insert(InterfaceAssociationSpec {
                    name: "vtep3".to_string().try_into().unwrap(),
                    controller_name: Some("br3".to_string().try_into().unwrap()),
                })
                .unwrap();
            req.associations
                .try_insert(InterfaceAssociationSpec {
                    name: "br3".to_string().try_into().unwrap(),
                    controller_name: Some("vrf3".to_string().try_into().unwrap()),
                })
                .unwrap();
        };

        let remove_some_requirement = move |req: &mut RequiredInformationBase| {
            req.interfaces
                .remove_by_name(&"br1".to_string().try_into().unwrap())
                .unwrap();
            req.interfaces
                .remove_by_name(&"vrf1".to_string().try_into().unwrap())
                .unwrap();
            req.interfaces
                .remove_by_name(&"vtep1".to_string().try_into().unwrap())
                .unwrap();
            req.associations
                .remove_by_name(&"br1".to_string().try_into().unwrap())
                .unwrap();
            req.associations
                .remove_by_name(&"vtep1".to_string().try_into().unwrap())
                .unwrap();
        };

        let vpcs = VpcManager::<RequiredInformationBase>::new(Arc::new(handle));

        for _ in 0..25 {
            let observed = vpcs.observe().await.unwrap();
            vpcs.reconcile(&mut required, &observed).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        inject_new_requirements(&mut required);
        for _ in 0..25 {
            let observed = vpcs.observe().await.unwrap();
            vpcs.reconcile(&mut required, &observed).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        remove_some_requirement(&mut required);
        for _ in 0..25 {
            let observed = vpcs.observe().await.unwrap();
            vpcs.reconcile(&mut required, &observed).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}
