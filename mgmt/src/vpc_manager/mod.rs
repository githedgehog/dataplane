// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use futures::TryStreamExt;
use interface_manager::Manager;
use interface_manager::interface::{
    MultiIndexInterfaceAssociationSpecMap, MultiIndexInterfaceSpecMap,
    MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap, TryFromLinkMessage,
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
use tracing::{debug, error};

#[derive(Clone, Debug)]
pub struct VpcManager<R> {
    handle: Arc<Handle>,
    _marker: PhantomData<R>,
}

impl<R> VpcManager<R> {
    pub fn new(handle: Arc<Handle>) -> Self {
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
    pub interfaces: MultiIndexInterfaceSpecMap,
    pub vrfs: MultiIndexVrfPropertiesSpecMap,
    pub vteps: MultiIndexVtepPropertiesSpecMap,
    pub associations: MultiIndexInterfaceAssociationSpecMap,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, Builder)]
pub struct ObservedInformationBase {
    pub interfaces: MultiIndexInterfaceMap,
    pub vrfs: MultiIndexVrfPropertiesMap,
    pub vteps: MultiIndexVtepPropertiesMap,
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
        let mut observations = MultiIndexInterfaceMap::with_capacity(512);
        let mut req = self.handle.link().get().execute();
        while let Ok(Some(message)) = req.try_next().await {
            match Interface::try_from_link_message(&message) {
                Ok(interface) => match observations.try_insert(interface) {
                    Ok(_) => {}
                    Err(uniqueness_error) => {
                        error!("{uniqueness_error:?}");
                    }
                },
                Err(err) => {
                    debug!("{err:?}");
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
        = bool
    // true if reconciled
    where
        Self: 'a;

    /// Returns true if the system is reconciled.
    async fn reconcile<'a>(
        &self,
        requirement: &'a mut RequiredInformationBase,
        observation: &'a ObservedInformationBase,
    ) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        let mut reconciled = true;
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

        // reconciling the extant interfaces as much as possible
        let iface_handle = Manager::<Interface>::new(self.handle.clone());
        for (_, interface) in observation.interfaces.iter() {
            match requirement.interfaces.get_by_name(&interface.name) {
                None => match interface.properties {
                    InterfaceProperties::Other => {}
                    _ => {
                        reconciled = false;
                        match iface_handle.remove(interface).await {
                            Ok(()) => {}
                            Err(err) => {
                                error!("{err:?}")
                            }
                        }
                    }
                },
                Some(requirement) => {
                    match iface_handle.reconcile(requirement, Some(interface)).await {
                        None => {}
                        Some(
                            Op::Create(Err(err)) | Op::Update(Err(err)) | Op::Remove(Err(err)),
                        ) => {
                            reconciled = false;
                            error!("{err:?}");
                        }
                        Some(Op::Create(Ok(()))) => {
                            reconciled = false;
                        }
                        Some(Op::Update(Ok(()))) => {
                            reconciled = false;
                        }
                        Some(Op::Remove(Ok(()))) => {
                            reconciled = false;
                        }
                    }
                }
            }
        }

        // go through the requirement list and create anything missing (and reconcile anything out
        // of sync)
        for (_, interface) in requirement.interfaces.iter() {
            match iface_handle
                .reconcile(
                    interface,
                    observation.interfaces.get_by_name(&interface.name),
                )
                .await
            {
                None => {}
                Some(Op::Create(Err(err)) | Op::Update(Err(err)) | Op::Remove(Err(err))) => {
                    reconciled = false;
                    error!("{err:?}");
                }
                _ => {
                    reconciled = false;
                }
            }
        }

        reconciled
    }
}

impl Vpc {
    #[must_use]
    pub fn new(route_table: RouteTableId, discriminant: VpcDiscriminant) -> Self {
        Self {
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

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::vpc_manager::{RequiredInformationBase, Vpc, VpcDiscriminant};
    use bolero::{Driver, TypeGenerator};
    use interface_manager::interface::{
        InterfaceAssociationSpec, InterfacePropertiesSpec, InterfaceSpec,
    };
    use net::interface::AdminState;

    impl TypeGenerator for VpcDiscriminant {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(VpcDiscriminant::EvpnVxlan {
                vni: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for Vpc {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                route_table: driver.produce()?,
                discriminant: driver.produce()?,
            })
        }
    }

    impl TypeGenerator for RequiredInformationBase {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            const MAX_VPCS: usize = 3000;
            let mut num_vpcs = driver.produce::<usize>()?;
            if num_vpcs > MAX_VPCS {
                num_vpcs = MAX_VPCS;
            }
            let mut requirements = RequiredInformationBase::default();
            let mut bridges = vec![];
            let mut vrfs = vec![];
            let mut vteps = vec![];

            for _ in 0..num_vpcs {
                let mut interface: InterfaceSpec = driver.produce()?;
                interface.controller = None;
                interface.admin_state = AdminState::Up;
                match &interface.properties {
                    InterfacePropertiesSpec::Bridge(_) => {
                        if let Ok(bridge) = requirements.interfaces.try_insert(interface) {
                            bridges.push(bridge.clone());
                        }
                    }
                    InterfacePropertiesSpec::Vtep(props) => {
                        if requirements
                            .interfaces
                            .try_insert(interface.clone())
                            .is_ok()
                        {
                            let Err(_) = requirements.vteps.try_insert(props.clone()) else {
                                vteps.push(interface.clone());
                                continue;
                            };
                            requirements
                                .interfaces
                                .remove_by_name(&interface.name)
                                .unwrap();
                        }
                    }
                    InterfacePropertiesSpec::Vrf(props) => {
                        if requirements
                            .interfaces
                            .try_insert(interface.clone())
                            .is_ok()
                        {
                            let Err(_) = requirements.vrfs.try_insert(props.clone()) else {
                                vrfs.push(interface.clone());
                                continue;
                            };
                            requirements
                                .interfaces
                                .remove_by_name(&interface.name)
                                .unwrap();
                        }
                    }
                }
            }
            if !bridges.is_empty() {
                for vtep in &vteps {
                    if driver.produce::<u8>()? > 192 {
                        continue;
                    }
                    let arbitrary_bridge_index = driver.produce::<usize>()? % bridges.len();
                    let arbitrary_bridge = &bridges[arbitrary_bridge_index];
                    let association = InterfaceAssociationSpec {
                        name: vtep.name.clone(),
                        controller_name: Some(arbitrary_bridge.name.clone()),
                    };
                    requirements.associations.try_insert(association).unwrap();
                }
            }
            if !vrfs.is_empty() {
                for bridge in &bridges {
                    if driver.produce::<u8>()? > 192 {
                        continue;
                    }
                    if vrfs.is_empty() {
                        continue;
                    }
                    let arbitrary_vrf_index = driver.produce::<usize>()? % vrfs.len();
                    let arbitrary_vrf = &vrfs[arbitrary_vrf_index];
                    let association = InterfaceAssociationSpec {
                        name: bridge.name.clone(),
                        controller_name: Some(arbitrary_vrf.name.clone()),
                    };
                    requirements.associations.try_insert(association).unwrap();
                }
            }
            Some(requirements)
        }
    }
}
