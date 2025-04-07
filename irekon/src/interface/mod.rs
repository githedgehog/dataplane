// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

mod association;
mod bridge;
mod properties;
mod vrf;
mod vtep;

#[allow(unused_imports)] // re-export
pub use association::*;
#[allow(unused_imports)] // re-export
pub use bridge::*;
#[allow(unused_imports)] // re-export
pub use properties::*;
#[allow(unused_imports)] // re-export
pub use vrf::*;
#[allow(unused_imports)] // re-export
pub use vtep::*;

use crate::{Manager, manager_of};
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::eth::mac::SourceMac;
use net::interface::{
    AdminState, Interface, InterfaceIndex, InterfaceName, InterfaceProperties, OperationalState,
};
use rekon::{AsRequirement, Create, Op, Reconcile, Remove, Update};
use rtnetlink::packet_route::link::{InfoBridge, InfoData, InfoVrf, InfoVxlan, LinkAttribute};
use rtnetlink::{LinkBridge, LinkUnspec, LinkVrf, LinkVxlan};
use serde::{Deserialize, Serialize};
use tracing::error;

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
pub struct InterfaceSpec {
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    #[builder(default)]
    pub mac: Option<SourceMac>,
    pub admin_state: AdminState,
    #[builder(default)]
    pub controller: Option<InterfaceIndex>,
    pub properties: InterfacePropertiesSpec,
}

impl AsRequirement<InterfaceSpec> for Interface {
    type Requirement<'a>
        = Option<InterfaceSpec>
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        Some(InterfaceSpec {
            name: self.name.clone(),
            mac: self.mac,
            admin_state: self.admin_state,
            controller: self.controller,
            properties: self.properties.as_requirement()?,
        })
    }
}

impl Create for Manager<Interface> {
    type Requirement<'a>
        = &'a InterfaceSpec
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;
    async fn create<'a>(&self, requirement: &'a InterfaceSpec) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        let mut message = match &requirement.properties {
            InterfacePropertiesSpec::Bridge(properties) => {
                LinkBridge::new(requirement.name.as_ref())
                    .set_info_data(InfoData::Bridge(vec![
                        InfoBridge::VlanFiltering(properties.vlan_filtering),
                        InfoBridge::VlanProtocol(properties.vlan_protocol.as_u16()),
                    ]))
                    .build()
            }
            InterfacePropertiesSpec::Vtep(properties) => {
                LinkVxlan::new(requirement.name.as_ref(), properties.vni.as_u32())
                    .set_info_data(InfoData::Vxlan(vec![
                        InfoVxlan::Id(properties.vni.as_u32()),
                        InfoVxlan::Ttl(properties.ttl),
                        InfoVxlan::Local(properties.local),
                    ]))
                    .build()
            }
            InterfacePropertiesSpec::Vrf(properties) => {
                LinkVrf::new(requirement.name.as_ref(), properties.route_table_id.into()).build()
            }
        };
        if let Some(mac) = requirement.mac {
            message
                .attributes
                .push(LinkAttribute::Address(mac.inner().0.to_vec()));
        }
        self.handle.link().add(message).execute().await
    }
}

impl Remove for Manager<Interface> {
    type Observation<'a>
        = &'a Interface
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a,
        Interface: 'a;

    async fn remove<'a>(&self, observation: &'a Interface) -> Result<(), rtnetlink::Error>
    where
        Self: 'a,
    {
        self.handle
            .link()
            .del(observation.index.to_u32())
            .execute()
            .await
    }
}

impl Update for Manager<InterfaceName> {
    type Requirement<'a>
        = &'a InterfaceName
    where
        Self: 'a;
    type Observation<'a>
        = &'a Interface
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(
        &self,
        requirement: &InterfaceName,
        observation: &Interface,
    ) -> Result<(), rtnetlink::Error> {
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(observation.index.to_u32())
                    .down()
                    .name(requirement.to_string())
                    .build(),
            )
            .execute()
            .await
    }
}

impl Update for Manager<InterfaceAssociation> {
    type Requirement<'a>
        = Option<InterfaceIndex>
    where
        Self: 'a;
    type Observation<'a>
        = &'a Interface
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(
        &self,
        requirement: Option<InterfaceIndex>,
        observation: &Interface,
    ) -> Result<(), rtnetlink::Error> {
        if observation.operational_state != OperationalState::Down {
            self.handle
                .link()
                .set_port(
                    LinkUnspec::new_with_index(observation.index.to_u32())
                        .down()
                        .build(),
                )
                .execute()
                .await?;
        }
        match requirement {
            None => {
                self.handle
                    .link()
                    .set_port(
                        LinkUnspec::new_with_index(observation.index.to_u32())
                            .nocontroller()
                            .build(),
                    )
                    .execute()
                    .await
            }
            Some(controller) => {
                self.handle
                    .link()
                    .set_port(
                        LinkUnspec::new_with_index(observation.index.to_u32())
                            .controller(controller.to_u32())
                            .build(),
                    )
                    .execute()
                    .await
            }
        }
    }
}

impl Update for Manager<InterfaceProperties> {
    type Requirement<'a>
        = &'a InterfacePropertiesSpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a Interface
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(
        &self,
        requirement: &InterfacePropertiesSpec,
        observation: &Interface,
    ) -> Result<(), rtnetlink::Error> {
        match (requirement, &observation.properties) {
            (InterfacePropertiesSpec::Bridge(req), InterfaceProperties::Bridge(_)) => {
                self.handle
                    .link()
                    .set_port(
                        LinkUnspec::new_with_index(observation.index.to_u32())
                            .set_info_data(InfoData::Bridge(vec![
                                InfoBridge::VlanProtocol(req.vlan_protocol.as_u16()),
                                InfoBridge::VlanFiltering(req.vlan_filtering),
                            ]))
                            .build(),
                    )
                    .execute()
                    .await
            }
            (InterfacePropertiesSpec::Vrf(req), InterfaceProperties::Vrf(_)) => {
                self.handle
                    .link()
                    .set_port(
                        LinkUnspec::new_with_index(observation.index.to_u32())
                            .set_info_data(InfoData::Vrf(vec![InfoVrf::TableId(
                                req.route_table_id.into(),
                            )]))
                            .build(),
                    )
                    .execute()
                    .await
            }
            (InterfacePropertiesSpec::Vtep(req), InterfaceProperties::Vtep(_)) => {
                self.handle
                    .link()
                    .set_port(
                        LinkUnspec::new_with_index(observation.index.to_u32())
                            .set_info_data(InfoData::Vxlan(vec![
                                InfoVxlan::Id(req.vni.as_u32()),
                                InfoVxlan::Ttl(req.ttl),
                                InfoVxlan::Local(req.local),
                            ]))
                            .build(),
                    )
                    .execute()
                    .await
            }
            (_, _) => {
                self.handle
                    .link()
                    .del(observation.index.to_u32())
                    .execute()
                    .await
            }
        }
    }
}

impl Update for Manager<SourceMac> {
    type Requirement<'a>
        = SourceMac
    where
        Self: 'a;
    type Observation<'a>
        = &'a Interface
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(
        &self,
        requirement: SourceMac,
        observation: &Interface,
    ) -> Result<(), rtnetlink::Error>
    where
        Self: 'a,
    {
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(observation.index.to_u32())
                    .down()
                    .address(requirement.inner().0.to_vec())
                    .build(),
            )
            .execute()
            .await
    }
}

impl Update for Manager<AdminState> {
    type Requirement<'a>
        = AdminState
    where
        Self: 'a;
    type Observation<'a>
        = &'a Interface
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(
        &self,
        requirement: AdminState,
        observation: &Interface,
    ) -> Result<(), rtnetlink::Error> {
        match requirement {
            AdminState::Down => {
                self.handle
                    .link()
                    .set(
                        LinkUnspec::new_with_index(observation.index.to_u32())
                            .down()
                            .build(),
                    )
                    .execute()
                    .await
            }
            AdminState::Up => {
                self.handle
                    .link()
                    .set(
                        LinkUnspec::new_with_index(observation.index.to_u32())
                            .up()
                            .build(),
                    )
                    .execute()
                    .await
            }
        }
    }
}

impl Update for Manager<Interface> {
    type Requirement<'a>
        = &'a InterfaceSpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a Interface
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a,
        Interface: 'a;

    async fn update<'a>(
        &self,
        required: &InterfaceSpec,
        observed: &Interface,
    ) -> Result<(), rtnetlink::Error> {
        if required == observed {
            return Ok(());
        }
        if required.name != observed.name {
            manager_of::<InterfaceName>(self)
                .update(&required.name, observed)
                .await?;
        }
        if required.mac != observed.mac {
            match required.mac {
                None => { /* no mac specified */ }
                Some(mac) => {
                    manager_of::<SourceMac>(self).update(mac, observed).await?;
                }
            }
        }
        if required.properties != observed.properties {
            manager_of::<InterfaceProperties>(self)
                .update(&required.properties, observed)
                .await?;
        }
        if required.controller != observed.controller {
            manager_of::<InterfaceAssociation>(self)
                .update(required.controller, observed)
                .await?;
        }
        if required.admin_state != observed.admin_state {
            manager_of::<AdminState>(self)
                .update(required.admin_state, observed)
                .await?;
        }
        error!("programmer error: bad implementation of update or partial eq for Interface");
        Ok(())
    }
}

impl Reconcile for Manager<Interface> {
    type Requirement<'a>
        = &'a InterfaceSpec
    where
        Self: 'a;
    type Observation<'a>
        = Option<&'a Interface>
    where
        Self: 'a;
    type Outcome<'a>
        = Option<Op<'a, Self>>
    where
        Self: 'a,
        Interface: 'a;

    async fn reconcile<'a>(
        &self,
        requirement: &'a InterfaceSpec,
        observation: Option<&'a Interface>,
    ) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        match observation {
            None => Some(Op::Create(self.create(requirement).await)),
            Some(observed) => {
                if requirement == observed {
                    return None;
                }
                Some(Op::Update(self.update(requirement, observed).await))
            }
        }
    }
}

impl PartialEq<Interface> for InterfaceSpec {
    fn eq(&self, other: &Interface) -> bool {
        match other.as_requirement() {
            None => false,
            Some(other) => *self == other,
        }
    }
}
