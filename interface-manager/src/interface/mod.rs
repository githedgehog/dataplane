// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reconcile the intended state of the linux interfaces with its observed state.

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
pub use vrf::*;
#[allow(unused_imports)] // re-export
pub use vtep::*;

use crate::Manager;
use crate::interface::properties::InterfacePropertiesSpec;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::eth::mac::SourceMac;
use net::interface::{
    AdminState, Interface, InterfaceIndex, InterfaceName, InterfaceProperties, OperationalState,
};
use rekon::{AsRequirement, Create, Remove, Update};
use rtnetlink::packet_route::link::{InfoBridge, InfoData, InfoVrf, InfoVxlan, LinkAttribute};
use rtnetlink::{LinkBridge, LinkUnspec, LinkVrf, LinkVxlan};
use serde::{Deserialize, Serialize};

/// The specified / intended state for a network interface.
///
/// This type represents a "plan" in that it consists of goals to be realized, not observed external
/// state.
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
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceSpec {
    /// The intended name of the network interface.
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    /// The MAC address to be assigned to the interface.  If set to `None `, then the operating
    /// system will pick for you.
    #[builder(default)]
    pub mac: Option<SourceMac>,
    /// The intended administrative state of the network interface.
    ///
    /// Note that it is never possible to specify the operational state of a network interface.
    /// At most, you may articulate if a network interface _should_ be up or down.
    pub admin_state: AdminState,
    /// If this network interface is supposed to be a member / "slave" / controlled by another
    /// network interface, then specify that other interface's index here.
    ///
    /// Note that the end user rarely needs to set this directly (principally because this
    /// information is rarely available directly).
    /// Instead, the reconciliation algorithm will fill in this information as it becomes
    ///  available.
    ///
    /// Note that the default (`None`) indicates that this interface _should not_ be controlled by
    /// / associated with any other network interface.
    #[builder(default)]
    pub controller: Option<InterfaceIndex>,
    /// Interface-specific properties.
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
                        InfoVxlan::Local(properties.local.inner()),
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
                            .down()
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
