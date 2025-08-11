// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reconcile the intended state of the linux interfaces with its observed state.

mod association;
mod bridge;
mod pci;
mod properties;
mod tap;
mod vrf;
mod vtep;

#[allow(unused_imports)] // re-export
pub use association::*;
#[allow(unused_imports)] // re-export
pub use bridge::*;
#[allow(unused_imports)] // re-export
pub use pci::*;
#[allow(unused_imports)] // re-export
pub use properties::*;
#[allow(unused_imports)] // re-export
pub use tap::*;
#[allow(unused_imports)] // re-export
pub use vrf::*;
#[allow(unused_imports)] // re-export
pub use vtep::*;

#[cfg(feature = "netdevsim")]
mod netdevsim;
#[cfg(feature = "netdevsim")]
#[allow(unused_imports)]
pub use netdevsim::*;

use crate::{Manager, manager_of};
use derive_builder::Builder;
use futures::TryFutureExt;
use multi_index_map::MultiIndexMap;
use net::eth::ethtype::EthType;
use net::eth::mac::SourceMac;
use net::interface::switch::SwitchId;
use net::interface::{
    AdminState, BridgePropertiesBuilder, Interface, InterfaceBuilder, InterfaceBuilderError,
    InterfaceIndex, InterfaceName, InterfaceProperties, Mtu, OperationalState,
    PciNetdevPropertiesBuilder, VrfPropertiesBuilder, VtepPropertiesBuilder,
};
use net::ipv4::addr::UnicastIpv4Addr;
use net::pci::PciEbdf;
use net::route::RouteTableId;
use net::vxlan::InvalidVni;
use rekon::{AsRequirement, Create, Op, Reconcile, Remove, Update};
use rtnetlink::packet_route::link::{
    InfoBridge, InfoData, InfoKind, InfoVrf, InfoVxlan, LinkAttribute, LinkFlags, LinkInfo,
    LinkMessage, State,
};
use rtnetlink::{LinkBridge, LinkDummy, LinkUnspec, LinkVrf, LinkVxlan};
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use tracing::{debug, error, warn};

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
    /// The MTU to be assigned to the interface.  If set to `None `, then the operating
    /// system will pick for you.
    #[builder(default)]
    pub mtu: Option<Mtu>,
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
            mtu: self.mtu,
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
                        InfoVxlan::Port(properties.port.as_u16()),
                    ]))
                    .build()
            }
            InterfacePropertiesSpec::Vrf(properties) => {
                LinkVrf::new(requirement.name.as_ref(), properties.route_table_id.into()).build()
            }
            InterfacePropertiesSpec::Pci(_) => {
                warn!("expected pci device missing: {requirement:#?}");
                return Err(rtnetlink::Error::RequestFailed);
            }
            InterfacePropertiesSpec::Tap => {
                return TapDevice::open(&requirement.name)
                    .map_err(|err| {
                        warn!("failed to create tap device: {err:?}");
                        rtnetlink::Error::RequestFailed
                    })
                    .await;
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
                                InfoVxlan::Local(req.local.inner()),
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

impl Update for Manager<Mtu> {
    type Requirement<'a>
        = Mtu
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
        requirement: Mtu,
        observation: &Interface,
    ) -> Result<(), rtnetlink::Error>
    where
        Self: 'a,
    {
        self.handle
            .link()
            .set(
                LinkUnspec::new_with_index(observation.index.to_u32())
                    .mtu(requirement.to_u32())
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
        if required.properties != observed.properties {
            if let InterfacePropertiesSpec::Pci(_) = required.properties {
                // you can't change any properties of the pci device, let alone remove it
            } else {
                // If properties are drifting, then we need to just kill and fill the thing.
                // Many properties are not possible to update reliably.
                // We might not even be dealing with an aligned interface type.
                manager_of::<Interface>(self).remove(observed).await?;
                return Ok(());
            }
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
                    return Ok(());
                }
            }
        }
        if required.mtu != observed.mtu {
            match required.mtu {
                None => { /* no mtu specified */ }
                Some(mtu) => {
                    manager_of::<Mtu>(self).update(mtu, observed).await?;
                    return Ok(());
                }
            }
        }
        if required.controller != observed.controller {
            manager_of::<InterfaceAssociation>(self)
                .update(required.controller, observed)
                .await?;
            return Ok(());
        }
        if required.admin_state != observed.admin_state {
            manager_of::<AdminState>(self)
                .update(required.admin_state, observed)
                .await?;
            return Ok(());
        }
        Ok(())
    }
}

impl PartialEq<Interface> for InterfaceSpec {
    fn eq(&self, other: &Interface) -> bool {
        match other.as_requirement() {
            None => false,
            Some(mut other) => {
                if self.mac.is_none() {
                    other.mac = None;
                }
                if self.mtu.is_none() {
                    other.mtu = None;
                }
                *self == other
            }
        }
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

pub trait TryFromLinkMessage {
    type Error;
    /// Try to construct this type from a netlink [`LinkMessage`].
    ///
    /// # Errors
    ///
    /// Returns an error if unable to construct `Self` from that message.
    fn try_from_link_message(message: &LinkMessage) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

fn extract_vrf_data(builder: &mut VrfPropertiesBuilder, datas: &[InfoVrf]) {
    for data in datas {
        if let InfoVrf::TableId(raw) = data {
            match RouteTableId::try_from(*raw) {
                Ok(route_table) => {
                    builder.route_table_id(route_table);
                }
                Err(err) => {
                    error!("zero is not a legal route table id!: {err:?}");
                }
            }
        }
    }
}

fn extract_vxlan_info(builder: &mut VtepPropertiesBuilder, datas: &[InfoVxlan]) {
    for data in datas {
        match data {
            InfoVxlan::Id(vni) => {
                match (*vni).try_into() {
                    Ok(vni) => {
                        builder.vni(Some(vni));
                    }
                    Err(InvalidVni::ReservedZero) => {
                        builder.vni(None); // likely an external vtep
                    }
                    Err(InvalidVni::TooLarge(wrong)) => {
                        error!("found too large VNI: {wrong}");
                    }
                }
            }
            InfoVxlan::Local(local) => match UnicastIpv4Addr::try_from(*local) {
                Ok(local) => {
                    if local.inner().is_unspecified() {
                        warn!("likely OS error: unspecified local ipv4 address for vtep: {local}");
                        builder.local(None);
                    }
                    builder.local(Some(local));
                }
                Err(err) => {
                    error!("{err}");
                    builder.local(None);
                }
            },
            InfoVxlan::Ttl(ttl) => {
                builder.ttl(Some(*ttl));
            }
            _ => {}
        }
    }
}

fn extract_bridge_info(builder: &mut BridgePropertiesBuilder, datas: &[InfoBridge]) {
    for data in datas {
        match data {
            InfoBridge::VlanFiltering(f) => {
                builder.vlan_filtering(*f);
            }
            InfoBridge::VlanProtocol(p) => {
                builder.vlan_protocol(EthType::from(*p));
            }
            _ => {}
        }
    }
}

impl TryFromLinkMessage for Interface {
    type Error = InterfaceBuilderError;

    #[allow(clippy::too_many_lines)] // TEMPORARY: break up function
    fn try_from_link_message(message: &LinkMessage) -> Result<Self, Self::Error> {
        let mut builder = InterfaceBuilder::default();
        match InterfaceIndex::try_new(message.header.index) {
            Ok(index) => builder.index(index),
            Err(err) => {
                return Err(InterfaceBuilderError::ValidationError(format!("{err}")));
            }
        };
        let mut vtep_builder = VtepPropertiesBuilder::default();
        let mut vrf_builder = VrfPropertiesBuilder::default();
        let mut bridge_builder = BridgePropertiesBuilder::default();
        let mut pci_netdev_builder = PciNetdevPropertiesBuilder::default();
        let mut kind: Option<InfoKind> = None;
        builder.admin_state(if message.header.flags.contains(LinkFlags::Up) {
            AdminState::Up
        } else {
            AdminState::Down
        });
        builder.controller(None);
        builder.mac(None);
        builder.mtu(None);

        for attr in &message.attributes {
            match attr {
                LinkAttribute::Address(addr) => {
                    builder.mac(SourceMac::try_from(addr).ok());
                }
                LinkAttribute::Mtu(mtu) => {
                    builder.mtu(Mtu::try_from(*mtu).ok());
                }
                LinkAttribute::LinkInfo(infos) => {
                    for info in infos {
                        match info {
                            LinkInfo::Kind(kind_) => match &kind {
                                None => {
                                    kind = Some(kind_.clone());
                                }
                                Some(old_kind) => {
                                    warn!("duplicate kind attribute: {old_kind:?} {kind_:?}");
                                }
                            },
                            LinkInfo::Data(data) => match data {
                                InfoData::Bridge(datas) => {
                                    extract_bridge_info(&mut bridge_builder, datas);
                                }
                                InfoData::Vxlan(datas) => {
                                    extract_vxlan_info(&mut vtep_builder, datas);
                                }
                                InfoData::Vrf(datas) => {
                                    extract_vrf_data(&mut vrf_builder, datas);
                                }
                                _ => {}
                            },
                            _ => {}
                        }
                    }
                }
                LinkAttribute::IfName(name) => match InterfaceName::try_from(name.clone()) {
                    Ok(name) => {
                        builder.name(name);
                    }
                    Err(illegal_name) => {
                        error!("{illegal_name:?}");
                    }
                },
                LinkAttribute::Controller(c) => match NonZero::new(*c) {
                    None => {
                        warn!("zero is not a legal controller index");
                        builder.controller(None);
                    }
                    Some(c) => {
                        builder.controller(Some(InterfaceIndex::new(c)));
                    }
                },
                LinkAttribute::OperState(state) => match state {
                    State::Up => {
                        builder.operational_state(OperationalState::Up);
                    }
                    State::Unknown => {
                        builder.operational_state(OperationalState::Unknown);
                    }
                    State::Down => {
                        builder.operational_state(OperationalState::Down);
                    }
                    _ => {
                        builder.operational_state(OperationalState::Complex);
                    }
                },
                LinkAttribute::PhysSwitchId(phys_link) => {
                    if phys_link.len > SwitchId::MAX_LEN {
                        warn!(
                            "Malformed netlink message: phys switch id is too long: {phys_link:?}"
                        );
                        pci_netdev_builder.switch_id(None);
                    }
                    match SwitchId::new(&phys_link.id[0..phys_link.len]) {
                        Ok(id) => {
                            pci_netdev_builder.switch_id(Some(id));
                        }
                        Err(err) => {
                            warn!("{err}");
                            pci_netdev_builder.switch_id(None);
                        }
                    }
                }
                LinkAttribute::PhysPortName(phys_name) => {
                    pci_netdev_builder.port_name(Some(phys_name.clone()));
                }
                LinkAttribute::ParentDevName(parent_name) => {
                    let dev = match PciEbdf::try_new(parent_name.clone()) {
                        Ok(dev) => dev,
                        Err(err) => {
                            debug!("{err}");
                            continue;
                        }
                    };
                    pci_netdev_builder.parent_dev(dev);
                }
                _ => {}
            }
        }

        match (kind, pci_netdev_builder.build()) {
            (Some(kind), Err(_)) => match kind {
                InfoKind::Tun => {
                    builder.properties(InterfaceProperties::Tap);
                }
                InfoKind::Bridge => match bridge_builder.build() {
                    Ok(props) => {
                        builder.properties(InterfaceProperties::Bridge(props));
                    }
                    Err(e) => {
                        debug!("failed to assemble bridge properties: {e}");
                    }
                },
                InfoKind::Vxlan => match vtep_builder.build() {
                    Ok(props) => {
                        builder.properties(InterfaceProperties::Vtep(props));
                    }
                    Err(e) => {
                        debug!("failed to assemble vtep properties {e}");
                    }
                },
                InfoKind::Vrf => match vrf_builder.build() {
                    Ok(props) => {
                        builder.properties(InterfaceProperties::Vrf(props));
                    }
                    Err(e) => {
                        debug!("{e}");
                    }
                },
                _ => {}
            },
            (None, Ok(props)) => {
                builder.properties(InterfaceProperties::Pci(props));
            }
            (Some(kind), Ok(pci)) => {
                warn!("pci and info kind data are mutually exclusive: {kind:#?}, {pci:#?}");
            }
            (None, Err(_)) => {}
        }
        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use crate::interface::InterfaceSpec;
    use net::interface::{Interface, InterfaceProperties};
    use rekon::AsRequirement;

    #[test]
    fn as_requirement_obeys_contract() {
        bolero::check!()
            .with_type()
            .with_test_time(std::time::Duration::from_secs(5))
            .for_each(|interface: &Interface| {
                if interface.properties == InterfaceProperties::Other {
                    assert!(interface.as_requirement().is_none());
                    return;
                }
                match interface.as_requirement() {
                    None => match &interface.properties {
                        InterfaceProperties::Vtep(props) => {
                            assert!(props.as_requirement().is_none());
                        }
                        _ => unreachable!(),
                    },
                    Some(requirement) => {
                        assert_eq!(&requirement, interface);
                        assert_eq!(requirement, interface.as_requirement().unwrap());
                    }
                }
            });
    }

    #[test]
    fn equality_meaning() {
        bolero::check!().with_type().for_each(
            |(requirement, observation): &(InterfaceSpec, Interface)| {
                if requirement == observation {
                    assert_eq!(requirement, &observation.as_requirement().unwrap());
                } else {
                    match observation.as_requirement() {
                        None => {}
                        Some(as_req) => {
                            assert_ne!(&as_req, requirement);
                        }
                    }
                }
            },
        );
    }
}
