// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use crate::tc::block::BlockIndex;
use derive_builder::Builder;
use futures::TryStreamExt;
use multi_index_map::MultiIndexMap;
use net::interface::InterfaceIndex;
use rekon::{AsRequirement, Create, Observe, Reconcile, Remove, Update};
use rtnetlink::packet_route::tc::TcAttribute;
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use tracing::warn;

#[derive(
    Builder, Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct QdiscHandle {
    pub major: u16,
    pub minor: u16,
}

impl From<QdiscHandle> for u32 {
    fn from(handle: QdiscHandle) -> Self {
        (u32::from(handle.major) << 16) | u32::from(handle.minor)
    }
}

impl From<u32> for QdiscHandle {
    fn from(handle: u32) -> Self {
        Self {
            major: (handle >> 16) as u16,
            minor: ((0x0000_ffff) & handle) as u16,
        }
    }
}

impl QdiscHandle {
    pub const INGRESS: Self = Self {
        major: u16::MAX,
        minor: 0xfff1,
    };
}

#[derive(
    Builder, Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct QdiscAddress {
    parent: QdiscHandle,
    handle: QdiscHandle,
}

impl QdiscAddress {
    pub const CLSACT: Self = Self {
        parent: QdiscHandle {
            major: u16::MAX,
            minor: 0xfff1,
        },
        handle: QdiscHandle {
            major: 0xffff,
            minor: 0,
        },
    };
}

#[derive(
    Builder, Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct QdiscId {
    #[builder(default = "QdiscAddress::CLSACT")]
    address: QdiscAddress,
    interface: InterfaceIndex,
}

impl QdiscId {
    #[must_use]
    pub const fn new_clsact_on(interface: InterfaceIndex) -> Self {
        Self {
            address: QdiscAddress::CLSACT,
            interface,
        }
    }

    #[must_use]
    pub const fn address(&self) -> QdiscAddress {
        self.address
    }

    #[must_use]
    pub const fn interface(&self) -> InterfaceIndex {
        self.interface
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
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct Qdisc {
    #[multi_index(ordered_unique)]
    pub id: QdiscId,
    #[builder(default)]
    #[multi_index(ordered_non_unique)]
    pub ingress_block: Option<BlockIndex>,
    #[builder(default)]
    #[multi_index(ordered_non_unique)]
    pub egress_block: Option<BlockIndex>,
    pub properties: QdiscProperties,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum QdiscProperties {
    #[default]
    ClsAct,
}

impl Qdisc {
    pub fn ingress_block(&mut self, block: BlockIndex) -> &mut Self {
        self.ingress_block = Some(block);
        self
    }

    pub fn egress_block(&mut self, block: BlockIndex) -> &mut Self {
        self.egress_block = Some(block);
        self
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
#[builder(build_fn(private, name = "_build"))]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct QdiscSpec {
    #[multi_index(ordered_unique)]
    pub id: QdiscId,
    #[builder(default)]
    pub ingress_block: Option<BlockIndex>,
    #[builder(default)]
    pub egress_block: Option<BlockIndex>,
    pub properties: QdiscProperties,
}

impl QdiscSpecBuilder {
    pub fn clsact_on(&mut self, interface_index: InterfaceIndex) -> &mut Self {
        self.id = Some(QdiscId::new_clsact_on(interface_index));
        self
    }

    /// Build a `QdiscSpec` from this builder.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// * needed fields are missing
    /// * the properties field is set to `ClsAct` but the address is not CLSACT
    pub fn build(self) -> Result<QdiscSpec, QdiscSpecBuilderError> {
        match (&self.id, &self.properties) {
            (Some(id), Some(QdiscProperties::ClsAct)) => {
                if id.address == QdiscAddress::CLSACT {
                    self._build()
                } else {
                    Err(QdiscSpecBuilderError::ValidationError(format!(
                        "clsact address mismatch: expected {:#?}, received {:#?}",
                        QdiscAddress::CLSACT,
                        id.address
                    )))
                }
            }
            _ => self._build(),
        }
    }
}

impl QdiscSpec {
    #[must_use]
    pub const fn new_clsact(interface_index: InterfaceIndex) -> Self {
        Self {
            id: QdiscId::new_clsact_on(interface_index),
            ingress_block: None,
            egress_block: None,
            properties: QdiscProperties::ClsAct,
        }
    }
}

impl Create for Manager<Qdisc> {
    type Requirement<'a>
        = &'a QdiscSpec
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn create<'a>(&self, requirement: Self::Requirement<'a>) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        let mut request = self
            .handle
            .qdisc()
            .add(
                #[allow(clippy::cast_possible_wrap)]
                {
                    requirement.id.interface.to_u32() as i32
                },
            )
            .clsact();

        match &requirement.ingress_block {
            None => {}
            Some(block) => {
                request.ingress_block(block.as_u32());
            }
        }

        match &requirement.egress_block {
            None => {}
            Some(block) => {
                request.egress_block(block.as_u32());
            }
        }

        request.execute().await
    }
}

impl Observe for Manager<Qdisc> {
    type Observation<'a>
        = Vec<Qdisc>
    where
        Self: 'a;

    async fn observe<'a>(&self) -> Vec<Qdisc>
    where
        Self: 'a,
    {
        let mut resp = self.handle.qdisc().get().execute();
        let mut qdiscs = Vec::new();
        while let Ok(Some(message)) = resp.try_next().await {
            let mut builder = QdiscBuilder::create_empty();
            let index_u32 = match u32::try_from(message.header.index) {
                Ok(idx) => idx,
                Err(err) => {
                    warn!("suspicious interface index (failed to convert to u32): {err}");
                    continue;
                }
            };
            let address = QdiscAddress {
                parent: QdiscHandle {
                    major: message.header.parent.major,
                    minor: message.header.parent.minor,
                },
                handle: QdiscHandle {
                    major: message.header.handle.major,
                    minor: message.header.handle.minor,
                },
            };

            match InterfaceIndex::try_new(index_u32) {
                Err(err) => {
                    warn!("suspicious interface index observed: {err}");
                    continue;
                }
                Ok(interface_index) => builder.id(QdiscId {
                    address,
                    interface: interface_index,
                }),
            };
            for attr in &message.attributes {
                match attr {
                    TcAttribute::Kind(kind) => {
                        if kind == "clsact" {
                            builder.properties(QdiscProperties::ClsAct);
                        }
                        // TODO: handle other kinds of qdiscs
                    }
                    TcAttribute::IngressBlock(block) => {
                        let index = match NonZero::new(*block) {
                            None => {
                                continue;
                            }
                            Some(block) => BlockIndex::new(block),
                        };
                        builder.ingress_block(Some(index));
                    }
                    TcAttribute::EgressBlock(block) => {
                        let index = match NonZero::new(*block) {
                            None => {
                                continue;
                            }
                            Some(block) => BlockIndex::new(block),
                        };
                        builder.egress_block(Some(index));
                    }
                    _ => {}
                }
            }
            if let Ok(qdisc) = builder.build() {
                qdiscs.push(qdisc);
            }
        }
        qdiscs
    }
}

impl Remove for Manager<Qdisc> {
    type Observation<'a>
        = &'a Qdisc
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn remove<'a>(&self, observation: Self::Observation<'a>) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        #[allow(clippy::cast_possible_wrap)] // TODO: error handling
        let mut req = self
            .handle
            .qdisc()
            .del(observation.id.interface.to_u32() as i32);
        req.message_mut().header.parent.major = observation.id.address.parent.major;
        req.message_mut().header.parent.minor = observation.id.address.parent.minor;
        req.message_mut().header.handle.major = observation.id.address.handle.major;
        req.message_mut().header.handle.minor = observation.id.address.handle.minor;
        req.execute().await
    }
}

impl AsRequirement<QdiscSpec> for Qdisc {
    type Requirement<'a>
        = QdiscSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a,
    {
        QdiscSpec {
            id: self.id,
            ingress_block: self.ingress_block,
            egress_block: self.egress_block,
            properties: self.properties.clone(),
        }
    }
}

impl Update for Manager<Qdisc> {
    type Requirement<'a>
        = QdiscSpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a Qdisc
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(&self, requirement: QdiscSpec, observation: &'a Qdisc) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        // TODO: this is unnecessarily crude.  We can do better later.
        self.remove(observation).await?;
        self.create(&requirement).await
    }
}

impl Reconcile for Manager<Qdisc> {
    type Requirement<'a>
        = QdiscSpec
    where
        Self: 'a;
    type Observation<'a>
        = Option<&'a Qdisc>
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn reconcile<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        match observation {
            None => self.create(&requirement).await,
            Some(observation) => self.update(requirement, observation).await,
        }
    }
}
