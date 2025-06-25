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
pub struct QdiscHandle {
    pub major: u16,
    pub minor: u16,
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
    pub handle: QdiscHandle,
    pub parent: QdiscHandle,
    pub interface_index: InterfaceIndex,
    #[builder(default)]
    pub ingress_block: Option<BlockIndex>,
    #[builder(default)]
    pub egress_block: Option<BlockIndex>,
    pub properties: QdiscProperties,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum QdiscProperties {
    ClsAct,
}

impl Qdisc {
    #[must_use]
    pub fn new(
        handle: QdiscHandle,
        parent: QdiscHandle,
        interface_index: InterfaceIndex,
        properties: QdiscProperties,
    ) -> Self {
        Self {
            handle,
            parent,
            interface_index,
            ingress_block: None,
            egress_block: None,
            properties,
        }
    }

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
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct QdiscSpec {
    pub interface_index: InterfaceIndex,
    #[builder(default)]
    pub ingress_block: Option<BlockIndex>,
    #[builder(default)]
    pub egress_block: Option<BlockIndex>,
    pub properties: QdiscProperties,
}

impl QdiscSpec {
    #[must_use]
    pub fn new(interface_index: InterfaceIndex, properties: QdiscProperties) -> Self {
        Self {
            interface_index,
            ingress_block: None,
            egress_block: None,
            properties,
        }
    }

    pub fn ingress_block(&mut self, block: BlockIndex) -> &mut Self {
        self.ingress_block = Some(block);
        self
    }

    pub fn egress_block(&mut self, block: BlockIndex) -> &mut Self {
        self.egress_block = Some(block);
        self
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
                    requirement.interface_index.to_u32() as i32
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
        let mut resp = self.handle.qdisc().get().ingress().execute();
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
            let qdisc_handle = QdiscHandle {
                major: message.header.handle.major,
                minor: message.header.handle.minor,
            };

            builder.handle(qdisc_handle);

            let parent_handle = QdiscHandle {
                major: message.header.parent.major,
                minor: message.header.parent.minor,
            };
            builder.parent(parent_handle);

            let index = match InterfaceIndex::try_new(index_u32) {
                Err(err) => {
                    warn!("suspicious interface index observed: {err}");
                    continue;
                }
                Ok(idx) => idx,
            };
            builder.interface_index(index);
            for attr in &message.attributes {
                match attr {
                    TcAttribute::Kind(kind) => {
                        if kind == "clsact" {
                            builder.properties(QdiscProperties::ClsAct);
                        }
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
            .del(observation.interface_index.to_u32() as i32);
        req.message_mut().header.handle.major = observation.handle.major;
        req.message_mut().header.handle.minor = observation.handle.minor;
        req.message_mut().header.parent.major = observation.parent.major;
        req.message_mut().header.parent.minor = observation.parent.minor;
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
            interface_index: self.interface_index,
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
