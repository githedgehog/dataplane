// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use crate::tc::block::BlockIndex;
use crate::tc::qdisc::{Qdisc, QdiscHandle};
use derive_builder::Builder;
use futures::TryStreamExt;
use multi_index_map::MultiIndexMap;
use net::interface::InterfaceIndex;
use rekon::{Create, Observe, Remove, Update};
use rtnetlink::packet_route::tc::{
    TcAttribute, TcFilterFlowerOption, TcHandle, TcMessage, TcOption,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tracing::{debug, warn};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[repr(transparent)]
pub struct ChainIndex(u32);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum ChainAttachment {
    Interface {
        interface: InterfaceIndex,
        parent: QdiscHandle,
    },
    Block(BlockIndex),
}

impl From<InterfaceIndex> for ChainAttachment {
    fn from(value: InterfaceIndex) -> Self {
        Self::Interface {
            interface: value,
            parent: QdiscHandle::INGRESS, // TODO: this is maybe an over aggressive default
        }
    }
}

impl From<BlockIndex> for ChainAttachment {
    fn from(value: BlockIndex) -> Self {
        Self::Block(value)
    }
}

#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct ChainId {
    index: ChainIndex,
    on: ChainAttachment,
}

impl ChainId {
    /// Creates a new chain ID.
    #[must_use]
    pub fn new(index: impl Into<ChainIndex>, on: impl Into<ChainAttachment>) -> Self {
        Self {
            index: index.into(),
            on: on.into(),
        }
    }

    /// Returns the block or interface which this chain is attached to.
    #[must_use]
    pub fn on(&self) -> ChainAttachment {
        self.on
    }

    /// Returns the index which identifies this chain within the block or device
    #[must_use]
    pub fn chain(&self) -> ChainIndex {
        self.index
    }
}

impl From<u32> for ChainIndex {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ChainIndex> for u32 {
    fn from(value: ChainIndex) -> Self {
        value.0
    }
}

impl std::ops::Add<u32> for ChainIndex {
    type Output = Self;

    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0 + rhs)
    }
}

#[derive(Builder, Debug, Clone, PartialEq, Eq, MultiIndexMap)]
#[multi_index_derive(Debug, Clone)]
pub struct Chain {
    #[multi_index(ordered_unique)]
    id: ChainId,
    #[builder(default)]
    template: Option<Vec<TcFilterFlowerOption>>,
}

#[derive(Builder, Debug, Clone, PartialEq, Eq, MultiIndexMap)]
#[multi_index_derive(Debug, Clone)]
pub struct ChainSpec {
    #[multi_index(ordered_unique)]
    id: ChainId,
    #[builder(default)]
    template: Option<Vec<TcFilterFlowerOption>>,
}

impl Create for Manager<Chain> {
    type Requirement<'a>
        = &'a ChainSpec
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
        let req = match requirement.id.on() {
            ChainAttachment::Interface { interface, parent } => {
                self.handle
                    .traffic_chain(
                        #[allow(clippy::cast_possible_wrap)] // u32 under the hood anyway
                        {
                            u32::from(interface) as i32
                        },
                    )
                    .add()
                    .parent(TcHandle {
                        major: parent.major,
                        minor: parent.minor,
                    })
            }
            ChainAttachment::Block(block) => self.handle.traffic_chain(0).add().block(block.into()),
        }
        .chain(requirement.id.chain().into());

        let req = match &requirement.template {
            None => req,
            Some(template) => match req.flower(template.as_slice()) {
                Ok(req) => req,
                Err(err) => {
                    return Err(err);
                }
            },
        };
        req.execute().await
    }
}

impl Remove for Manager<Chain> {
    type Observation<'a>
        = &'a ChainId
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
        match observation.on() {
            ChainAttachment::Interface { interface, parent } => self
                .handle
                .traffic_chain(
                    #[allow(clippy::cast_possible_wrap)] // u32 under the hood anyway
                    {
                        interface.to_u32() as i32
                    },
                )
                .del()
                .parent(TcHandle {
                    major: parent.major,
                    minor: parent.minor,
                }),
            ChainAttachment::Block(block) => self.handle.traffic_chain(0).del().block(block.into()),
        }
        .chain(observation.chain().into())
        .execute()
        .await
    }
}

impl Update for Manager<Chain> {
    type Requirement<'a>
        = &'a ChainSpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a Chain
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a> {
        self.remove(&observation.id).await?;
        self.create(requirement).await
    }
}

fn try_chain_from_tc_message(msg: TcMessage) -> Option<Chain> {
    let mut builder = ChainBuilder::create_empty();
    let mut chain_id_builder = ChainIdBuilder::create_empty();
    let mut kind_found = false;
    let mut template: Vec<TcFilterFlowerOption> = vec![];
    let mut template_found = false;
    for attr in msg.attributes {
        match attr {
            TcAttribute::Kind(kind) => {
                // TODO: impl a KIND trait for flower
                if kind.as_str() != "flower" {
                    debug!("unsupported kind: {}", kind.as_str());
                    return None;
                }
                kind_found = true;
            }
            TcAttribute::Options(options) => {
                template_found = true;
                for option in options {
                    if let TcOption::Flower(option) = option {
                        template.push(option);
                    } else {
                        /*todo*/
                    }
                }
            }
            TcAttribute::Chain(chain_idx) => {
                chain_id_builder.index(chain_idx.into());
            }
            _ => { /* todo */ }
        }
    }
    match (template_found, kind_found) {
        (true, true) => {
            builder.template(Some(template));
        }
        (true, false) => {
            warn!("template found but no kind");
        }
        (false, true) => {
            debug!("kind found but no template");
        }
        (false, false) => {
            builder.template(None);
        }
    }
    if msg.header.index == -1 {
        // this chain is on a block
        let raw_index =
            (u32::from(msg.header.parent.major) << 16) | u32::from(msg.header.parent.minor);
        let block_index = match BlockIndex::try_from(raw_index) {
            Ok(index) => index,
            Err(err) => {
                warn!("invalid block index: {err}");
                return None;
            }
        };
        chain_id_builder.on(block_index.into());
    } else {
        // this chain is on an interface
        match InterfaceIndex::try_from(
            #[allow(clippy::cast_sign_loss)] // u32 under the hood anyway
            {
                msg.header.index as u32
            },
        ) {
            Ok(interface) => {
                chain_id_builder.on(interface.into());
            }
            Err(err) => {
                warn!("invalid interface index: {err}");
                return None;
            }
        }
    }
    builder.id(chain_id_builder.build().ok()?);
    builder.build().ok()
}

impl Observe for Manager<Chain> {
    type Observation<'a>
        = Vec<Chain>
    where
        Self: 'a;

    async fn observe<'a>(&self) -> Self::Observation<'a> {
        let mut chains: Vec<Chain> = vec![];
        let qdisc_manager = Manager::<Qdisc>::new(self.handle.clone());
        let qdiscs = qdisc_manager.observe().await;
        let blocks: BTreeSet<BlockIndex> = qdiscs
            .iter()
            .filter_map(|qdisc| qdisc.ingress_block)
            .chain(qdiscs.iter().filter_map(|qdisc| qdisc.egress_block))
            .collect();
        let devices: BTreeSet<InterfaceIndex> =
            qdiscs.iter().map(|qdisc| qdisc.id.interface()).collect();
        for block in blocks {
            let mut resp = self
                .handle
                .traffic_chain(0)
                .get()
                .block(block.into())
                .execute();
            while let Ok(Some(msg)) = resp.try_next().await {
                match try_chain_from_tc_message(msg) {
                    None => {}
                    Some(chain) => {
                        chains.push(chain);
                    }
                }
            }
        }
        for dev in devices {
            let mut resp = self
                .handle
                .traffic_chain(
                    #[allow(clippy::cast_possible_wrap)]
                    {
                        dev.to_u32() as i32
                    },
                )
                .get()
                .execute();
            while let Ok(Some(msg)) = resp.try_next().await {
                match try_chain_from_tc_message(msg) {
                    None => {}
                    Some(chain) => {
                        chains.push(chain);
                    }
                }
            }
        }
        chains
    }
}
