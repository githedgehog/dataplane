// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use crate::tc::block::BlockIndex;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::InterfaceIndex;
use rekon::{Create, Observe, Remove, Update};
use rtnetlink::packet_route::tc::TcFilterFlowerOption;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[repr(transparent)]
pub struct ChainIndex(u32);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum ChainOn {
    Interface(InterfaceIndex),
    Block(BlockIndex),
}

#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct ChainId {
    index: ChainIndex,
    on: ChainOn,
}

impl ChainId {
    /// Creates a new chain ID.
    #[must_use]
    pub fn new(index: impl Into<ChainIndex>, on: ChainOn) -> Self {
        Self {
            index: index.into(),
            on,
        }
    }

    /// Returns the block or interface which this chain is attached to.
    #[must_use]
    pub fn on(&self) -> ChainOn {
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
            ChainOn::Interface(interface) => self
                .handle
                .traffic_chain(
                    #[allow(clippy::cast_possible_wrap)] // u32 under the hood anyway
                    {
                        u32::from(interface) as i32
                    },
                )
                .add(),
            ChainOn::Block(block) => self.handle.traffic_chain(0).add().block(block.into()),
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
            ChainOn::Interface(iface) => self
                .handle
                .traffic_chain(
                    #[allow(clippy::cast_possible_wrap)] // u32 under the hood anyway
                    {
                        iface.to_u32() as i32
                    },
                )
                .del(),
            ChainOn::Block(block) => self.handle.traffic_chain(0).del().block(block.into()),
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

// impl Observe for Manager<Chain> {
//     type Observation<'a>
//         = Vec<Chain>
//     where
//         Self: 'a;
//
//     async fn observe<'a>(&self) -> Self::Observation<'a> {
//         let mut links = Manager::<Interface>::new()
//         let mut x = self.handle.traffic_chain(0).get().block(s);
//     }
// }
