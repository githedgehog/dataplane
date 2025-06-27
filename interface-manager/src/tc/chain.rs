// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use crate::tc::block::BlockIndex;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use rekon::Create;
use rtnetlink::packet_route::tc::TcFilterFlowerOption;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[repr(transparent)]
pub struct ChainIndex(u32);

#[derive(Builder, Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct ChainId {
    block_index: BlockIndex,
    chain_index: ChainIndex,
}

impl ChainId {
    /// Creates a new chain ID.
    #[must_use]
    pub fn new(block_index: impl Into<BlockIndex>, chain_index: impl Into<ChainIndex>) -> Self {
        Self {
            block_index: block_index.into(),
            chain_index: chain_index.into(),
        }
    }

    /// Returns the block index this chain is associated with.
    #[must_use]
    pub fn block(&self) -> BlockIndex {
        self.block_index
    }

    /// Returns the index which identifies this chain within the block.
    #[must_use]
    pub fn chain(&self) -> ChainIndex {
        self.chain_index
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
        let req = self
            .handle
            .traffic_chain(0)
            .add()
            .block(requirement.id.block().into())
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
