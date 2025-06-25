// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};
use std::num::NonZero;

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct BlockIndex(NonZero<u32>);

impl From<BlockIndex> for u32 {
    fn from(index: BlockIndex) -> Self {
        index.as_u32()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlockIndexError {
    #[error("zero is not a valid block index")]
    Zero,
}

impl TryFrom<u32> for BlockIndex {
    type Error = BlockIndexError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        NonZero::new(value).ok_or(BlockIndexError::Zero).map(Self)
    }
}

impl BlockIndex {
    #[must_use]
    pub fn new(index: NonZero<u32>) -> Self {
        Self(index)
    }

    /// Returns the block index as a `u32`.
    #[must_use]
    pub fn as_u32(&self) -> u32 {
        self.0.get()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
pub enum BlockType {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, MultiIndexMap)]
pub struct Block {
    #[multi_index(ordered_unique)]
    index: BlockIndex,
    #[multi_index(ordered_non_unique)]
    #[allow(clippy::struct_field_names)]
    block_type: BlockType,
}

impl Block {
    #[must_use]
    pub fn new(index: BlockIndex, block_type: BlockType) -> Self {
        Self { index, block_type }
    }

    #[must_use]
    pub fn index(&self) -> BlockIndex {
        self.index
    }

    #[must_use]
    pub fn block_type(&self) -> BlockType {
        self.block_type
    }
}
