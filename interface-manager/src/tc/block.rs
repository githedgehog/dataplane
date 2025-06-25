// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::tc::chain::MultiIndexChainMap;
use multi_index_map::MultiIndexMap;
use net::interface::InterfaceIndex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
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

#[derive(Debug, Copy, Clone)]
pub enum BlockType {
    Ingress,
    Egress,
}

#[derive(Debug, Clone, MultiIndexMap)]
pub struct Block {
    #[multi_index(ordered_unique)]
    index: BlockIndex,
    #[allow(clippy::struct_field_names)]
    block_type: BlockType,
    devices: BTreeSet<InterfaceIndex>,
    chains: MultiIndexChainMap,
}

impl Block {
    #[must_use]
    pub fn new(index: BlockIndex, block_type: BlockType) -> Self {
        Self {
            index,
            block_type,
            devices: BTreeSet::new(),
            chains: MultiIndexChainMap::default(),
        }
    }

    #[must_use]
    pub fn index(&self) -> BlockIndex {
        self.index
    }

    #[must_use]
    pub fn block_type(&self) -> BlockType {
        self.block_type
    }

    #[must_use]
    pub fn devices(&self) -> &BTreeSet<InterfaceIndex> {
        &self.devices
    }

    pub fn add_device(&mut self, device: InterfaceIndex) -> bool {
        self.devices.insert(device)
    }

    pub fn remove_device(&mut self, device: InterfaceIndex) -> bool {
        self.devices.remove(&device)
    }

    #[must_use]
    pub fn chains(&self) -> &MultiIndexChainMap {
        &self.chains
    }

    pub fn chains_mut(&mut self) -> &mut MultiIndexChainMap {
        &mut self.chains
    }
}
