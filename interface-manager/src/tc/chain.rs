// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use multi_index_map::MultiIndexMap;
use rtnetlink::packet_route::tc::TcFilterFlowerOption;

pub type ChainIndex = u32;

#[derive(Debug, Clone, PartialEq, Eq, MultiIndexMap)]
#[multi_index_derive(Debug, Clone)]
pub struct Chain {
    #[multi_index(ordered_unique)]
    pub(crate) index: ChainIndex,
    pub(crate) template: Vec<TcFilterFlowerOption>,
}
