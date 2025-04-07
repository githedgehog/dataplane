// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::route::RouteTableId;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

#[derive(
    Builder,
    Clone,
    Debug,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VrfProperties {
    #[multi_index(ordered_non_unique)]
    pub route_table_id: RouteTableId,
}
