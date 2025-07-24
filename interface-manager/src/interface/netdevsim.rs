// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::NetDevSimPort;
use serde::{Deserialize, Serialize};

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
pub struct NetdevSimPropertiesSpec {
    #[multi_index(ordered_non_unique)]
    pub port: NetDevSimPort,
}
