// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::route::RouteTableId;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

/// Vrf specific properties
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
    /// The route table id of the vrf
    #[multi_index(ordered_non_unique)]
    pub route_table_id: RouteTableId,
}

#[cfg(any(test, feature = "bolero"))]
mod contracts {
    use crate::interface::vrf::VrfProperties;
    use crate::route::RouteTableId;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for VrfProperties {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                route_table_id: RouteTableId::generate(driver)?,
            })
        }
    }
}
