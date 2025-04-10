// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::VrfProperties;
use net::route::RouteTableId;
use rekon::AsRequirement;
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
pub struct VrfPropertiesSpec {
    #[multi_index(ordered_unique)]
    pub route_table_id: RouteTableId,
}

impl AsRequirement<VrfPropertiesSpec> for VrfProperties {
    type Requirement<'a>
        = VrfPropertiesSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        VrfPropertiesSpec {
            route_table_id: self.route_table_id,
        }
    }
}

impl PartialEq<VrfProperties> for VrfPropertiesSpec {
    fn eq(&self, other: &VrfProperties) -> bool {
        self == &other.as_requirement()
    }
}
