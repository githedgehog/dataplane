// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::interface::InterfaceName;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

/// Veth specific properties
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
pub struct VethProperties {
    #[multi_index(ordered_non_unique)]
    pub peer: InterfaceName,
    pub peer_ns: Option<String>,
}

#[cfg(any(test, feature = "bolero"))]
mod contracts {
    use crate::interface::InterfaceName;
    use crate::interface::veth::VethProperties;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for VethProperties {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                peer: InterfaceName::generate(driver)?,
                peer_ns: None, // TBD later
            })
        }
    }
}
