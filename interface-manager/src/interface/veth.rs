// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::InterfaceName;
use net::interface::VethProperties;
use rekon::AsRequirement;
use serde::{Deserialize, Serialize};

/// The planned properties of a veth interface.
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
pub struct VethPropertiesSpec {
    /// Name of peer interface
    #[multi_index(ordered_unique)]
    pub peer: InterfaceName,
    /// Name of peer net NS
    pub peer_ns: Option<String>, // not impl
}

impl AsRequirement<VethPropertiesSpec> for VethProperties {
    type Requirement<'a>
        = VethPropertiesSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        VethPropertiesSpec {
            peer: self.peer.clone(),
            peer_ns: self.peer_ns.clone(),
        }
    }
}

impl PartialEq<VethProperties> for VethPropertiesSpec {
    fn eq(&self, other: &VethProperties) -> bool {
        self == &other.as_requirement()
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::interface::VethPropertiesSpec;
    use bolero::{Driver, TypeGenerator};
    use net::interface::InterfaceName;

    impl TypeGenerator for VethPropertiesSpec {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                peer: InterfaceName::generate(driver)?,
                peer_ns: None, // TBD later
            })
        }
    }
}
