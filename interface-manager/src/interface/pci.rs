// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::PciNetdevProperties;
use net::interface::switch::SwitchId;
use net::pci::PciEbdf;
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
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct PciNetdevPropertiesSpec {
    #[multi_index(ordered_non_unique)]
    pub switch_id: Option<SwitchId>, // the embedded switch id (if any)
    #[multi_index(ordered_non_unique)]
    pub port_name: Option<String>, // note: NOT strictly an InterfaceName
    #[multi_index(ordered_non_unique)]
    pub parent_dev: PciEbdf, // typically a pci address
}

impl AsRequirement<PciNetdevPropertiesSpec> for PciNetdevProperties {
    type Requirement<'a>
        = PciNetdevPropertiesSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> PciNetdevPropertiesSpec
    where
        Self: 'a,
    {
        PciNetdevPropertiesSpec {
            switch_id: self.switch_id.clone(),
            port_name: self.port_name.clone(),
            parent_dev: self.parent_dev.clone(),
        }
    }
}

impl PartialEq<PciNetdevProperties> for PciNetdevPropertiesSpec {
    fn eq(&self, other: &PciNetdevProperties) -> bool {
        self.parent_dev == other.parent_dev
            && self.port_name == other.port_name
            && self.switch_id == other.switch_id
    }
}
