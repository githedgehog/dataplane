// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::interface::switch::SwitchId;
use crate::pci::PciEbdf;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

pub mod switch;

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
pub struct PciNetdevProperties {
    #[multi_index(ordered_non_unique)]
    pub parent_dev: PciEbdf,
    #[builder(default)]
    #[multi_index(ordered_non_unique)]
    pub switch_id: Option<SwitchId>,
    #[builder(default)]
    #[multi_index(ordered_non_unique)]
    pub port_name: Option<String>, // note: NOT strictly an InterfaceName
}
