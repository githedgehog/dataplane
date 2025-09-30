// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::interface::switch::SwitchId;
use crate::pci::PciEbdf;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

/// PCI device properties.
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
    /// The (extended) Bus-Device-Function identifier of the parent device.
    #[multi_index(ordered_non_unique)]
    pub parent_dev: PciEbdf,
    /// The switch-id of the device (if any).  Not all PCI devices are switchdev.
    #[builder(default)]
    #[multi_index(ordered_non_unique)]
    pub switch_id: Option<SwitchId>,
    /// The port name of this port.  This field will be `None` if the device is not a switchdev device.
    /// This field may be `None` if the hardware does not supply a name or the port is not bound the a
    /// driver, or the driver to which it is bound does not support this field.
    #[builder(default)]
    #[multi_index(ordered_non_unique)]
    pub port_name: Option<String>, // note: NOT strictly an InterfaceName
}
