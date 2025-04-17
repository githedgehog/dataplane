// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reconcile the intended state of the linux interfaces with its observed state.

mod association;
mod bridge;
mod properties;
mod vrf;
mod vtep;

#[allow(unused_imports)] // re-export
pub use association::*;
#[allow(unused_imports)] // re-export
pub use bridge::*;
#[allow(unused_imports)] // re-export
pub use vrf::*;
#[allow(unused_imports)] // re-export
pub use vtep::*;

use crate::interface::properties::InterfacePropertiesSpec;
use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::eth::mac::SourceMac;
use net::interface::{AdminState, InterfaceIndex, InterfaceName};
use serde::{Deserialize, Serialize};

/// The specified / intended state for a network interface.
///
/// This type represents a "plan" in that it consists of goals to be realized, not observed external
/// state.
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
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceSpec {
    /// The intended name of the network interface.
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    /// The MAC address to be assigned to the interface.  If set to `None `, then the operating
    /// system will pick for you.
    #[builder(default)]
    pub mac: Option<SourceMac>,
    /// The intended administrative state of the network interface.
    ///
    /// Note that it is never possible to specify the operational state of a network interface.
    /// At most, you may articulate if a network interface _should_ be up or down.
    pub admin_state: AdminState,
    /// If this network interface is supposed to be a member / "slave" / controlled by another
    /// network interface, then specify that other interface's index here.
    ///
    /// Note that the end user rarely needs to set this directly (principally because this
    /// information is rarely available directly).
    /// Instead, the reconciliation algorithm will fill in this information as it becomes
    ///  available.
    ///
    /// Note that the default (`None`) indicates that this interface _should not_ be controlled by
    /// / associated with any other network interface.
    #[builder(default)]
    pub controller: Option<InterfaceIndex>,
    /// Interface-specific properties.
    pub properties: InterfacePropertiesSpec,
}
