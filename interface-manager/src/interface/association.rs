// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::interface::InterfaceName;
use serde::{Deserialize, Serialize};

#[cfg(doc)]
use net::interface::Interface;

/// An "observed" association (or lack of same) from one network interface with another.
///
/// For example, putting a VTEP in a bridge, or a bridge in a VRF.
///
/// This type is currently empty, as interface associations are observed by way of [`Interface`].
#[non_exhaustive]
pub struct InterfaceAssociation;

/// A "plan" to associate (or disassociate) one network interface with another.
///
/// For example, putting a VTEP in a bridge, or a bridge in a VRF.
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
pub struct InterfaceAssociationSpec {
    /// The name of the network interface to be associated
    #[multi_index(hashed_unique)]
    pub name: InterfaceName,
    /// The name of the network interface which should be controlling the interface with `name`.
    pub controller_name: Option<InterfaceName>,
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::interface::InterfaceAssociationSpec;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for InterfaceAssociationSpec {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self {
                name: driver.produce()?,
                controller_name: driver.produce()?,
            })
        }
    }
}
