// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("README.md")]

#[cfg(any(test, feature = "scan"))]
#[allow(unused_imports)] // re-export
pub use self::scan::*;

/// Attributes for a logical hardware group.
///
/// Groups in hardware topology are used to represent logical collections
/// of components. The depth indicates the hierarchical level of the group
/// within the topology tree.
///
/// # Examples
///
/// ```
/// # use dataplane_hardware::group::GroupAttributes;
/// #
/// let attrs = GroupAttributes::new(1);
/// println!("Group at depth level: {}", attrs.depth());
/// ```
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct GroupAttributes {
    depth: usize,
}

impl GroupAttributes {
    /// Creates new group attributes with the specified depth.
    ///
    /// # Arguments
    ///
    /// * `depth` - The hierarchical depth level of this group
    #[must_use]
    pub fn new(depth: usize) -> Self {
        Self { depth }
    }

    /// Returns the depth level of this group.
    ///
    /// The depth indicates the hierarchical level within the topology,
    /// where 0 is the top level.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.depth
    }
}

/// Hardware scanning integration for groups.
#[cfg(any(test, feature = "scan"))]
mod scan {
    #[allow(clippy::wildcard_imports)] // transparently re-exported above
    use super::*;

    impl From<hwlocality::object::attributes::GroupAttributes> for GroupAttributes {
        /// Converts from hwlocality's [`hwlocality::object::attributes::GroupAttributes`].
        fn from(value: hwlocality::object::attributes::GroupAttributes) -> Self {
            Self {
                depth: value.depth(),
            }
        }
    }
}
