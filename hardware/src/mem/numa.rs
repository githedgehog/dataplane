// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NUMA (Non-Uniform Memory Access) node attributes.
//!
//! This module provides types for representing NUMA nodes in the system topology.
//! NUMA architecture provides multiple memory nodes where memory access time
//! depends on the memory location relative to the processor.

use std::collections::BTreeSet;

use crate::{ByteCount, mem::page::PageType};

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "scan"))]
pub use self::scan::*;

/// Attributes describing a NUMA node.
///
/// NUMA nodes represent regions of memory in a Non-Uniform Memory Access
/// architecture. Each NUMA node has local memory that can be accessed
/// faster by processors on the same node than by processors on other nodes.
///
/// # Examples
///
/// ```
/// # use dataplane_hardware::mem::numa::NumaNodeAttributes;
/// # use dataplane_hardware::mem::page::PageType;
/// # use dataplane_hardware::ByteCount;
/// # use std::collections::BTreeSet;
/// #
/// // Create a NUMA node with 32GB memory and specific page types
/// let mut page_types = BTreeSet::new();
/// page_types.insert(PageType::new(
///     ByteCount::new(4096).unwrap(),
///     1000,
/// ));
///
/// let numa = NumaNodeAttributes::new(
///     Some(ByteCount::new(32 * 1024 * 1024 * 1024).unwrap()),
///     page_types,
/// );
/// ```
#[derive(
    Clone,
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
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct NumaNodeAttributes {
    local_memory: Option<ByteCount>,
    page_types: BTreeSet<PageType>,
}

impl NumaNodeAttributes {
    /// Creates new NUMA node attributes.
    ///
    /// # Arguments
    ///
    /// * `local_memory` - The amount of local memory on this NUMA node, if known
    /// * `page_types` - Set of memory page types supported by this node
    #[must_use]
    pub fn new(local_memory: Option<ByteCount>, page_types: BTreeSet<PageType>) -> Self {
        Self {
            local_memory,
            page_types,
        }
    }

    /// Returns the amount of local memory on this NUMA node, if known.
    #[must_use]
    pub fn local_memory(&self) -> Option<ByteCount> {
        self.local_memory
    }

    /// Returns the set of page types supported by this NUMA node.
    #[must_use]
    pub fn page_types(&self) -> &BTreeSet<PageType> {
        &self.page_types
    }
}

/// Hardware scanning integration for NUMA nodes.
#[cfg(any(test, feature = "scan"))]
mod scan {
    use hwlocality::object::attributes::NUMANodeAttributes;
    use num_traits::ToPrimitive;

    use crate::{ByteCount, mem::numa::NumaNodeAttributes};

    impl<'a> From<NUMANodeAttributes<'a>> for NumaNodeAttributes {
        /// Converts from hwlocality's [`NUMANodeAttributes`].
        fn from(value: NUMANodeAttributes<'a>) -> Self {
            Self {
                local_memory: value.local_memory().and_then(|x| {
                    let Some(size) = x.get().to_usize() else {
                        panic!("nonsense memory size found: memory size can not be represented as usize?");
                    };
                    ByteCount::new(size)
                }),
                page_types: value.page_types().iter().map(|x| (*x).into()).collect(),
            }
        }
    }
}
