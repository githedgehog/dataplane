// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Memory page types and attributes.
//!
//! This module provides types for representing different memory page sizes
//! and their allocation status. Modern systems support multiple page sizes
//! (e.g., 4KB, 2MB, 1GB) for different performance and memory usage trade-offs.

use crate::ByteCount;

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "scan"))]
pub use self::scan::*;

/// Represents a memory page type with its size and allocation count.
///
/// Different page sizes offer different trade-offs:
/// - Smaller pages (4KB) provide fine-grained memory management
/// - Larger pages (2MB, 1GB) reduce TLB pressure but may waste memory
///
/// The `allocated` field indicates how many pages of this type are
/// currently allocated in the system.
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
    derive(serde::Serialize, serde::Deserialize)
)]
#[rkyv(attr(derive(PartialEq, Eq, PartialOrd, Ord)))]
pub struct PageType {
    size: ByteCount,
    /// NOTE: hwlocality calls this count, but it's actually the number of pages currently allocated
    allocated: u64,
}

impl PageType {
    /// Creates a new page type.
    ///
    /// # Arguments
    ///
    /// * `size` - The size of each page in bytes
    /// * `allocated` - The number of pages of this type currently allocated / reserved
    #[must_use]
    pub fn new(size: ByteCount, allocated: u64) -> Self {
        Self { size, allocated }
    }

    /// Returns the size of each page in bytes.
    #[must_use]
    pub fn size(&self) -> ByteCount {
        self.size
    }

    /// Returns the number of pages of this type currently allocated.
    #[must_use]
    pub fn allocated(&self) -> u64 {
        self.allocated
    }

    /// Returns the total memory used by allocated pages of this type.
    #[must_use]
    pub fn total_allocated_bytes(&self) -> u64 {
        self.allocated * self.size.get() as u64
    }
}

/// Hardware scanning integration for page types.
#[cfg(any(test, feature = "scan"))]
mod scan {
    use num_traits::ToPrimitive;

    use crate::{ByteCount, mem::page::PageType};

    impl From<hwlocality::object::attributes::MemoryPageType> for PageType {
        /// Converts from hwlocality's [`hwlocality::object::attributes::MemoryPageType`].
        fn from(value: hwlocality::object::attributes::MemoryPageType) -> Self {
            let Some(size) = value.size().get().to_usize() else {
                panic!(
                    "nonsensical page size found: memory page size larger than possible memory space?"
                );
            };
            let Some(size) = ByteCount::new(size) else {
                panic!("nonsensical page size found: memory page size is zero?");
            };
            Self {
                size,
                allocated: value.count(),
            }
        }
    }
}
