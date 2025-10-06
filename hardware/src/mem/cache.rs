// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cache attributes and types for hardware topology.
//!
//! This module provides types for representing different kinds of CPU caches
//! (unified, data, instruction) and their attributes such as size and line size.
use crate::ByteCount;

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "scan"))]
pub use scan::*;

/// Represents the type of a cache.
///
/// This enum distinguishes between different cache types found in CPU hierarchies.
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
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
    strum::FromRepr,
    strum::IntoStaticStr,
)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "&str", into = "&'static str")
)]
#[strum(serialize_all = "lowercase")]
pub enum CacheType {
    /// Unified cache that stores both instructions and data
    Unified,
    /// Data cache
    Data,
    /// Instruction cache
    Instruction,
}

impl From<CacheType> for String {
    fn from(value: CacheType) -> Self {
        let value: &'static str = value.into();
        value.to_string()
    }
}

/// Error returned when an unknown cache type is encountered.
///
/// This error can occur when converting from external representations
/// that contain cache types not supported by this crate.
#[derive(Debug, thiserror::Error, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[error("unknown cache type")]
pub struct UnknownCacheType;

/// Attributes describing a CPU cache.
///
/// Contains information about a cache's type, size, and optionally its line size.
/// Line size is the size of the cache line (the unit of data transfer between
/// different levels of the cache hierarchy).
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
pub struct CacheAttributes {
    /// The type of cache (unified, data, or instruction)
    cache_type: CacheType,
    /// The total size of the cache
    size: ByteCount,
    /// The size of a cache line, if known
    line_size: Option<ByteCount>,
}

impl CacheAttributes {
    /// Returns the type of this cache.
    #[must_use]
    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }

    /// Returns the total size of this cache.
    #[must_use]
    pub fn size(&self) -> ByteCount {
        self.size
    }

    /// Returns the size of a cache line, if known.
    ///
    /// The cache line size is the unit of data transfer between different levels
    /// of the cache hierarchy. This value may not be available for all caches.
    #[must_use]
    pub fn line_size(&self) -> Option<ByteCount> {
        self.line_size
    }
}

/// Conversions from hwlocality types when the "scan" feature is enabled.
#[cfg(any(test, feature = "scan"))]
mod scan {
    use num_traits::ToPrimitive;

    #[allow(clippy::wildcard_imports)] // transparently re-exported above
    use super::*;

    impl TryFrom<hwlocality::object::attributes::CacheAttributes> for CacheAttributes {
        type Error = UnknownCacheType;

        fn try_from(
            value: hwlocality::object::attributes::CacheAttributes,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                cache_type: CacheType::try_from(value.cache_type())
                    .map_err(|_| UnknownCacheType)?,
                size: match value.size() {
                    None => return Err(UnknownCacheType),
                    Some(size) => {
                        let Some(size) = size.get().to_usize() else {
                            return Err(UnknownCacheType);
                        };
                        match ByteCount::new(size) {
                            Some(size) => size,
                            None => {
                                unreachable!("found zero value where unreachable by construction")
                            }
                        }
                    }
                },
                line_size: value.line_size(),
            })
        }
    }

    impl TryFrom<hwlocality::object::types::CacheType> for CacheType {
        type Error = UnknownCacheType;

        fn try_from(value: hwlocality::object::types::CacheType) -> Result<Self, Self::Error> {
            Ok(match value {
                hwlocality::object::types::CacheType::Unified => CacheType::Unified,
                hwlocality::object::types::CacheType::Data => CacheType::Data,
                hwlocality::object::types::CacheType::Instruction => CacheType::Instruction,
                hwlocality::object::types::CacheType::Unknown(_) => Err(UnknownCacheType)?,
            })
        }
    }
}
