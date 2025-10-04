use crate::ByteCount;

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "scan"))]
pub use scan::*;

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
    /// Unified cache
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

#[derive(Debug, thiserror::Error, PartialEq, Hash, Eq, PartialOrd, Ord)]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[error("unknown cache type")]
pub struct UnknownCacheType;

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
    cache_type: CacheType,
    size: ByteCount,
    line_size: Option<ByteCount>,
}

#[cfg(any(test, feature = "scan"))]
mod scan {
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
                    Some(size) => ByteCount::new(size.get() as usize).unwrap(), // panic should be unreachable
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
