use crate::ByteCount;

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "scan"))]
pub use self::scan::*;

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

#[cfg(any(test, feature = "scan"))]
mod scan {
    use crate::{ByteCount, mem::page::PageType};

    impl From<hwlocality::object::attributes::MemoryPageType> for PageType {
        fn from(value: hwlocality::object::attributes::MemoryPageType) -> Self {
            Self {
                size: ByteCount::new(value.size().get() as usize).unwrap(), // safe by construction
                allocated: value.count(),
            }
        }
    }
}
