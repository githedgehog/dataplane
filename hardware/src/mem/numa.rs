use std::collections::BTreeSet;

use crate::{ByteCount, mem::page::PageType};

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "scan"))]
pub use self::scan::*;

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

#[cfg(any(test, feature = "scan"))]
mod scan {
    use hwlocality::object::attributes::NUMANodeAttributes;

    use crate::{ByteCount, mem::numa::NumaNodeAttributes};

    impl<'a> From<NUMANodeAttributes<'a>> for NumaNodeAttributes {
        fn from(value: NUMANodeAttributes<'a>) -> Self {
            Self {
                local_memory: value
                    .local_memory()
                    .map(|x| ByteCount::new(x.get() as usize))
                    .flatten(),
                page_types: value.page_types().iter().map(|x| (*x).into()).collect(),
            }
        }
    }
}
