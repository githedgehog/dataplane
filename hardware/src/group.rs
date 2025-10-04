#[cfg(any(test, feature = "scan"))]
#[allow(unused_imports)] // re-export
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
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct GroupAttributes {
    depth: usize,
}

#[cfg(any(test, feature = "scan"))]
mod scan {

    use super::*;

    impl From<hwlocality::object::attributes::GroupAttributes> for GroupAttributes {
        fn from(value: hwlocality::object::attributes::GroupAttributes) -> Self {
            Self {
                depth: value.depth(),
            }
        }
    }
}
