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
    strum::IntoStaticStr,
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(
    any(test, feature = "serde"),
    derive(serde::Serialize, serde::Deserialize),
    serde(tag = "type")
)]
pub enum OsDeviceType {
    Storage,
    Gpu,
    Network,
    OpenFabrics,
    Dma,
    CoProcessor,
    Memory,
}

impl From<OsDeviceType> for String {
    fn from(value: OsDeviceType) -> Self {
        let x: &'static str = value.into();
        x.into()
    }
}

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
pub struct OsDeviceAttributes {
    pub device_type: OsDeviceType,
}

#[cfg(any(test, feature = "scan"))]
mod scan {
    use hwlocality::object::{attributes::OSDeviceAttributes, types::OSDeviceType};

    use crate::os::{OsDeviceAttributes, OsDeviceType};

    impl TryFrom<OSDeviceType> for OsDeviceType {
        type Error = ();

        fn try_from(value: OSDeviceType) -> Result<Self, Self::Error> {
            Ok(match value {
                OSDeviceType::Storage => OsDeviceType::Storage,
                OSDeviceType::GPU => OsDeviceType::Gpu,
                OSDeviceType::Network => OsDeviceType::Network,
                OSDeviceType::OpenFabrics => OsDeviceType::OpenFabrics,
                OSDeviceType::DMA => OsDeviceType::Dma,
                OSDeviceType::CoProcessor => OsDeviceType::CoProcessor,
                OSDeviceType::Unknown(_) => Err(())?,
            })
        }
    }

    impl TryFrom<OSDeviceAttributes> for OsDeviceAttributes {
        type Error = ();

        fn try_from(value: OSDeviceAttributes) -> Result<Self, Self::Error> {
            Ok(Self {
                device_type: value.device_type().try_into()?,
            })
        }
    }
}
