use crate::pci::PciDeviceAttributes;

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
    serde(tag = "type")
)]
pub enum BridgeType {
    Pci,
    Host,
}

impl From<BridgeType> for String {
    fn from(value: BridgeType) -> Self {
        match value {
            BridgeType::Pci => "pci".to_string(),
            BridgeType::Host => "host".to_string(),
        }
    }
}

impl TryFrom<String> for BridgeType {
    type Error = ();

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(match value.as_str() {
            "pci" => BridgeType::Pci,
            "host" => BridgeType::Host,
            _ => return Err(()),
        })
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
pub struct BridgeAttributes {
    upstream_type: BridgeType,
    downstream_type: BridgeType,
    upstream_attributes: Option<PciDeviceAttributes>,
}

#[cfg(any(test, feature = "scan"))]
mod scan {
    use super::*;
    use hwlocality::object::attributes::UpstreamAttributes;

    impl TryFrom<hwlocality::object::attributes::BridgeAttributes> for BridgeAttributes {
        type Error = ();

        fn try_from(
            value: hwlocality::object::attributes::BridgeAttributes,
        ) -> Result<Self, Self::Error> {
            Ok(Self {
                upstream_type: value.upstream_type().try_into()?,
                downstream_type: value.downstream_type().try_into()?,
                upstream_attributes: value
                    .upstream_attributes()
                    .map(|UpstreamAttributes::PCI(&p)| p.into()),
            })
        }
    }

    impl TryFrom<hwlocality::object::types::BridgeType> for BridgeType {
        type Error = ();

        fn try_from(value: hwlocality::object::types::BridgeType) -> Result<Self, Self::Error> {
            Ok(match value {
                hwlocality::object::types::BridgeType::PCI => BridgeType::Pci,
                hwlocality::object::types::BridgeType::Host => BridgeType::Host,
                _ => Err(())?,
            })
        }
    }
}
