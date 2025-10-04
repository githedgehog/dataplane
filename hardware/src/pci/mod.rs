use crate::pci::{address::PciAddress, device::DeviceId, vendor::VendorId};

pub mod address;
pub mod bridge;
pub mod bus;
pub mod device;
pub mod domain;
pub mod function;
pub mod vendor;

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
pub struct PciDeviceAttributes {
    address: PciAddress,
    revision: u8,
    #[cfg_attr(any(test, feature = "serde"), serde(rename = "device"))]
    device_description: PciDeviceDescription,
    #[cfg_attr(any(test, feature = "serde"), serde(rename = "sub_device"))]
    sub_device_description: PciDeviceDescription,
    link_speed: String,
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
pub struct PciDeviceDescription {
    pub vendor_id: VendorId,
    pub vendor_name: Option<String>,
    pub device_id: DeviceId,
    pub device_name: Option<String>,
}
