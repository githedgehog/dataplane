// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tools for identifying supported hardware.

use crate::pci::{device::DeviceId, vendor::VendorId};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    strum::IntoStaticStr,
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
    strum::FromRepr,
)]
#[strum(serialize_all = "snake_case")]
pub enum SupportedVendor {
    Intel,
    Mellanox,
    RedHat,
}

impl SupportedVendor {
    #[must_use]
    pub const fn vendor_id(&self) -> VendorId {
        let result = match self {
            SupportedVendor::Intel => VendorId::new(0x8086),
            SupportedVendor::Mellanox => VendorId::new(0x15b3),
            SupportedVendor::RedHat => VendorId::new(0x1af4),
        };
        match result {
            Ok(ret) => ret,
            Err(_) => unreachable!(),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    strum::IntoStaticStr,
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
    strum::FromRepr,
)]
#[strum(serialize_all = "snake_case")]
pub enum SupportedDevice {
    #[strum(props(description = "82574L Gigabit Network Connection"))]
    IntelE1000,
    #[strum(props(description = "Ethernet Controller X710"))]
    IntelX710,
    #[strum(props(description = "Ethernet Virtual Function 700 Series"))]
    IntelX710VirtualFunction,
    #[strum(props(description = "MT28908 Family [ConnectX-6]"))]
    MellanoxConnectX6DX,
    #[strum(props(description = "MT2910 Family [ConnectX-7]"))]
    MellanoxConnectX7,
    #[strum(props(description = "CX8 Family [ConnectX-8]"))]
    MellanoxConnectX8,
    #[strum(props(
        description = "MT42822 BlueField-2 integrated ConnectX-6 Dx network controller"
    ))]
    MellanoxBlueField2,
    #[strum(props(description = "MT43244 BlueField-3 integrated ConnectX-7 network controller"))]
    MellanoxBlueField3,
    #[strum(props(description = "Virtio network device"))]
    VirtioNet,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    strum::IntoStaticStr,
    strum::Display,
    strum::EnumIs,
    strum::EnumString,
    strum::FromRepr,
)]
#[strum(serialize_all = "snake_case")]
pub enum DpdkDriverType {
    VfioPci,
    Bifurcated,
}

impl From<SupportedDevice> for DpdkDriverType {
    fn from(value: SupportedDevice) -> Self {
        match value {
            SupportedDevice::IntelE1000
            | SupportedDevice::IntelX710
            | SupportedDevice::IntelX710VirtualFunction
            | SupportedDevice::VirtioNet => DpdkDriverType::VfioPci,
            SupportedDevice::MellanoxConnectX6DX
            | SupportedDevice::MellanoxConnectX7
            | SupportedDevice::MellanoxConnectX8
            | SupportedDevice::MellanoxBlueField2
            | SupportedDevice::MellanoxBlueField3 => DpdkDriverType::Bifurcated,
        }
    }
}

impl SupportedDevice {
    #[must_use]
    pub const fn vendor(&self) -> SupportedVendor {
        #[allow(clippy::enum_glob_use)]
        use SupportedDevice::*;
        #[allow(clippy::enum_glob_use)]
        use SupportedVendor::*;
        match self {
            IntelX710 | IntelX710VirtualFunction | IntelE1000 => Intel,
            MellanoxConnectX6DX | MellanoxConnectX7 | MellanoxConnectX8 | MellanoxBlueField2
            | MellanoxBlueField3 => Mellanox,
            VirtioNet => RedHat,
        }
    }

    #[must_use]
    pub const fn vendor_id(&self) -> VendorId {
        self.vendor().vendor_id()
    }

    #[must_use]
    pub const fn device_ids(&self) -> &'static [DeviceId] {
        #[allow(clippy::enum_glob_use)]
        use SupportedDevice::*;
        match self {
            IntelE1000 => {
                const DEVICES: [DeviceId; 1] = [
                    // TODO: this is somewhat confusing as this card seems to have many sub-models
                    // 82574L Gigabit Network Connection
                    DeviceId::new(0x10d3),
                ];
                DEVICES.as_slice()
            }
            IntelX710 => {
                const DEVICES: [DeviceId; 1] = [
                    // Ethernet Controller X710 for 10GBASE-T
                    DeviceId::new(0x15ff),
                ];
                DEVICES.as_slice()
            }
            IntelX710VirtualFunction => {
                const DEVICES: [DeviceId; 1] = [
                    // Ethernet Virtual Function 700 Series
                    DeviceId::new(0x154c),
                ];
                DEVICES.as_slice()
            }
            MellanoxConnectX6DX => {
                const DEVICES: [DeviceId; 1] = [
                    DeviceId::new(0x101d), // this is the answer from the DB but I don't trust it until I see it in the scan
                ];
                DEVICES.as_slice()
            }
            MellanoxConnectX7 => {
                const DEVICES: [DeviceId; 1] = [
                    // TODO: fill in with exact supported device id once we can scan the test unit
                    // This is the answer from the DB but I don't trust it until I see it in the scan
                    DeviceId::new(0x1021),
                ];
                DEVICES.as_slice()
            }
            MellanoxConnectX8 => {
                const DEVICES: [DeviceId; 1] = [
                    // TODO: fill in with exact supported device id once we can scan the test unit
                    // This is the answer from the DB but I don't trust it until I see it in the scan
                    DeviceId::new(0x1023),
                ];
                DEVICES.as_slice()
            }
            MellanoxBlueField2 => {
                const DEVICES: [DeviceId; 1] = [DeviceId::new(0xa2d6)];
                DEVICES.as_slice()
            }
            MellanoxBlueField3 => {
                const DEVICES: [DeviceId; 1] = [DeviceId::new(0xa2dc)];
                DEVICES.as_slice()
            }
            VirtioNet => {
                const DEVICES: [DeviceId; 2] = [
                    // legacy code
                    DeviceId::new(0x1000),
                    // modern code
                    DeviceId::new(0x1041),
                ];
                DEVICES.as_slice()
            }
        }
    }
}

impl From<SupportedVendor> for VendorId {
    fn from(value: SupportedVendor) -> Self {
        value.vendor_id()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0} is not a supported pci device vendor")]
pub struct UnsupportedVendor(VendorId);

impl TryFrom<VendorId> for SupportedVendor {
    type Error = UnsupportedVendor;

    fn try_from(value: VendorId) -> Result<Self, Self::Error> {
        #[allow(clippy::enum_glob_use)]
        use SupportedVendor::*;
        Ok(match value {
            vendor if vendor == Intel.vendor_id() => Intel,
            vendor if vendor == Mellanox.vendor_id() => Mellanox,
            vendor if vendor == RedHat.vendor_id() => RedHat,
            vendor => Err(UnsupportedVendor(vendor))?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("vendor id {0}, device id {1} is not a supported pci device")]
pub struct UnsupportedDevice(VendorId, DeviceId);

impl TryFrom<(VendorId, DeviceId)> for SupportedDevice {
    type Error = UnsupportedDevice;

    fn try_from(value: (VendorId, DeviceId)) -> Result<Self, Self::Error> {
        let (vendor, device) = value;
        Ok(
            match SupportedVendor::try_from(vendor)
                .map_err(|_| UnsupportedDevice(vendor, device))?
            {
                SupportedVendor::Intel => match device {
                    device if SupportedDevice::IntelE1000.device_ids().contains(&device) => {
                        SupportedDevice::IntelE1000
                    }
                    device if SupportedDevice::IntelX710.device_ids().contains(&device) => {
                        SupportedDevice::IntelX710
                    }
                    device
                        if SupportedDevice::IntelX710VirtualFunction
                            .device_ids()
                            .contains(&device) =>
                    {
                        SupportedDevice::IntelX710VirtualFunction
                    }
                    _ => Err(UnsupportedDevice(vendor, device))?,
                },
                SupportedVendor::Mellanox => match device {
                    device
                        if SupportedDevice::MellanoxConnectX6DX
                            .device_ids()
                            .contains(&device) =>
                    {
                        SupportedDevice::MellanoxConnectX6DX
                    }
                    device
                        if SupportedDevice::MellanoxConnectX7
                            .device_ids()
                            .contains(&device) =>
                    {
                        SupportedDevice::MellanoxConnectX7
                    }
                    device
                        if SupportedDevice::MellanoxConnectX8
                            .device_ids()
                            .contains(&device) =>
                    {
                        SupportedDevice::MellanoxConnectX8
                    }
                    device
                        if SupportedDevice::MellanoxBlueField2
                            .device_ids()
                            .contains(&device) =>
                    {
                        SupportedDevice::MellanoxBlueField2
                    }
                    device
                        if SupportedDevice::MellanoxBlueField3
                            .device_ids()
                            .contains(&device) =>
                    {
                        SupportedDevice::MellanoxBlueField3
                    }
                    _ => Err(UnsupportedDevice(vendor, device))?,
                },
                SupportedVendor::RedHat => match device {
                    device if SupportedDevice::VirtioNet.device_ids().contains(&device) => {
                        SupportedDevice::VirtioNet
                    }
                    _ => Err(UnsupportedDevice(vendor, device))?,
                },
            },
        )
    }
}
