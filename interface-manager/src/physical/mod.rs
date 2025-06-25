// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#[repr(u16)]
pub enum KnownNetworkCardVendor {
    Intel = 0x8086,
    Mellanox = 0x15b3,
}

impl From<KnownNetworkCardVendor> for String {
    fn from(value: KnownNetworkCardVendor) -> Self {
        match value {
            KnownNetworkCardVendor::Intel => "Intel Corporation".to_string(),
            KnownNetworkCardVendor::Mellanox => "Mellanox Technologies".to_string(),
        }
    }
}

mod vendor {
    use crate::physical::KnownNetworkCardVendor;
    pub(super) const MELLANOX: u16 = KnownNetworkCardVendor::Mellanox as u16;
    pub(super) const INTEL: u16 = KnownNetworkCardVendor::Intel as u16;
}

pub enum NetworkCardVendor {
    Known(KnownNetworkCardVendor),
    Unknown(UnknownNetworkCardVendor),
}

#[repr(transparent)]
pub struct UnknownNetworkCardVendor(u16);

impl From<KnownNetworkCardVendor> for u16 {
    fn from(value: KnownNetworkCardVendor) -> Self {
        value as u16
    }
}

impl From<u16> for NetworkCardVendor {
    fn from(value: u16) -> Self {
        match value {
            vendor::INTEL => NetworkCardVendor::Known(KnownNetworkCardVendor::Intel),
            vendor::MELLANOX => NetworkCardVendor::Known(KnownNetworkCardVendor::Mellanox),
            _ => NetworkCardVendor::Unknown(UnknownNetworkCardVendor(value)),
        }
    }
}

#[cfg(test)]
mod test {
    use pci_ids::Device;
    use pci_info::PciInfo;
    use pci_info::pci_enums::PciDeviceInterfaceFunc;
    use std::fs;

    #[test]
    fn pci_test() {
        // Enumerate the devices on the PCI bus using the default
        // enumerator for the current platform. The `unwrap()` panics if
        // the enumeration fatally fails.
        let info = PciInfo::enumerate_pci().unwrap();

        // Print out some properties of the enumerated devices.
        // Note that the collection contains both devices and errors
        // as the enumeration of PCI devices can fail entirely (in which
        // case `PciInfo::enumerate_pci()` would return error) or
        // partially (in which case an error would be inserted in the
        // result).
        info.iter().filter_map(Result::ok).for_each(|pci_device| {
            if let Ok(PciDeviceInterfaceFunc::NetworkController_Ethernet_Default) =
                pci_device.device_iface()
            {
                let device =
                    match Device::from_vid_pid(pci_device.vendor_id(), pci_device.device_id()) {
                        None => {
                            println!(
                                "Unknown device: {:#x}:{:#x}",
                                pci_device.vendor_id(),
                                pci_device.device_id()
                            );
                            let location = match pci_device.location() {
                                Ok(location) => location,
                                Err(err) => {
                                    eprintln!("{err}");
                                    return;
                                }
                            };
                            match fs::read_link(format!("/sys/bus/pci/devices/{location}/physfn")) {
                                Ok(physfn) => {
                                    println!(
                                        "physfn: {}",
                                        physfn
                                            .strip_prefix("../")
                                            .unwrap()
                                            .as_os_str()
                                            .to_string_lossy()
                                    );
                                }
                                Err(err) => {
                                    eprintln!("{err}");
                                    return;
                                }
                            }
                            return;
                        }
                        Some(device) => device,
                    };
                println!("device: {device:#?}");
            }
        });
    }
}
