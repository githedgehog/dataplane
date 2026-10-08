// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! network card initialization, detection, and manipulation utilities.

use std::{
    io::{ErrorKind, Write},
    str::FromStr,
};

use sysfs::{SysfsErr, SysfsFile, SysfsPath, sysfs_root};
use tracing::{error, info, warn};

use crate::pci::address::PciAddress;
use crate::pci::device::DeviceId;
use crate::pci::vendor::VendorId;
use crate::support::{DpdkDriverType, SupportedDevice};

#[derive(Debug, thiserror::Error)]
pub enum DriverErr {
    #[error(transparent)]
    Sysfs(SysfsErr),
    #[error("unable to find driver {0}")]
    MissingDriver(PciDriver),
    #[error("driver {driver_name} is not supported")]
    NotSupported { driver_name: String },
    #[error("{device} is driven through its kernel driver, not vfio-pci; refusing to unbind it")]
    NotVfioPci { device: SupportedDevice },
}

/// Errors opening a PCI network card with [`PciNic::new`].
#[derive(Debug, thiserror::Error)]
pub enum PciNicError {
    #[error(transparent)]
    Sysfs(#[from] SysfsErr),
    #[error("cannot read the {attribute} of PCI device {address}: {reason}")]
    UnreadableId {
        address: PciAddress,
        attribute: &'static str,
        reason: String,
    },
    #[error(
        "PCI device {address} (vendor {vendor:#06x}, device {device:#06x}) is not a supported \
         network card; refusing to touch it"
    )]
    Unsupported {
        address: PciAddress,
        vendor: u16,
        device: u16,
    },
}

/// Structure to represent a network interface card using a PCI address.
///
/// Note that the NIC may or may not be visible to the OS, depending on the state of
/// the system.
///
/// The vendor and device IDs must identify a [`SupportedDevice`].
/// This prevents driver binding operations on unrelated devices, such as storage controllers.
#[derive(Debug)]
pub struct PciNic {
    address: PciAddress,
    device: SupportedDevice,
}

impl PciNic {
    /// Open the network card at `address`.
    ///
    /// # Errors
    ///
    /// - [`PciNicError::Sysfs`] if the device does not exist or is not accessible.
    /// - [`PciNicError::UnreadableId`] if its vendor or device ID cannot be read.
    /// - [`PciNicError::Unsupported`] if it is not a [`SupportedDevice`].
    pub fn new(address: PciAddress) -> Result<PciNic, PciNicError> {
        let device_path = sysfs_root().relative(format!("bus/pci/devices/{address}"))?;
        let read_id = |attribute: &'static str| -> Result<u16, PciNicError> {
            let unreadable = |reason: String| PciNicError::UnreadableId {
                address,
                attribute,
                reason,
            };
            let text = std::fs::read_to_string(device_path.inner().join(attribute))
                .map_err(|e| unreadable(e.to_string()))?;
            let hex = text.trim().trim_start_matches("0x");
            u16::from_str_radix(hex, 16).map_err(|e| unreadable(format!("{text:?}: {e}")))
        };
        let (vendor, device) = (read_id("vendor")?, read_id("device")?);
        let unsupported = || PciNicError::Unsupported {
            address,
            vendor,
            device,
        };
        let vendor_id = VendorId::new(vendor).map_err(|_| unsupported())?;
        let device = SupportedDevice::try_from((vendor_id, DeviceId::new(device)))
            .map_err(|_| unsupported())?;
        Ok(PciNic { address, device })
    }

    /// The supported device identified by its PCI IDs.
    #[must_use]
    pub fn device(&self) -> SupportedDevice {
        self.device
    }

    /// Get the path to the "device" directory under sysfs for this NIC.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] - If an I/O error occurs while reading sysfs
    ///
    /// # Panics
    ///
    /// - Panics if the device path is not under the sysfs directory (most likely a broken kernel)
    /// - Panics if the device path is not valid UTF-8 (very likely a broken kernel)
    /// - Panics if called before setup function
    fn device_path(&self) -> Result<SysfsPath, SysfsErr> {
        let sysfs = sysfs_root();
        sysfs.relative(format!("bus/pci/devices/{self}"))
    }

    fn override_file(&self) -> Result<SysfsFile, SysfsErr> {
        let override_path = self.device_path()?.relative("driver_override")?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        SysfsFile::open(override_path, &options)
    }
}

impl GetDriver for PciNic {
    fn driver(&self) -> Result<Option<PciDriver>, DriverErr> {
        let device_path = self.device_path().map_err(DriverErr::Sysfs)?;
        info!("found device {self} under device path {:?}", device_path);
        let driver_path = match device_path.relative("driver") {
            Ok(p) => p,
            Err(SysfsErr::IoError(e)) if e.kind() == ErrorKind::NotFound => {
                info!("no driver symlink for {self} (no driver bound)");
                return Ok(None);
            }
            Err(e) => return Err(DriverErr::Sysfs(e)),
        };
        info!("{self} is using driver path {driver_path:?}");
        match driver_path.inner().file_name() {
            Some(os_str) => match os_str.to_str() {
                Some(driver_name) => match PciDriver::from_str(driver_name) {
                    Ok(driver) => Ok(Some(driver)),
                    Err(_) => Err(DriverErr::NotSupported {
                        driver_name: driver_name.to_string(),
                    }),
                },
                None => Err(DriverErr::Sysfs(SysfsErr::SysfsPathIsNotValidUtf8)),
            },
            None => unreachable!("sysfs path has no components?"),
        }
    }
}

impl std::fmt::Display for PciNic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

/// Enum describing supported PCI drivers.
#[derive(Debug, Copy, Clone, PartialEq, Eq, strum::EnumString, strum::IntoStaticStr)]
pub enum PciDriver {
    /// Intel's e1000 driver, including QEMU's 82540EM.
    #[strum(serialize = "e1000")]
    E1000,
    /// Intel's e1000e driver, including QEMU's 82574L.
    #[strum(serialize = "e1000e")]
    E1000E,
    /// Intel's i40e driver.
    #[strum(serialize = "i40e")]
    I40e,
    /// Intel's iavf driver.
    #[strum(serialize = "iavf")]
    Iavf,
    /// NVIDIA/Mellanox's mlx5 driver
    #[strum(serialize = "mlx5_core")]
    Mlx5Core,
    /// PCI Express port services driver for root and downstream bridges.
    #[strum(serialize = "pcieport")]
    PciePort,
    /// The vfio-pci driver.
    #[strum(serialize = "vfio-pci")]
    VfioPci,
    /// The virtio-net driver.
    // NOTE: inconsistent use of _ vs - is deliberate.  Linux is not consistent
    #[strum(serialize = "virtio_net")]
    VirtioNet,
    /// The virtio-pci driver (sometimes assigned to virtio net devices)
    #[strum(serialize = "virtio-pci")]
    VirtioPci,
}

impl PciDriver {
    /// Get the path to the "driver" directory under sysfs for this driver.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] if the path cannot be accessed for some reason (e.g. permissions issues).
    ///
    /// # Panics
    ///
    /// - Panics if the driver path is not under sysfs.
    /// - Panics if the driver path is not valid UTF-8.
    /// - Panics if this function is called before calling setup
    fn driver_path(self) -> Result<SysfsPath, DriverErr> {
        match sysfs_root().relative(format!("bus/pci/drivers/{self}")) {
            Ok(path) => Ok(path),
            Err(SysfsErr::IoError(e)) => match e.kind() {
                std::io::ErrorKind::NotFound => {
                    warn!(
                        "driver {self} does not seem to be available.  You may need to modprobe {self}"
                    );
                    Err(DriverErr::MissingDriver(self))
                }
                _ => Err(DriverErr::Sysfs(SysfsErr::IoError(e))),
            },
            Err(e) => Err(DriverErr::Sysfs(e)),
        }
    }

    fn bind_file(self) -> Result<SysfsFile, DriverErr> {
        let driver_path = self.driver_path()?;
        let path = format!("{driver_path}/bind");
        info!("opening bind file {path}");
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        SysfsFile::open(path, &options).map_err(DriverErr::Sysfs)
    }
}

impl std::fmt::Display for PciDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: &'static str = self.into();
        write!(f, "{s}")
    }
}

trait GetDriver {
    /// Get the driver for a device.
    ///
    /// If the device has no driver, returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// The most typical error here occurs when the device is simply not supported (yet).
    ///
    /// However, this function is susceptible to various error conditions ranging from missing drivers to permissions
    /// issues to completely broken kernels.
    ///
    /// More, we don't really have the ability to fully restrict the set of things which can go wrong here.
    /// The best we can do is return a [`std::io::Error`] which tries to describe what happened.
    ///
    /// # Panics
    ///
    /// This function should not panic under normal circumstances.
    /// The only deliberate panics address wildly broken invariants or compromised kernel memory.
    fn driver(&self) -> Result<Option<PciDriver>, DriverErr>;
}

/// Trait for pci devices which may be unbound from their linux driver.
trait UnbindPciDriver {
    type Error: std::error::Error;
    /// Attempt to unbind the device from its current driver.
    ///
    /// Implementations should expect that the device is currently bound to
    /// some driver, including drivers absent from [`PciDriver`].
    ///
    /// # Errors
    ///
    /// `Self::Error` should be returned in all cases where the unbinding was not successful.
    fn unbind(&mut self) -> Result<(), Self::Error>;
}

/// Trait for pci devices which may have their driver overridden.
///
/// When a driver is overridden for a specific device, linux will not attempt to associate that device
/// with the default driver (which is selected based on the type of device in question).
///
/// Overriding a driver is specific to a device, not the make / model of the device.
trait OverridePciDriver {
    type Error: std::error::Error;
    /// Attempt to override the driver for a pci device.
    ///
    /// Implementations should expect that the device is currently unbound from
    /// any driver.
    ///
    /// Note: override is not the same as bind.  See [`BindPciDriver`].
    ///
    /// # Errors
    ///
    /// `Self::Error` should be returned in all cases where the override was not successful.
    fn override_driver(&mut self, driver: PciDriver) -> Result<(), Self::Error>;
}

impl UnbindPciDriver for PciNic {
    type Error = DriverErr;
    fn unbind(&mut self) -> Result<(), DriverErr> {
        let device_path = self.device_path().map_err(DriverErr::Sysfs)?;
        // Follow the device's driver link to support drivers absent from `PciDriver`.
        let driver_path = match device_path.relative("driver") {
            Ok(path) => path,
            Err(SysfsErr::IoError(e)) if e.kind() == ErrorKind::NotFound => {
                info!("no driver bound to {self}");
                return Ok(());
            }
            Err(e) => return Err(DriverErr::Sysfs(e)),
        };
        let path = format!("{driver_path}/unbind");
        info!("opening unbind file {path}");
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        SysfsFile::open(path, &options)
            .map_err(DriverErr::Sysfs)?
            .write_all(format!("{self}").as_bytes())
            .map_err(|e| DriverErr::Sysfs(SysfsErr::IoError(e)))
    }
}

impl OverridePciDriver for PciNic {
    type Error = DriverErr;

    fn override_driver(&mut self, driver: PciDriver) -> Result<(), DriverErr> {
        info!("overriding driver for {self} to {driver}");
        self.override_file()
            .map_err(DriverErr::Sysfs)?
            .write_all(driver.to_string().as_bytes())
            .map_err(SysfsErr::IoError)
            .map_err(DriverErr::Sysfs)
    }
}

/// Trait for pci devices which may be bound to a linux driver.
trait BindPciDriver {
    type Error: std::error::Error;
    /// Attempt to bind the device to a specific [`PciDriver`].
    ///
    /// Implementations should expect that the device is currently "unbound" from
    /// any driver.
    ///
    /// # Errors
    ///
    /// `Self::Error` should be returned in all cases where the binding was not successful.
    fn bind(&mut self, driver: PciDriver) -> Result<(), Self::Error>;
}

impl BindPciDriver for PciNic {
    type Error = DriverErr;

    fn bind(&mut self, driver: PciDriver) -> Result<(), DriverErr> {
        let driver_name: &'static str = driver.into();
        info!("binding device {self} to {driver_name}");
        driver
            .bind_file()?
            .write_all(format!("{self}").as_bytes())
            .map_err(|e| DriverErr::Sysfs(SysfsErr::IoError(e)))
    }
}

/// Trait for devices which may be bound to the vfio-pci driver.
pub trait BindToVfioPci {
    /// Errors which may occur when binding to the vfio-pci driver.
    type Error: std::error::Error;
    /// Bind the device to the vfio-pci driver, regardless of the current driver.
    ///
    /// # Errors
    ///
    /// Returns an error if the device could not be bound to the vfio-pci driver.
    fn bind_to_vfio_pci(&mut self) -> Result<(), Self::Error>;
}

impl BindToVfioPci for PciNic {
    type Error = DriverErr;

    fn bind_to_vfio_pci(&mut self) -> Result<(), DriverErr> {
        // A bifurcated device (mlx5) must keep its kernel driver; DPDK reaches it through verbs.
        if DpdkDriverType::from(self.device) != DpdkDriverType::VfioPci {
            return Err(DriverErr::NotVfioPci {
                device: self.device,
            });
        }
        match self.driver() {
            Ok(Some(PciDriver::VfioPci)) => {
                info!("device {self} is already bound to vfio-pci");
                return Ok(());
            }
            Ok(Some(known_driver)) => {
                info!("unbinding device {self} from {known_driver}");
                self.unbind()?;
            }
            Err(DriverErr::NotSupported { driver_name }) => {
                info!("unbinding device {self} from unrecognized driver {driver_name}");
                self.unbind()?;
            }
            Ok(None) => {
                info!("device {self} has no driver bound; proceeding to vfio-pci bind");
            }
            Err(err) => {
                error!("failed to get device driver: {:?}", err);
                return Err(err);
            }
        }
        self.override_driver(PciDriver::VfioPci)?;
        self.bind(PciDriver::VfioPci)?;
        Ok(())
    }
}
